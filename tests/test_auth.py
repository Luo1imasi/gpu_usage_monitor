import base64
import os
import tempfile
import time
import unittest
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from gpu_monitor import auth, web
from gpu_monitor.user_store import ssh_key_id


class AuthenticationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.app = web.create_app({"AUTH_DATABASE": self.directory.name + "/auth.sqlite3", "TESTING": True})
        self.client = self.app.test_client()
        self.client.environ_base["HTTP_X_MONITOR_REQUEST"] = "1"
        self.key = ed25519.Ed25519PrivateKey.generate()
        self.public = self.key.public_key().public_bytes(
            serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
        self.users = [{"username": "alice", "ssh_keys": [self.public]}]
        patcher = patch.object(auth, "load_user_keys", side_effect=lambda: self.users)
        patcher.start()
        self.addCleanup(patcher.stop)

    def challenge(self):
        return self.client.post("/api/auth/challenge", json={"key_id": ssh_key_id(self.public)}).get_json()

    def signed_payload(self, challenge, key=None):
        return {"challenge_id": challenge["challenge_id"],
                "signature": base64.b64encode((key or self.key).sign(challenge["message"].encode())).decode()}

    def login(self):
        response = self.client.post("/api/auth/verify", json=self.signed_payload(self.challenge()))
        self.assertEqual(response.status_code, 200)
        return response

    def test_all_existing_routes_require_login_even_with_admin_token(self):
        for rule in self.app.url_map.iter_rules():
            if rule.endpoint in {"gpu_monitor.login_page", "gpu_monitor.login_asset",
                                 "gpu_monitor.auth_challenge", "gpu_monitor.auth_verify"}:
                continue
            path = rule.rule.replace("<username>", "alice")
            for method in rule.methods - {"HEAD", "OPTIONS"}:
                with self.subTest(path=path, method=method):
                    response = self.client.open(path, method=method, headers={"X-Admin-Token": "secret"})
                    self.assertEqual(response.status_code, 401 if path.startswith("/api/") else 302)

    def test_login_cookie_and_security_headers(self):
        response = self.login()
        cookie = response.headers.getlist("Set-Cookie")[0]
        for attribute in ("Secure", "HttpOnly", "SameSite=Strict"):
            self.assertIn(attribute, cookie)
        self.assertEqual(self.client.get("/").status_code, 200)
        self.assertEqual(self.client.get("/api/gpu").status_code, 200)
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        worker = self.client.get("/login-assets/login-worker.js")
        self.assertIn("connect-src 'none'", worker.headers["Content-Security-Policy"])
        worker.close()

    def test_replay_and_wrong_signature_are_rejected(self):
        payload = self.signed_payload(self.challenge())
        self.assertEqual(self.client.post("/api/auth/verify", json=payload).status_code, 200)
        self.assertEqual(self.client.post("/api/auth/verify", json=payload).status_code, 403)
        challenge = self.challenge()
        wrong = self.signed_payload(challenge, ed25519.Ed25519PrivateKey.generate())
        self.assertEqual(self.client.post("/api/auth/verify", json=wrong).status_code, 403)
        self.assertEqual(self.client.post("/api/auth/verify", json=self.signed_payload(challenge)).status_code, 403)

    def test_challenge_is_bound_to_browser(self):
        payload = self.signed_payload(self.challenge())
        other = self.app.test_client()
        self.assertEqual(other.post("/api/auth/verify", json=payload,
                                    headers={"X-Monitor-Request": "1"}).status_code, 403)
        self.assertEqual(self.client.post("/api/auth/verify", json=payload).status_code, 200)

    def test_expired_challenge_and_session_are_rejected(self):
        payload = self.signed_payload(self.challenge())
        with patch.object(auth.time, "time", return_value=time.time() + 120):
            self.assertEqual(self.client.post("/api/auth/verify", json=payload).status_code, 403)
        self.login()
        with patch.object(auth.time, "time", return_value=time.time() + auth.SESSION_TTL + 1):
            self.assertEqual(self.client.get("/api/gpu").status_code, 401)

    def test_key_removal_and_logout_revoke_session(self):
        self.login()
        self.users.clear()
        self.assertEqual(self.client.get("/api/gpu").status_code, 401)
        self.users.append({"username": "alice", "ssh_keys": [self.public]})
        self.login()
        token = self.client.get_cookie(auth.COOKIE_NAME).value
        self.assertEqual(self.client.post("/api/auth/logout").status_code, 200)
        self.client.set_cookie(auth.COOKIE_NAME, token)
        self.assertEqual(self.client.get("/api/gpu").status_code, 401)

    def test_login_does_not_grant_admin(self):
        self.login()
        with patch.object(web, "load_config", return_value={"admin_token": "secret"}):
            self.assertEqual(self.client.post("/api/users", json={}).status_code, 403)

    def test_cross_origin_and_unexpected_fields_are_rejected(self):
        payload = {"key_id": ssh_key_id(self.public)}
        self.assertEqual(self.client.post("/api/auth/challenge", json=payload,
                                         headers={"Origin": "https://attacker.example"}).status_code, 403)
        self.assertEqual(self.client.post("/api/auth/challenge", json={**payload, "private_key": "secret"}).status_code, 400)
        self.login()
        self.assertEqual(self.client.post("/api/auth/logout", headers={"Origin": "https://attacker.example"}).status_code, 403)

    def test_unregistered_ambiguous_and_zero_key_accounts_cannot_login(self):
        self.users = [{"username": "alice", "ssh_keys": []}]
        self.assertEqual(self.client.post("/api/auth/challenge", json={"key_id": ssh_key_id(self.public)}).status_code, 403)
        self.users = [{"username": username, "ssh_keys": [self.public]} for username in ("alice", "bob")]
        self.assertEqual(self.client.post("/api/auth/challenge", json={"key_id": ssh_key_id(self.public)}).status_code, 403)

    def test_login_rate_limit(self):
        for _ in range(30):
            self.assertEqual(self.client.post("/api/auth/challenge", json={"key_id": "0" * 64}).status_code, 403)
        self.assertEqual(self.client.post("/api/auth/challenge", json={"key_id": "0" * 64}).status_code, 429)

    def test_https_reverse_proxy_challenge_and_login(self):
        with patch.dict(os.environ, {"GPU_MONITOR_TRUST_PROXY": "1"}):
            app = web.create_app({"AUTH_DATABASE": self.directory.name + "/proxy.sqlite3"})
        client = app.test_client()
        headers = {"Host": "gpu.example.test", "Origin": "https://gpu.example.test",
                   "X-Forwarded-Proto": "https", "X-Forwarded-For": "192.0.2.10",
                   "X-Monitor-Request": "1"}
        challenge = client.post("/api/auth/challenge", json={"key_id": ssh_key_id(self.public)}, headers=headers)
        self.assertEqual(challenge.status_code, 200)
        self.assertEqual(challenge.get_json()["message"].split("\n")[1], "https://gpu.example.test")
        response = client.post("/api/auth/verify", json=self.signed_payload(challenge.get_json()), headers=headers)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(client.get("/api/gpu", headers=headers).status_code, 200)
        self.assertEqual(client.post("/api/auth/challenge", json={"key_id": ssh_key_id(self.public)},
                                     headers={**headers, "Origin": "https://attacker.example"}).status_code, 403)

    def test_supported_signature_algorithms(self):
        for key in (rsa.generate_private_key(public_exponent=65537, key_size=2048),
                    ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP384R1()),
                    ec.generate_private_key(ec.SECP521R1()), self.key):
            public = key.public_key().public_bytes(serialization.Encoding.OpenSSH, serialization.PublicFormat.OpenSSH).decode()
            message = "gpu-monitor-login-v1\n测试"
            if isinstance(key, rsa.RSAPrivateKey):
                signature = key.sign(message.encode(), padding.PKCS1v15(), hashes.SHA256())
            elif isinstance(key, ec.EllipticCurvePrivateKey):
                signature = key.sign(message.encode(), ec.ECDSA(hashes.SHA256()))
            else:
                signature = key.sign(message.encode())
            auth.verify_signature(public, message, base64.b64encode(signature).decode())
            with self.assertRaises(Exception):
                auth.verify_signature(public, message + "tampered", base64.b64encode(signature).decode())
