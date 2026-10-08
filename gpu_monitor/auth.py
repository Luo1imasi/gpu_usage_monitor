"""Public-key login: only public key IDs and signatures cross the HTTP boundary."""

import base64
import hashlib
import re
import secrets
import sqlite3
import time

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from .user_store import load_user_keys, ssh_key_id, ssh_key_identity

COOKIE_NAME = "monitor_session"
CHALLENGE_COOKIE = "monitor_challenge"
CHALLENGE_TTL = 60
SESSION_TTL = 8 * 60 * 60
KEY_ID_PATTERN = re.compile(r"^[0-9a-f]{64}$")


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def registered_key(key_id):
    matches = [(user["username"], ssh_key_identity(key))
               for user in load_user_keys() for key in user["ssh_keys"]
               if ssh_key_id(key) == key_id]
    matches = set(matches)
    return next(iter(matches)) if len(matches) == 1 else None


def verify_signature(public_key, message, signature):
    key = serialization.load_ssh_public_key(public_key.encode())
    raw = base64.b64decode(signature, validate=True)
    data = message.encode()
    if isinstance(key, ed25519.Ed25519PublicKey):
        key.verify(raw, data)
    elif isinstance(key, rsa.RSAPublicKey):
        key.verify(raw, data, padding.PKCS1v15(), hashes.SHA256())
    elif isinstance(key, ec.EllipticCurvePublicKey):
        key.verify(raw, data, ec.ECDSA(hashes.SHA256()))
    else:
        raise ValueError("Unsupported key")


class AuthStore:
    def __init__(self, path):
        self.path = str(path)

    def connect(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.executescript("""
            CREATE TABLE IF NOT EXISTS challenges (
                id TEXT PRIMARY KEY, key_id TEXT, username TEXT,
                message TEXT, binding TEXT, expires REAL);
            CREATE TABLE IF NOT EXISTS sessions (
                token TEXT PRIMARY KEY, key_id TEXT, username TEXT, expires REAL);
            CREATE TABLE IF NOT EXISTS attempts (
                bucket TEXT PRIMARY KEY, window REAL, count INTEGER);
        """)
        return db

    def throttle(self, address):
        now = time.time()
        bucket = digest(address or "unknown")
        db = self.connect()
        try:
            with db:
                db.execute("BEGIN IMMEDIATE")
                db.execute("DELETE FROM attempts WHERE window < ?", (now - 60,))
                db.execute("DELETE FROM challenges WHERE expires < ?", (now,))
                db.execute("DELETE FROM sessions WHERE expires < ?", (now,))
                db.execute("INSERT INTO attempts VALUES (?, ?, 1) ON CONFLICT(bucket) "
                           "DO UPDATE SET count = count + 1", (bucket, now))
                count = db.execute("SELECT count FROM attempts WHERE bucket = ?", (bucket,)).fetchone()[0]
            return count <= 30
        finally:
            db.close()

    def challenge(self, key_id, origin):
        match = registered_key(key_id)
        if not match:
            return None
        username, _ = match
        challenge_id, binding = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        expires = time.time() + CHALLENGE_TTL
        message = "\n".join(("gpu-monitor-login-v1", origin, username, key_id,
                             challenge_id, str(int(expires)), secrets.token_urlsafe(32)))
        db = self.connect()
        try:
            with db:
                db.execute("INSERT INTO challenges VALUES (?, ?, ?, ?, ?, ?)",
                           (challenge_id, key_id, username, message, digest(binding), expires))
        finally:
            db.close()
        return {"challenge_id": challenge_id, "message": message}, binding

    def login(self, challenge_id, signature, binding):
        db = self.connect()
        try:
            with db:
                db.execute("BEGIN IMMEDIATE")
                row = db.execute("SELECT * FROM challenges WHERE id = ?", (challenge_id,)).fetchone()
                if not row or not binding or not secrets.compare_digest(row["binding"], digest(binding)):
                    return None
                # Consume even failed signatures, atomically across Flask workers.
                db.execute("DELETE FROM challenges WHERE id = ?", (challenge_id,))
                match = registered_key(row["key_id"])
                if row["expires"] < time.time() or not match or match[0] != row["username"]:
                    return None
                try:
                    verify_signature(match[1], row["message"], signature)
                except (InvalidSignature, ValueError, TypeError):
                    return None
                token = secrets.token_urlsafe(32)
                db.execute("INSERT INTO sessions VALUES (?, ?, ?, ?)",
                           (digest(token), row["key_id"], row["username"], time.time() + SESSION_TTL))
                return token, row["username"]
        finally:
            db.close()

    def user(self, token):
        if not token or len(token) > 128:
            return None
        db = self.connect()
        try:
            row = db.execute("SELECT * FROM sessions WHERE token = ? AND expires > ?",
                             (digest(token), time.time())).fetchone()
        finally:
            db.close()
        if row:
            match = registered_key(row["key_id"])
            if match and match[0] == row["username"]:
                return row["username"]
        return None

    def logout(self, token):
        db = self.connect()
        try:
            with db:
                db.execute("DELETE FROM sessions WHERE token = ?", (digest(token),))
        finally:
            db.close()
