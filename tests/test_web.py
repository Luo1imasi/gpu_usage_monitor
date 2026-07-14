import unittest
from unittest.mock import patch

from flask import url_for

from gpu_monitor import web


class WebRouteTests(unittest.TestCase):
    def setUp(self):
        self.app = web.create_app()
        self.client = self.app.test_client()

    def test_factory_registers_blueprint_without_static_route(self):
        with self.app.test_request_context():
            self.assertEqual(url_for("gpu_monitor.index"), "/")

        self.assertEqual(self.app.name, "gpu_monitor.web")
        self.assertIsNone(self.app.static_folder)

    def test_index_nests_storage_inside_each_server_card(self):
        response = self.client.get("/")
        html = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertLess(
            html.index('id="servers"'),
            html.index('class="access-panel management-panel"'),
        )
        for removed_marker in (
            'id="storage-title"',
            'id="storage-kpis"',
            'id="storage-servers"',
            'id="storage-notice"',
        ):
            with self.subTest(removed_marker=removed_marker):
                self.assertNotIn(removed_marker, html)
        for marker in (
            'class="monitor-panel gpu-panel"',
            'id="gpu-title"',
            'class="servers monitor-grid"',
            "serverCard.className = 'server-card monitor-card'",
            "let storageByServer = new Map()",
            "function renderServerStorage(serverName, scrollSnapshot)",
            "card.className = 'gpu-item storage-item'",
            ".gpu-item.storage-item {",
            "grid-column: 1 / -1;",
            "scrollbar-width: thin;",
            ".storage-user-list::-webkit-scrollbar-thumb",
            "gpuList.appendChild(",
            "renderServerStorage(s.server, storageScrollSnapshot)",
            "const storageKey = 'server:' + serverName + ':storage'",
            "card.open = getSavedOpenState(storageKey, false)",
            "rememberOpenState(card, storageKey)",
            "storageScrollState",
            "server.user_min_bytes",
            "server.filtered_user_count",
            "setInterval(refreshStorage, 60000)",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, html)
        self.assertNotIn("scrollbar-gutter: stable", html)

    def test_gpu_endpoint_returns_state_snapshot(self):
        snapshot = [{"server": "alpha", "gpus": [], "error": None}]
        with patch.object(web.gpu_state, "get_cached_data", return_value=snapshot):
            response = self.client.get("/api/gpu")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), snapshot)

    def test_storage_endpoint_returns_state_snapshot(self):
        snapshot = [
            {
                "server": "alpha",
                "filesystem": {
                    "path": "/home",
                    "total": 1000,
                    "used": 400,
                    "available": 600,
                    "percent": 40.0,
                },
                "users": [
                    {
                        "username": "alice",
                        "used": 250,
                    }
                ],
                "partial": False,
                "user_error_count": 0,
                "user_min_bytes": 100 * 1024 * 1024,
                "filtered_user_count": 0,
                "error": None,
                "updated_at": 123.0,
                "stale": False,
                "last_error": None,
            }
        ]
        with patch.object(
            web.storage_state,
            "get_cached_data",
            return_value=snapshot,
        ):
            response = self.client.get("/api/storage")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), snapshot)

    def test_servers_endpoint_exposes_only_public_metadata(self):
        servers = [
            {
                "name": "alpha",
                "host": "192.0.2.10",
                "username": "private-user",
                "key_file": "/private/key",
            }
        ]
        settings = {
            "refresh_interval": 2,
            "api_poll_interval": 3,
        }
        with (
            patch.object(web, "get_configured_servers", return_value=servers),
            patch.object(web, "get_monitoring_settings", return_value=settings),
        ):
            response = self.client.get("/api/servers")

        payload = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            set(payload),
            {"servers", "refresh_interval", "poll_interval"},
        )
        self.assertEqual(payload["servers"], [{"name": "alpha"}])
        self.assertEqual(payload["refresh_interval"], 2)
        self.assertEqual(payload["poll_interval"], 3)
        self.assertNotIn("host", payload["servers"][0])
        self.assertNotIn("username", payload["servers"][0])
        self.assertNotIn("key_file", payload["servers"][0])

    def test_access_matrix_query_is_forwarded_with_normalized_lists(self):
        result = {"servers": [], "users": [], "cached": False}
        with patch.object(
            web,
            "build_access_matrix",
            return_value=(result, 200),
        ) as build:
            response = self.client.get(
                "/api/access-matrix?servers=alpha,beta&users=alice"
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), result)
        build.assert_called_once_with(["alpha", "beta"], ["alice"])

    def test_admin_endpoints_reject_missing_token(self):
        requests = [
            ("post", "/api/check-ssh-key", {}),
            ("post", "/api/users", {}),
            ("post", "/api/detect-users", {}),
            ("post", "/api/import-users", {}),
            ("delete", "/api/users/alice", {}),
            ("post", "/api/configure-access", {}),
        ]

        with patch.object(web, "load_config", return_value={"admin_token": "secret"}):
            for method, path, payload in requests:
                with self.subTest(path=path):
                    response = getattr(self.client, method)(path, json=payload)
                    self.assertEqual(response.status_code, 403)
                    self.assertEqual(
                        response.get_json(),
                        {"error": "admin_token_required"},
                    )

    def test_configure_access_forwards_valid_selection(self):
        expected = {"error": None, "results": []}
        with (
            patch.object(web, "load_config", return_value={"admin_token": "secret"}),
            patch.object(
                web,
                "configure_selected_access",
                return_value=(expected, 200),
            ) as configure,
        ):
            response = self.client.post(
                "/api/configure-access",
                headers={"X-Admin-Token": "secret"},
                json={"servers": ["alpha"], "users": ["alice"]},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), expected)
        configure.assert_called_once_with(["alpha"], ["alice"])


if __name__ == "__main__":
    unittest.main()
