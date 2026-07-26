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
            "let gpuRefreshTimer = null",
            "function updateGpuRefreshTimer()",
            "gpuRefreshTimer = setInterval(refresh, refreshInterval * 1000)",
            "document.addEventListener('visibilitychange'",
            "if (!document.hidden)",
            "setInterval(refreshStorage, 60000)",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, html)
        self.assertNotIn("apiPollInterval", html)
        self.assertNotIn("scrollbar-gutter: stable", html)

    def test_delete_account_ui_is_not_limited_by_matrix_scope(self):
        response = self.client.get("/")
        html = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn("将尝试在全部配置服务器终止该用户进程", html)
        self.assertNotIn("deleteAccountButton.disabled = partialMatrix", html)
        self.assertNotIn("servers: targetServers", html)

    def test_delete_key_dialog_shows_accessible_server_counts(self):
        response = self.client.get("/")
        html = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        for marker in (
            "function getDeleteKeyAccessText(key)",
            "key.accessible_server_count",
            "key.total_server_count",
            "key.access_unknown_server_count",
            "key.unknown_server_count",
            "data.total_server_count",
            "data.server_count",
            "data.unknown_server_count",
            "access.className = 'key-delete-option-access'",
            "'可访问服务器 ' + accessibleCount",
            "' 台状态未知）'",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, html)

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
            {"servers", "refresh_interval"},
        )
        self.assertEqual(payload["servers"], [{"name": "alpha"}])
        self.assertEqual(payload["refresh_interval"], 2)
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
            ("get", "/api/users/alice/keys", None),
            ("delete", "/api/users/alice/keys", {}),
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

    def test_user_key_list_requires_admin_and_forwards_username(self):
        expected = {
            "error": None,
            "username": "alice",
            "key_count": 1,
            "keys": [{"key_id": "a" * 64}],
        }
        with (
            patch.object(web, "load_config", return_value={"admin_token": "secret"}),
            patch.object(
                web,
                "list_user_keys",
                return_value=(expected, 200),
            ) as list_keys,
        ):
            response = self.client.get(
                "/api/users/alice/keys",
                headers={"X-Admin-Token": "secret"},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), expected)
        list_keys.assert_called_once_with("alice")

    def test_delete_user_keys_forwards_batch_selection(self):
        key_ids = ["a" * 64, "b" * 64]
        expected = {
            "error": None,
            "username": "alice",
            "requested_key_count": 2,
            "selected_key_ids": key_ids,
            "local": {"removed_keys": 2},
            "results": [],
        }
        with (
            patch.object(web, "load_config", return_value={"admin_token": "secret"}),
            patch.object(
                web,
                "delete_user_keys",
                return_value=(expected, 200),
            ) as delete_keys,
        ):
            response = self.client.delete(
                "/api/users/alice/keys",
                headers={"X-Admin-Token": "secret"},
                json={"key_ids": key_ids},
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json(), expected)
        delete_keys.assert_called_once_with("alice", {"key_ids": key_ids})


if __name__ == "__main__":
    unittest.main()
