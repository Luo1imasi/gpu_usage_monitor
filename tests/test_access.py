import unittest
from unittest.mock import patch

from gpu_monitor.access import service
from gpu_monitor.user_store import key_fingerprint, ssh_key_id


class AccessServiceTests(unittest.TestCase):
    def setUp(self):
        service.invalidate_access_matrix_cache()

    def tearDown(self):
        service.invalidate_access_matrix_cache()

    def test_normalize_name_list_splits_and_deduplicates(self):
        self.assertEqual(
            service.normalize_name_list(["alpha,beta", "alpha；gamma"]),
            ["alpha", "beta", "gamma"],
        )

    def test_invalid_access_selection_is_rejected_before_remote_work(self):
        with (
            patch.object(
                service,
                "get_servers_by_name",
                return_value={"alpha": {"name": "alpha"}},
            ),
            patch.object(
                service,
                "get_users_by_name",
                return_value={"alice": {"username": "alice", "ssh_keys": []}},
            ),
        ):
            result, status = service.configure_selected_access(
                ["missing"],
                ["unknown"],
            )

        self.assertEqual(status, 400)
        self.assertEqual(result["error"], "invalid_selection")
        self.assertEqual(result["unknown_servers"], ["missing"])
        self.assertEqual(result["unknown_users"], ["unknown"])

    def test_root_account_cannot_be_deleted(self):
        result, status = service.delete_user_access("root", {})

        self.assertEqual(status, 400)
        self.assertEqual(result["error"], "protected_username")
        self.assertEqual(result["results"], [])

    def test_delete_user_rejects_non_object_payload(self):
        result, status = service.delete_user_access("alice", [])

        self.assertEqual(status, 400)
        self.assertEqual(result["error"], "request_body_must_be_an_object")

    def test_delete_account_uses_all_servers_and_keeps_local_record_on_error(self):
        servers = [
            {"name": "beta", "username": "monitor"},
            {"name": "alpha", "username": "monitor"},
        ]

        def delete_remote(
            server,
            username,
            ssh_keys,
            mode,
            clear_authorized_keys,
            remove_home,
        ):
            self.assertEqual(username, "alice")
            self.assertEqual(ssh_keys, ["ssh-ed25519 body laptop"])
            self.assertEqual(mode, "delete_account")
            self.assertTrue(clear_authorized_keys)
            self.assertTrue(remove_home)
            if server["name"] == "beta":
                return {"server": "beta", "error": "offline", "result": {}}
            return {
                "server": "alpha",
                "error": None,
                "result": {"deleted": True, "errors": []},
            }

        with (
            patch.object(service, "get_configured_servers", return_value=servers),
            patch.object(
                service,
                "get_users_by_name",
                return_value={
                    "alice": {
                        "username": "alice",
                        "ssh_keys": ["ssh-ed25519 body laptop"],
                    }
                },
            ),
            patch.object(
                service,
                "revoke_user_on_server",
                side_effect=delete_remote,
            ) as delete_remote_mock,
            patch.object(service, "remove_user_from_file") as remove_local,
        ):
            result, status = service.delete_user_access(
                "alice",
                {
                    "mode": "delete_account",
                    "confirm": "alice",
                    "remove_home": True,
                    "remove_from_user_file": True,
                    "clear_authorized_keys": True,
                },
            )

        self.assertEqual(status, 200)
        self.assertEqual(delete_remote_mock.call_count, 2)
        self.assertEqual(
            [item["server"] for item in result["results"]],
            ["alpha", "beta"],
        )
        self.assertTrue(result["local"]["skipped"])
        self.assertEqual(result["local"]["reason"], "remote_errors")
        remove_local.assert_not_called()

    def test_delete_account_rejects_server_selection(self):
        with (
            patch.object(
                service,
                "get_configured_servers",
                return_value=[{"name": "alpha", "username": "monitor"}],
            ),
            patch.object(service.admin_executor, "submit") as submit,
            patch.object(service, "remove_user_from_file") as remove_local,
        ):
            result, status = service.delete_user_access(
                "alice",
                {
                    "mode": "delete_account",
                    "servers": ["alpha"],
                    "confirm": "alice",
                },
            )

        self.assertEqual(status, 400)
        self.assertEqual(result["error"], "server_selection_not_supported")
        submit.assert_not_called()
        remove_local.assert_not_called()

    def test_delete_account_removes_local_record_after_all_servers_succeed(self):
        servers = [
            {"name": "alpha", "username": "monitor"},
            {"name": "beta", "username": "monitor"},
        ]
        local_result = {"username": "alice", "removed_lines": 1}

        def delete_remote(server, *args):
            return {
                "server": server["name"],
                "error": None,
                "result": {"deleted": True, "errors": []},
            }

        with (
            patch.object(service, "get_configured_servers", return_value=servers),
            patch.object(
                service,
                "get_users_by_name",
                return_value={"alice": {"username": "alice", "ssh_keys": []}},
            ),
            patch.object(
                service,
                "revoke_user_on_server",
                side_effect=delete_remote,
            ) as delete_remote_mock,
            patch.object(
                service,
                "remove_user_from_file",
                return_value=(local_result, 200),
            ) as remove_local,
        ):
            result, status = service.delete_user_access(
                "alice",
                {
                    "mode": "delete_account",
                    "confirm": "alice",
                    "remove_home": True,
                    "remove_from_user_file": True,
                },
            )

        self.assertEqual(status, 200)
        self.assertEqual(delete_remote_mock.call_count, 2)
        remove_local.assert_called_once_with("alice")
        self.assertEqual(result["local"], local_result)

    def test_list_user_keys_reports_accessible_server_count_per_key(self):
        first_key = "ssh-ed25519 first-body laptop"
        second_key = "ssh-ed25519 second-body desktop"
        first_key_id = ssh_key_id(first_key)
        second_key_id = ssh_key_id(second_key)
        keys = [
            {
                "key_id": first_key_id,
                "ssh_key": first_key,
                "key_type": "ssh-ed25519",
                "comment": "laptop",
            },
            {
                "key_id": second_key_id,
                "ssh_key": second_key,
                "key_type": "ssh-ed25519",
                "comment": "desktop",
            },
        ]
        servers = [
            {"name": "alpha"},
            {"name": "beta"},
            {"name": "gamma"},
            {"name": "delta"},
            {"name": "epsilon"},
            {"name": "zeta"},
        ]
        server_results = {
            "alpha": {
                "server": "alpha",
                "error": None,
                "users": {
                    "alice": {
                        "user_exists": True,
                        "authorized_keys_readable": True,
                        "authorized_key_ids": [
                            first_key_id,
                            second_key_id,
                            first_key_id,
                        ],
                        "error": None,
                    }
                },
            },
            "beta": {
                "server": "beta",
                "error": None,
                "users": {
                    "alice": {
                        "user_exists": True,
                        "authorized_keys_readable": True,
                        "authorized_key_ids": [first_key_id],
                        "error": None,
                    }
                },
            },
            "gamma": {
                "server": "gamma",
                "error": None,
                "users": {
                    "alice": {
                        "user_exists": False,
                        "authorized_keys_readable": False,
                        "authorized_key_ids": [],
                        "error": None,
                    }
                },
            },
            "delta": {
                "server": "delta",
                "error": "offline",
                "users": {},
            },
            "epsilon": {
                "server": "epsilon",
                "error": None,
                "users": {
                    "alice": {
                        "user_exists": True,
                        "authorized_keys_readable": False,
                        "authorized_key_ids": [],
                        "error": "permission_denied",
                    }
                },
            },
            "zeta": {
                "server": "zeta",
                "error": None,
                "users": {
                    "alice": {
                        "user_exists": True,
                        "authorized_keys_readable": False,
                        "authorized_key_ids": [],
                        "error": None,
                    }
                },
            },
        }

        with (
            patch.object(service, "get_user_key_records", return_value=keys),
            patch.object(service, "get_configured_servers", return_value=servers),
            patch.object(
                service,
                "check_access_matrix_for_servers",
                return_value=server_results,
            ) as check_servers,
        ):
            result, status = service.list_user_keys("alice")

        self.assertEqual(status, 200)
        self.assertEqual(result["server_count"], 6)
        self.assertEqual(result["unknown_server_count"], 3)
        self.assertEqual(
            [key["accessible_server_count"] for key in result["keys"]],
            [2, 1],
        )
        check_servers.assert_called_once_with(
            servers,
            [{"username": "alice"}],
        )

    def test_list_user_keys_with_no_servers_reports_zero_counts(self):
        ssh_key = "ssh-ed25519 first-body laptop"
        keys = [
            {
                "key_id": ssh_key_id(ssh_key),
                "ssh_key": ssh_key,
                "key_type": "ssh-ed25519",
                "comment": "laptop",
            }
        ]

        with (
            patch.object(service, "get_user_key_records", return_value=keys),
            patch.object(service, "get_configured_servers", return_value=[]),
            patch.object(service, "check_access_matrix_for_servers") as check_servers,
        ):
            result, status = service.list_user_keys("alice")

        self.assertEqual(status, 200)
        self.assertEqual(result["server_count"], 0)
        self.assertEqual(result["unknown_server_count"], 0)
        self.assertEqual(result["keys"][0]["accessible_server_count"], 0)
        check_servers.assert_not_called()

    def test_connection_account_keys_are_protected(self):
        with patch.object(
            service,
            "get_configured_servers",
            return_value=[
                {"name": "alpha", "username": "alice"},
            ],
        ):
            result, status = service.delete_user_keys(
                "alice", {"key_ids": ["a" * 64]}
            )

        self.assertEqual(status, 400)
        self.assertEqual(result["error"], "protected_username")

    def test_unknown_key_id_is_rejected_without_remote_or_local_changes(self):
        ssh_key = "ssh-ed25519 first-body laptop"
        with (
            patch.object(service, "get_configured_servers", return_value=[]),
            patch.object(
                service,
                "get_users_by_name",
                return_value={"alice": {"ssh_keys": [ssh_key]}},
            ),
            patch.object(service, "remove_user_keys_from_file") as remove_local,
            patch.object(service.admin_executor, "submit") as submit,
        ):
            result, status = service.delete_user_keys(
                "alice", {"key_ids": ["f" * 64]}
            )

        self.assertEqual(status, 400)
        self.assertEqual(result["error"], "invalid_key_selection")
        self.assertEqual(result["unknown_key_ids"], ["f" * 64])
        remove_local.assert_not_called()
        submit.assert_not_called()

    def test_delete_selected_keys_uses_every_configured_server_then_local_store(self):
        first_key = "ssh-ed25519 first-body laptop"
        second_key = "ssh-ed25519 second-body desktop"
        first_key_id = ssh_key_id(first_key)
        servers = [
            {"name": "beta", "username": "monitor"},
            {"name": "alpha", "username": "monitor"},
        ]
        local_result = {
            "username": "alice",
            "requested_key_count": 1,
            "removed_keys": 1,
            "removed_lines": 1,
            "removed_key_ids": [first_key_id],
            "remaining_key_count": 1,
        }

        def remove_remote(server, username, keys):
            self.assertEqual(username, "alice")
            self.assertEqual(keys, [first_key])
            return {
                "server": server["name"],
                "error": None,
                "result": {"keys_removed": 1, "errors": []},
            }

        with (
            patch.object(service, "get_configured_servers", return_value=servers),
            patch.object(
                service,
                "get_users_by_name",
                return_value={
                    "alice": {"ssh_keys": [first_key, second_key]},
                },
            ),
            patch.object(
                service,
                "remove_user_keys_on_server",
                side_effect=remove_remote,
            ) as remove_remote_mock,
            patch.object(
                service,
                "remove_user_keys_from_file",
                return_value=(local_result, 200),
            ) as remove_local,
        ):
            result, status = service.delete_user_keys(
                "alice", {"key_ids": [first_key_id]}
            )

        self.assertEqual(status, 200)
        self.assertEqual(result["requested_key_count"], 1)
        self.assertEqual(result["selected_key_ids"], [first_key_id])
        self.assertEqual(
            [item["server"] for item in result["results"]],
            ["alpha", "beta"],
        )
        self.assertEqual(remove_remote_mock.call_count, 2)
        remove_local.assert_called_once_with("alice", [first_key_id])
        self.assertEqual(result["local"], local_result)

    def test_remote_key_removal_error_keeps_local_keys(self):
        ssh_key = "ssh-ed25519 first-body laptop"
        key_id = ssh_key_id(ssh_key)
        servers = [
            {"name": "alpha", "username": "monitor"},
            {"name": "beta", "username": "monitor"},
        ]

        def remove_remote(server, username, keys):
            if server["name"] == "beta":
                return {"server": "beta", "error": "offline", "result": {}}
            return {
                "server": "alpha",
                "error": None,
                "result": {"keys_removed": 1, "errors": []},
            }

        with (
            patch.object(service, "get_configured_servers", return_value=servers),
            patch.object(
                service,
                "get_users_by_name",
                return_value={"alice": {"ssh_keys": [ssh_key]}},
            ),
            patch.object(
                service,
                "remove_user_keys_on_server",
                side_effect=remove_remote,
            ),
            patch.object(service, "remove_user_keys_from_file") as remove_local,
        ):
            result, status = service.delete_user_keys(
                "alice", {"key_ids": [key_id]}
            )

        self.assertEqual(status, 200)
        self.assertTrue(result["local"]["skipped"])
        self.assertEqual(result["local"]["reason"], "remote_errors")
        self.assertEqual(result["local"]["removed_keys"], 0)
        remove_local.assert_not_called()

    def test_empty_access_matrix_does_not_schedule_remote_commands(self):
        with (
            patch.object(service, "get_configured_servers", return_value=[]),
            patch.object(service, "load_user_keys", return_value=[]),
            patch.object(service.admin_executor, "submit") as submit,
        ):
            matrix, status = service.build_access_matrix()

        self.assertEqual(status, 200)
        self.assertEqual(matrix["servers"], [])
        self.assertEqual(matrix["users"], [])
        self.assertFalse(matrix["cached"])
        submit.assert_not_called()

    def test_access_matrix_distinguishes_partial_and_complete_key_sync(self):
        first_key = "ssh-ed25519 first-body laptop"
        second_key = "ssh-ed25519 second-body desktop"
        first_key_id = ssh_key_id(first_key)
        second_key_id = ssh_key_id(second_key)
        users = [
            {
                "username": "alice",
                "ssh_keys": [first_key, second_key],
                "key_ids": [first_key_id, second_key_id],
                "key_hashes": [
                    key_fingerprint(first_key),
                    key_fingerprint(second_key),
                ],
            }
        ]
        servers = [{"name": "alpha", "username": "monitor"}]
        remote_result = {
            "server": "alpha",
            "error": None,
            "users": {
                "alice": {
                    "user_exists": True,
                    "authorized_keys_readable": True,
                    "authorized_key_ids": [first_key_id],
                    "authorized_key_count": 1,
                    "error": None,
                }
            },
        }

        with (
            patch.object(service, "get_configured_servers", return_value=servers),
            patch.object(service, "load_user_keys", return_value=users),
            patch.object(
                service,
                "check_access_matrix_for_server",
                return_value=remote_result,
            ),
        ):
            matrix, status = service.build_access_matrix()

        self.assertEqual(status, 200)
        cell = matrix["users"][0]["servers"][0]
        self.assertTrue(cell["accessible"])
        self.assertTrue(cell["key_installed"])
        self.assertFalse(cell["all_keys_installed"])
        self.assertEqual(cell["expected_key_count"], 2)
        self.assertEqual(cell["installed_key_count"], 1)
        self.assertEqual(cell["missing_key_count"], 1)
        self.assertEqual(cell["remote_key_count"], 1)

        remote_user = remote_result["users"]["alice"]
        remote_user["authorized_key_ids"] = [first_key_id, second_key_id]
        remote_user["authorized_key_count"] = 2
        service.invalidate_access_matrix_cache()

        with (
            patch.object(service, "get_configured_servers", return_value=servers),
            patch.object(service, "load_user_keys", return_value=users),
            patch.object(
                service,
                "check_access_matrix_for_server",
                return_value=remote_result,
            ),
        ):
            complete_matrix, status = service.build_access_matrix()

        self.assertEqual(status, 200)
        complete_cell = complete_matrix["users"][0]["servers"][0]
        self.assertTrue(complete_cell["all_keys_installed"])
        self.assertEqual(complete_cell["installed_key_count"], 2)
        self.assertEqual(complete_cell["missing_key_count"], 0)


if __name__ == "__main__":
    unittest.main()
