import threading
import time
import unittest
from contextlib import contextmanager
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from gpu_monitor.access import service
from gpu_monitor.user_store import key_fingerprint, ssh_key_id


class AccessServiceTests(unittest.TestCase):
    def setUp(self):
        service.invalidate_access_matrix_cache()

    def tearDown(self):
        service.invalidate_access_matrix_cache()

    def wait_for_user_operation_references(self, username, expected, timeout=1):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with service.user_operation_locks_lock:
                entry = service.user_operation_locks.get(username)
                references = entry["references"] if entry else 0
            if references == expected:
                return
            time.sleep(0.001)
        self.fail(
            f"user operation lock for {username!r} did not reach "
            f"{expected} references"
        )

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

    def test_configure_selected_access_rejects_zero_key_account(self):
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
            patch.object(service.admin_executor, "submit") as submit,
        ):
            result, status = service.configure_selected_access(
                ["alpha"],
                ["alice"],
            )

        self.assertEqual(status, 400)
        self.assertEqual(result["error"], "invalid_selection")
        self.assertEqual(result["unknown_servers"], [])
        self.assertEqual(result["unknown_users"], [])
        self.assertEqual(result["users_without_keys"], ["alice"])
        submit.assert_not_called()

    def test_configure_access_pairs_rejects_zero_key_account(self):
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
            patch.object(service.admin_executor, "submit") as submit,
        ):
            result, status = service.configure_access_pairs(
                [{"server": "alpha", "user": "alice"}]
            )

        self.assertEqual(status, 400)
        self.assertEqual(result["error"], "invalid_selection")
        self.assertEqual(result["unknown_servers"], [])
        self.assertEqual(result["unknown_users"], [])
        self.assertEqual(result["users_without_keys"], ["alice"])
        submit.assert_not_called()

    def test_revoke_access_pairs_deduplicates_selected_pairs_and_keeps_local_keys(self):
        alice_keys = [
            "ssh-ed25519 alice-first laptop",
            "ssh-ed25519 alice-second desktop",
        ]
        bob_keys = ["ssh-ed25519 bob-first workstation"]
        servers = {
            "alpha": {"name": "alpha"},
            "beta": {"name": "beta"},
            "gamma": {"name": "gamma"},
        }
        users = {
            "alice": {"username": "alice", "ssh_keys": alice_keys},
            "bob": {"username": "bob", "ssh_keys": bob_keys},
        }
        pairs = [
            {"server": "beta", "user": "alice"},
            {"server": "alpha", "user": "bob"},
            {"server": "beta", "user": "alice"},
        ]
        locked_usernames = []
        lock_active = threading.Event()

        @contextmanager
        def record_lock(usernames):
            locked_usernames.append(list(usernames))
            lock_active.set()
            try:
                yield
            finally:
                lock_active.clear()

        def remove_remote(server, username, ssh_keys):
            self.assertTrue(lock_active.is_set())
            return {
                "server": server["name"],
                "error": None,
                "result": {"keys_removed": len(ssh_keys), "errors": []},
            }

        with (
            patch.object(service, "get_servers_by_name", return_value=servers),
            patch.object(service, "get_users_by_name", return_value=users),
            patch.object(
                service,
                "serialize_user_operations",
                side_effect=record_lock,
            ),
            patch.object(
                service,
                "remove_user_keys_on_server",
                side_effect=remove_remote,
            ) as remove_keys,
            patch.object(service, "remove_user_keys_from_file") as remove_local,
            patch.object(service, "invalidate_access_matrix_cache") as invalidate,
        ):
            result, status = service.revoke_access_pairs(pairs)

        self.assertEqual(status, 200)
        self.assertEqual(
            result,
            {
                "error": None,
                "local_keys_preserved": True,
                "results": [
                    {
                        "server": "alpha",
                        "user": "bob",
                        "error": None,
                        "result": {"keys_removed": 1, "errors": []},
                    },
                    {
                        "server": "beta",
                        "user": "alice",
                        "error": None,
                        "result": {"keys_removed": 2, "errors": []},
                    },
                ],
            },
        )
        self.assertEqual(set(locked_usernames[0]), {"alice", "bob"})
        self.assertEqual(remove_keys.call_count, 2)
        self.assertEqual(
            {
                (call.args[0]["name"], call.args[1], tuple(call.args[2]))
                for call in remove_keys.call_args_list
            },
            {
                ("alpha", "bob", tuple(bob_keys)),
                ("beta", "alice", tuple(alice_keys)),
            },
        )
        remove_local.assert_not_called()
        invalidate.assert_called_once_with()

    def test_revoke_access_pairs_rejects_malformed_pairs_before_remote_work(self):
        cases = [
            (None, "pairs_must_be_a_list"),
            ([], "select_at_least_one_access_pair"),
            (["alpha:alice"], "pairs_must_contain_objects"),
            (
                [{"server": "alpha", "user": 7}],
                "pair_server_and_user_must_be_strings",
            ),
        ]

        for pairs, expected_error in cases:
            with self.subTest(pairs=pairs):
                with (
                    patch.object(service, "get_servers_by_name", return_value={}),
                    patch.object(service, "get_users_by_name", return_value={}),
                    patch.object(service.admin_executor, "submit") as submit,
                ):
                    result, status = service.revoke_access_pairs(pairs)

                self.assertEqual(status, 400)
                self.assertEqual(result["error"], expected_error)
                self.assertEqual(result["results"], [])
                submit.assert_not_called()

    def test_revoke_access_pairs_rejects_unknown_and_protected_selections(self):
        with (
            patch.object(
                service,
                "get_servers_by_name",
                return_value={
                    "alpha": {"name": "alpha", "username": "monitor"}
                },
            ),
            patch.object(
                service,
                "get_users_by_name",
                return_value={
                    "root": {
                        "username": "root",
                        "ssh_keys": ["ssh-ed25519 root-key"],
                    },
                    "monitor": {
                        "username": "monitor",
                        "ssh_keys": ["ssh-ed25519 monitor-key"],
                    },
                },
            ),
            patch.object(service.admin_executor, "submit") as submit,
        ):
            result, status = service.revoke_access_pairs(
                [
                    {"server": "missing", "user": "ghost"},
                    {"server": "alpha", "user": "root"},
                    {"server": "alpha", "user": "monitor"},
                ]
            )

        self.assertEqual(status, 400)
        self.assertEqual(result["error"], "invalid_selection")
        self.assertEqual(result["unknown_servers"], ["missing"])
        self.assertEqual(result["unknown_users"], ["ghost"])
        self.assertEqual(result["protected_users"], ["monitor", "root"])
        self.assertEqual(result["results"], [])
        submit.assert_not_called()

    def test_revoke_access_pairs_rejects_users_without_local_keys(self):
        with (
            patch.object(
                service,
                "get_servers_by_name",
                return_value={"alpha": {"name": "alpha"}},
            ),
            patch.object(
                service,
                "get_users_by_name",
                return_value={
                    "alice": {"username": "alice", "ssh_keys": []},
                },
            ),
            patch.object(service.admin_executor, "submit") as submit,
        ):
            result, status = service.revoke_access_pairs(
                [{"server": "alpha", "user": "alice"}]
            )

        self.assertEqual(status, 400)
        self.assertEqual(result["error"], "invalid_selection")
        self.assertEqual(result["unknown_servers"], [])
        self.assertEqual(result["unknown_users"], [])
        self.assertEqual(result["users_without_keys"], ["alice"])
        self.assertEqual(result["results"], [])
        submit.assert_not_called()

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

    def test_delete_last_key_then_delete_zero_key_account(self):
        ssh_key = "ssh-ed25519 first-body laptop"
        key_id = ssh_key_id(ssh_key)
        servers = [{"name": "alpha", "username": "monitor"}]
        users_by_name = {
            "alice": {
                "username": "alice",
                "ssh_keys": [ssh_key],
            }
        }

        def remove_last_local_key(username, key_ids):
            self.assertEqual(username, "alice")
            self.assertEqual(key_ids, [key_id])
            users_by_name[username]["ssh_keys"] = []
            return {
                "username": username,
                "requested_key_count": 1,
                "removed_keys": 1,
                "removed_lines": 1,
                "removed_key_ids": [key_id],
                "remaining_key_count": 0,
            }, 200

        def delete_remote_account(
            server,
            username,
            ssh_keys,
            mode,
            clear_authorized_keys,
            remove_home,
        ):
            self.assertEqual(username, "alice")
            self.assertEqual(ssh_keys, [])
            self.assertEqual(mode, "delete_account")
            self.assertTrue(clear_authorized_keys)
            self.assertTrue(remove_home)
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
                side_effect=lambda: users_by_name,
            ),
            patch.object(
                service,
                "remove_user_keys_on_server",
                return_value={
                    "server": "alpha",
                    "error": None,
                    "result": {"keys_removed": 1, "errors": []},
                },
            ),
            patch.object(
                service,
                "remove_user_keys_from_file",
                side_effect=remove_last_local_key,
            ) as remove_local_key,
            patch.object(
                service,
                "revoke_user_on_server",
                side_effect=delete_remote_account,
            ) as delete_remote,
            patch.object(
                service,
                "remove_user_from_file",
                return_value=({"username": "alice", "removed_lines": 1}, 200),
            ) as remove_local_account,
        ):
            key_result, key_status = service.delete_user_keys(
                "alice", {"key_ids": [key_id]}
            )
            account_result, account_status = service.delete_user_access(
                "alice",
                {
                    "mode": "delete_account",
                    "confirm": "alice",
                    "remove_home": True,
                    "remove_from_user_file": True,
                    "clear_authorized_keys": True,
                },
            )

        self.assertEqual(key_status, 200)
        self.assertEqual(key_result["local"]["remaining_key_count"], 0)
        remove_local_key.assert_called_once_with("alice", [key_id])
        self.assertEqual(account_status, 200)
        self.assertTrue(account_result["results"][0]["result"]["deleted"])
        delete_remote.assert_called_once()
        remove_local_account.assert_called_once_with("alice")

    def test_delete_keys_blocks_same_user_configure_until_local_update(self):
        ssh_key = "ssh-ed25519 first-body laptop"
        key_id = ssh_key_id(ssh_key)
        server = {"name": "alpha", "username": "monitor"}
        users_by_name = {
            "alice": {"username": "alice", "ssh_keys": [ssh_key]},
        }
        delete_remote_started = threading.Event()
        allow_delete_to_finish = threading.Event()
        configure_remote_started = threading.Event()

        def remove_remote(*args):
            delete_remote_started.set()
            allow_delete_to_finish.wait(2)
            return {
                "server": "alpha",
                "error": None,
                "result": {"keys_removed": 1, "errors": []},
            }

        def remove_local(username, key_ids):
            users_by_name[username]["ssh_keys"] = []
            return {
                "username": username,
                "requested_key_count": 1,
                "removed_keys": 1,
                "removed_lines": 1,
                "removed_key_ids": key_ids,
                "remaining_key_count": 0,
            }, 200

        def configure_remote(*args):
            configure_remote_started.set()
            return {"server": "alpha", "error": None, "users": {}}

        with (
            patch.object(service, "get_configured_servers", return_value=[server]),
            patch.object(
                service,
                "get_servers_by_name",
                return_value={"alpha": server},
            ),
            patch.object(
                service,
                "get_users_by_name",
                side_effect=lambda: users_by_name,
            ),
            patch.object(
                service,
                "remove_user_keys_on_server",
                side_effect=remove_remote,
            ),
            patch.object(
                service,
                "remove_user_keys_from_file",
                side_effect=remove_local,
            ),
            patch.object(
                service,
                "configure_access_for_server",
                side_effect=configure_remote,
            ),
        ):
            executor = ThreadPoolExecutor(max_workers=2)
            try:
                delete_future = executor.submit(
                    service.delete_user_keys,
                    "alice",
                    {"key_ids": [key_id]},
                )
                self.assertTrue(delete_remote_started.wait(1))
                configure_future = executor.submit(
                    service.configure_selected_access,
                    ["alpha"],
                    ["alice"],
                )
                self.wait_for_user_operation_references("alice", 2)
                self.assertFalse(configure_remote_started.is_set())

                allow_delete_to_finish.set()
                delete_result, delete_status = delete_future.result(timeout=2)
                configure_result, configure_status = configure_future.result(timeout=2)
            finally:
                allow_delete_to_finish.set()
                executor.shutdown(wait=True)

        self.assertEqual(delete_status, 200)
        self.assertEqual(delete_result["local"]["remaining_key_count"], 0)
        self.assertEqual(configure_status, 400)
        self.assertEqual(configure_result["users_without_keys"], ["alice"])
        self.assertFalse(configure_remote_started.is_set())

    def test_user_operations_for_different_users_remain_concurrent(self):
        alice_key = "ssh-ed25519 alice-body laptop"
        bob_key = "ssh-ed25519 bob-body laptop"
        alice_key_id = ssh_key_id(alice_key)
        server = {"name": "alpha", "username": "monitor"}
        users_by_name = {
            "alice": {"username": "alice", "ssh_keys": [alice_key]},
            "bob": {"username": "bob", "ssh_keys": [bob_key]},
        }
        alice_delete_started = threading.Event()
        allow_alice_delete = threading.Event()
        bob_configure_started = threading.Event()

        def remove_alice_remote(*args):
            alice_delete_started.set()
            allow_alice_delete.wait(2)
            return {
                "server": "alpha",
                "error": None,
                "result": {"keys_removed": 1, "errors": []},
            }

        def configure_bob_remote(*args):
            bob_configure_started.set()
            return {"server": "alpha", "error": None, "users": {}}

        with (
            patch.object(service, "get_configured_servers", return_value=[server]),
            patch.object(
                service,
                "get_servers_by_name",
                return_value={"alpha": server},
            ),
            patch.object(
                service,
                "get_users_by_name",
                side_effect=lambda: users_by_name,
            ),
            patch.object(
                service,
                "remove_user_keys_on_server",
                side_effect=remove_alice_remote,
            ),
            patch.object(
                service,
                "remove_user_keys_from_file",
                return_value=({"remaining_key_count": 0}, 200),
            ),
            patch.object(
                service,
                "configure_access_for_server",
                side_effect=configure_bob_remote,
            ),
        ):
            executor = ThreadPoolExecutor(max_workers=2)
            try:
                delete_future = executor.submit(
                    service.delete_user_keys,
                    "alice",
                    {"key_ids": [alice_key_id]},
                )
                self.assertTrue(alice_delete_started.wait(1))
                configure_future = executor.submit(
                    service.configure_selected_access,
                    ["alpha"],
                    ["bob"],
                )
                self.assertTrue(bob_configure_started.wait(1))
                configure_result, configure_status = configure_future.result(timeout=1)
                self.assertEqual(configure_status, 200)
                self.assertIsNone(configure_result["error"])
            finally:
                allow_alice_delete.set()
                executor.shutdown(wait=True)

        delete_result, delete_status = delete_future.result(timeout=1)
        self.assertEqual(delete_status, 200)
        self.assertIsNone(delete_result["error"])

    def test_user_operation_locks_release_after_exception(self):
        first_entered = threading.Event()
        allow_exception = threading.Event()
        second_entered = threading.Event()

        def failing_operation():
            with service.serialize_user_operations(["alice"]):
                first_entered.set()
                allow_exception.wait(2)
                raise RuntimeError("failed operation")

        def waiting_operation():
            with service.serialize_user_operations(["alice"]):
                second_entered.set()

        executor = ThreadPoolExecutor(max_workers=2)
        try:
            first_future = executor.submit(failing_operation)
            self.assertTrue(first_entered.wait(1))
            second_future = executor.submit(waiting_operation)
            self.wait_for_user_operation_references("alice", 2)
            self.assertFalse(second_entered.is_set())

            allow_exception.set()
            with self.assertRaisesRegex(RuntimeError, "failed operation"):
                first_future.result(timeout=1)
            second_future.result(timeout=1)
        finally:
            allow_exception.set()
            executor.shutdown(wait=True)

        self.assertTrue(second_entered.is_set())
        with service.user_operation_locks_lock:
            self.assertNotIn("alice", service.user_operation_locks)

    def test_multi_user_operation_locks_use_stable_order(self):
        with service.serialize_user_operations(["bob", "alice", "bob"]):
            with service.user_operation_locks_lock:
                self.assertEqual(
                    list(service.user_operation_locks),
                    ["alice", "bob"],
                )

        with service.user_operation_locks_lock:
            self.assertNotIn("alice", service.user_operation_locks)
            self.assertNotIn("bob", service.user_operation_locks)

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

    def test_cache_invalidation_fences_in_flight_matrix_results(self):
        servers = [{"name": "alpha"}]
        users = [{"username": "alice"}]
        with (
            patch.object(service, "get_user_store_generation", return_value=1),
            patch.object(service, "get_file_signature", return_value=(1, 1)),
        ):
            old_key = service.access_matrix_cache_key(servers, users)
            service.invalidate_access_matrix_cache()
            service.set_cached_access_matrix(
                old_key,
                {"servers": [], "users": [], "cached": False},
            )
            current_key = service.access_matrix_cache_key(servers, users)

        self.assertNotEqual(old_key, current_key)
        self.assertIsNone(service.get_cached_access_matrix(current_key))

    def test_user_snapshot_changed_during_load_requests_a_retry(self):
        generation = {"value": 0}
        old_users = [
            {
                "username": "alice",
                "ssh_keys": ["ssh-ed25519 first-key"],
                "key_ids": ["first"],
                "key_hashes": [],
            }
        ]
        new_users = [
            {
                "username": "alice",
                "ssh_keys": [
                    "ssh-ed25519 first-key",
                    "ssh-ed25519 second-key",
                ],
                "key_ids": ["first", "second"],
                "key_hashes": [],
            }
        ]
        load_count = 0

        def load_users_during_mutation():
            nonlocal load_count
            load_count += 1
            if load_count == 1:
                generation["value"] = 1
                return old_users
            return new_users

        with (
            patch.object(service, "get_configured_servers", return_value=[]),
            patch.object(
                service,
                "load_user_keys",
                side_effect=load_users_during_mutation,
            ),
            patch.object(
                service,
                "get_user_store_generation",
                side_effect=lambda: generation["value"],
            ),
            patch.object(service, "get_file_signature", return_value=(1, 1)),
        ):
            old_matrix, old_status = service.build_access_matrix()
            new_matrix, new_status = service.build_access_matrix()

        self.assertEqual(old_status, 409)
        self.assertEqual(old_matrix["error"], "access_matrix_changed")
        self.assertEqual(new_status, 200)
        self.assertEqual(new_matrix["users"][0]["key_count"], 2)
        self.assertFalse(new_matrix["cached"])

    def test_matrix_changed_during_remote_check_is_not_cached(self):
        generation = {"value": 0}
        users = [
            {
                "username": "alice",
                "ssh_keys": ["ssh-ed25519 first-key"],
                "key_ids": ["first"],
                "key_hashes": [],
            }
        ]
        servers = [{"name": "alpha"}]
        remote_result = {
            "server": "alpha",
            "error": None,
            "users": {
                "alice": {
                    "user_exists": True,
                    "authorized_keys_readable": True,
                    "authorized_key_ids": ["first"],
                    "authorized_key_count": 1,
                    "error": None,
                }
            },
        }

        def mutate_during_check(selected_servers, selected_users):
            generation["value"] = 1
            return {"alpha": remote_result}

        with (
            patch.object(service, "get_configured_servers", return_value=servers),
            patch.object(service, "load_user_keys", return_value=users),
            patch.object(
                service,
                "get_user_store_generation",
                side_effect=lambda: generation["value"],
            ),
            patch.object(service, "get_file_signature", return_value=(1, 1)),
            patch.object(
                service,
                "check_access_matrix_for_servers",
                side_effect=mutate_during_check,
            ),
        ):
            matrix, status = service.build_access_matrix()
            old_key = service.access_matrix_cache_key(
                servers,
                users,
                (0, 0, (1, 1), (1, 1)),
            )

        self.assertEqual(status, 409)
        self.assertEqual(matrix["error"], "access_matrix_changed")
        self.assertIsNone(service.get_cached_access_matrix(old_key))

    def test_cached_matrix_is_ignored_when_source_changes_during_lookup(self):
        generations = iter([0, 1, 1])
        servers = []
        users = [
            {
                "username": "alice",
                "ssh_keys": ["ssh-ed25519 current-key"],
                "key_ids": ["current"],
                "key_hashes": [],
            }
        ]
        old_key = service.access_matrix_cache_key(
            servers,
            users,
            (service.access_matrix_cache_generation, 0, (1, 1), (1, 1)),
        )
        service.set_cached_access_matrix(
            old_key,
            {
                "servers": [],
                "users": [{"username": "alice", "key_count": 0}],
                "cached": False,
            },
        )

        with (
            patch.object(service, "get_configured_servers", return_value=servers),
            patch.object(service, "load_user_keys", return_value=users),
            patch.object(
                service,
                "get_user_store_generation",
                side_effect=lambda: next(generations),
            ),
            patch.object(service, "get_file_signature", return_value=(1, 1)),
        ):
            matrix, status = service.build_access_matrix()

        self.assertEqual(status, 409)
        self.assertEqual(matrix["error"], "access_matrix_changed")

    def test_access_matrix_includes_zero_key_account(self):
        users = [
            {
                "username": "alice",
                "ssh_keys": [],
                "key_ids": [],
                "key_hashes": [],
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
                    "authorized_key_ids": [],
                    "authorized_key_count": 0,
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
            ) as check_server,
        ):
            matrix, status = service.build_access_matrix()

        self.assertEqual(status, 200)
        self.assertEqual(len(matrix["users"]), 1)
        self.assertEqual(matrix["users"][0]["username"], "alice")
        self.assertEqual(matrix["users"][0]["key_count"], 0)
        self.assertEqual(len(matrix["users"][0]["servers"]), 1)
        cell = matrix["users"][0]["servers"][0]
        self.assertTrue(cell["user_exists"])
        self.assertFalse(cell["key_installed"])
        self.assertFalse(cell["accessible"])
        self.assertFalse(cell["all_keys_installed"])
        self.assertEqual(cell["expected_key_count"], 0)
        self.assertEqual(cell["installed_key_count"], 0)
        self.assertEqual(cell["missing_key_count"], 0)
        check_server.assert_called_once_with(servers[0], users)

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
