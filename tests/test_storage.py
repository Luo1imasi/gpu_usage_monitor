import json
import shlex
import unittest
from unittest.mock import patch

from gpu_monitor import storage


SERVER = {"name": "alpha"}
MEBIBYTE = 1024 * 1024


def storage_payload(*, partial=False):
    users = [{"username": "alice", "used": 128 * MEBIBYTE}]
    if partial:
        users.append(
            {
                "username": "bob",
                "used": None,
                "error": "unavailable",
            }
        )
    return {
        "filesystem": {
            "path": "/home",
            "total": 10_000,
            "used": 4_000,
            "available": 5_000,
            "percent": 44.4,
        },
        "users": users,
        "partial": partial,
        "user_error_count": 1 if partial else 0,
    }


class StorageCommandTests(unittest.TestCase):
    def test_remote_scripts_compile_for_sudo_and_fallback(self):
        sudo_parts = shlex.split(storage.build_storage_command(use_sudo=True))
        user_parts = shlex.split(storage.build_storage_command(use_sudo=False))

        self.assertEqual(sudo_parts[:3], ["sudo", "-n", "python3"])
        self.assertEqual(user_parts[:2], ["python3", "-c"])
        compile(sudo_parts[-1], "storage-remote.py", "exec")
        compile(user_parts[-1], "storage-remote.py", "exec")

    def test_collection_uses_separate_namespace_and_falls_back_without_sudo(self):
        with (
            patch.object(
                storage,
                "get_monitoring_settings",
                return_value={"storage_user_min_size_mb": 64},
            ),
            patch.object(
                storage,
                "run_server_ssh_command_status",
                side_effect=[
                    (1, "", "sudo unavailable"),
                    (0, json.dumps(storage_payload()), ""),
                ],
            ) as run,
        ):
            result = storage.collect_storage_for_server(SERVER)

        self.assertIsNone(result["error"])
        self.assertEqual(result["filesystem"]["used"], 4_000)
        self.assertEqual(
            result["users"],
            [{"username": "alice", "used": 128 * MEBIBYTE}],
        )
        self.assertFalse(result["partial"])
        self.assertEqual(result["user_min_bytes"], 64 * MEBIBYTE)
        self.assertEqual(result["filtered_user_count"], 0)
        self.assertEqual(run.call_count, 2)
        for call in run.call_args_list:
            self.assertEqual(call.kwargs["namespace"], "storage")

    def test_user_errors_mark_a_sample_as_partial(self):
        result = storage._parse_storage_response(
            SERVER,
            json.dumps(storage_payload(partial=True)),
        )

        self.assertTrue(result["partial"])
        self.assertEqual(result["user_error_count"], 1)
        self.assertEqual(result["users"][1]["error"], "unavailable")

    def test_small_known_users_are_filtered_but_unknown_usage_is_retained(self):
        payload = storage_payload(partial=True)
        payload["users"] = [
            {"username": "small", "used": 99 * MEBIBYTE},
            {"username": "boundary", "used": 100 * MEBIBYTE},
            {"username": "large", "used": 101 * MEBIBYTE},
            {"username": "unknown", "used": None, "error": "unavailable"},
        ]

        result = storage._parse_storage_response(SERVER, json.dumps(payload))

        self.assertEqual(
            [user["username"] for user in result["users"]],
            ["boundary", "large", "unknown"],
        )
        self.assertEqual(result["user_min_bytes"], 100 * MEBIBYTE)
        self.assertEqual(result["filtered_user_count"], 1)
        self.assertTrue(result["partial"])
        self.assertEqual(result["user_error_count"], 1)

    def test_waiting_result_exposes_configured_threshold(self):
        with patch.object(
            storage,
            "get_monitoring_settings",
            return_value={"storage_user_min_size_mb": 64},
        ):
            result = storage.make_waiting_storage_result("alpha")

        self.assertEqual(result["user_min_bytes"], 64 * MEBIBYTE)
        self.assertEqual(result["filtered_user_count"], 0)

    def test_zero_threshold_retains_a_zero_usage_user(self):
        payload = storage_payload()
        payload["users"] = [{"username": "empty", "used": 0}]

        result = storage._parse_storage_response(
            SERVER,
            json.dumps(payload),
            user_min_bytes=0,
        )

        self.assertEqual(result["users"], [{"username": "empty", "used": 0}])
        self.assertEqual(result["filtered_user_count"], 0)

    def test_failed_collection_exposes_threshold_metadata(self):
        with (
            patch.object(
                storage,
                "get_monitoring_settings",
                return_value={"storage_user_min_size_mb": 64},
            ),
            patch.object(
                storage,
                "run_server_ssh_command_status",
                return_value=(1, "", "query failed"),
            ),
        ):
            result = storage.collect_storage_for_server(SERVER)

        self.assertEqual(result["user_min_bytes"], 64 * MEBIBYTE)
        self.assertEqual(result["filtered_user_count"], 0)
        self.assertEqual(result["error"], "query failed")

    def test_invalid_numeric_fields_are_rejected(self):
        payload = storage_payload()
        payload["filesystem"]["total"] = "large"

        with self.assertRaisesRegex(ValueError, "total is invalid"):
            storage._parse_storage_response(SERVER, json.dumps(payload))


class StorageStateTests(unittest.TestCase):
    def test_failure_preserves_last_success_as_stale(self):
        success = {
            "server": "alpha",
            **storage_payload(),
            "user_min_bytes": 100 * MEBIBYTE,
            "filtered_user_count": 2,
            "error": None,
        }
        previous = storage.merge_storage_result(None, success, now=10)

        merged = storage.merge_storage_result(
            previous,
            {
                "server": "alpha",
                "filesystem": None,
                "users": [],
                "partial": False,
                "user_error_count": 0,
                "user_min_bytes": 64 * MEBIBYTE,
                "filtered_user_count": 0,
                "error": "SSH timeout",
            },
            now=20,
        )

        self.assertIsNone(merged["error"])
        self.assertTrue(merged["stale"])
        self.assertEqual(merged["updated_at"], 10)
        self.assertEqual(merged["last_error"], "SSH timeout")
        self.assertEqual(merged["filesystem"]["used"], 4_000)
        self.assertEqual(merged["user_min_bytes"], 100 * MEBIBYTE)
        self.assertEqual(merged["filtered_user_count"], 2)

    def test_identity_change_discards_cached_sample(self):
        state = storage.StorageStateStore()
        old_server = {
            "name": "alpha",
            "host": "old.example",
            "port": 22,
            "username": "gpu",
        }
        state.initialize_storage_cache([old_server])
        state.publish_storage_result(
            {
                "server": "alpha",
                **storage_payload(),
                "error": None,
            },
            ["alpha"],
        )

        state.initialize_storage_cache([{**old_server, "host": "new.example"}])

        result = state.get_cached_data()[0]
        self.assertEqual(result["error"], "Waiting for first sample")
        self.assertIsNone(result["filesystem"])


if __name__ == "__main__":
    unittest.main()
