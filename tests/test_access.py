import unittest
from unittest.mock import patch

from gpu_monitor.access import service


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


if __name__ == "__main__":
    unittest.main()
