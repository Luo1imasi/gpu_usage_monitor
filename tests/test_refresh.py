import copy
import json
import unittest
from unittest.mock import patch

from gpu_monitor import config
from gpu_monitor.gpu import collector, state


def gpu_result(server, marker):
    return {
        "server": server,
        "gpus": [{"index": 0, "name": marker, "processes": []}],
        "error": None,
    }


class FakeFuture:
    def __init__(self, result=None, error=None):
        self._result = result
        self._error = error

    def result(self):
        if self._error is not None:
            raise self._error
        return self._result


class FakeExecutor:
    def __init__(self, results):
        self.results = results
        self.by_name = {}

    def submit(self, _callback, server):
        value = self.results[server["name"]]
        future = value if isinstance(value, FakeFuture) else FakeFuture(result=value)
        self.by_name[server["name"]] = future
        return future


class MonitoringSettingsTests(unittest.TestCase):
    def test_example_config_only_exposes_common_settings(self):
        example_path = config.CONFIG_PATH.with_name("config.example.json")
        with open(example_path) as file:
            example = json.load(file)

        self.assertEqual(
            set(example["monitoring"]),
            {
                "refresh_interval_seconds",
                "storage_refresh_interval_seconds",
            },
        )
        self.assertNotIn("ssh", example)
        self.assertEqual(
            set(example["servers"][0]),
            {"name", "host", "port", "username", "key_file"},
        )

    def test_two_second_sample_interval_is_accepted(self):
        with patch.object(
            config,
            "load_config",
            return_value={
                "monitoring": {
                    "refresh_interval_seconds": 2,
                }
            },
        ):
            settings = config.get_monitoring_settings()

        self.assertEqual(settings["refresh_interval"], 2)
        self.assertNotIn("api_poll_interval", settings)
        self.assertEqual(settings["storage_refresh_interval"], 300)
        self.assertEqual(settings["storage_user_min_size_mb"], 100)

    def test_sample_interval_is_clamped_to_one_second(self):
        with patch.object(
            config,
            "load_config",
            return_value={
                "monitoring": {
                    "refresh_interval_seconds": 0.1,
                }
            },
        ):
            settings = config.get_monitoring_settings()

        self.assertEqual(settings["refresh_interval"], 1)

    def test_storage_refresh_interval_is_clamped_to_sixty_seconds(self):
        with patch.object(
            config,
            "load_config",
            return_value={
                "monitoring": {
                    "storage_refresh_interval_seconds": 5,
                }
            },
        ):
            settings = config.get_monitoring_settings()

        self.assertEqual(settings["storage_refresh_interval"], 60)

    def test_storage_user_min_size_is_clamped_to_zero(self):
        with patch.object(
            config,
            "load_config",
            return_value={
                "monitoring": {
                    "storage_user_min_size_mb": -1,
                }
            },
        ):
            settings = config.get_monitoring_settings()

        self.assertEqual(settings["storage_user_min_size_mb"], 0)

    def test_boolean_storage_user_min_size_uses_default(self):
        with patch.object(
            config,
            "load_config",
            return_value={
                "monitoring": {
                    "storage_user_min_size_mb": True,
                }
            },
        ):
            settings = config.get_monitoring_settings()

        self.assertEqual(settings["storage_user_min_size_mb"], 100)


class GPUCacheTests(unittest.TestCase):
    def setUp(self):
        self.state_store = state.gpu_state
        with self.state_store.lock:
            self.original_cached_data = self.state_store.cached_data
            self.original_cached_server_identities = (
                self.state_store.cached_server_identities
            )
            self.state_store.cached_data = []
            self.state_store.cached_server_identities = {}

    def tearDown(self):
        with self.state_store.lock:
            self.state_store.cached_data = self.original_cached_data
            self.state_store.cached_server_identities = (
                self.original_cached_server_identities
            )

    def test_success_replaces_stale_state_and_updates_timestamp(self):
        previous = {
            **gpu_result("alpha", "old"),
            "stale": True,
            "updated_at": 10,
            "last_error": "old failure",
        }

        merged = state.merge_gpu_result(
            previous,
            gpu_result("alpha", "new"),
            now=20,
        )

        self.assertEqual(merged["gpus"][0]["name"], "new")
        self.assertFalse(merged["stale"])
        self.assertEqual(merged["updated_at"], 20)
        self.assertIsNone(merged["last_error"])

    def test_failure_preserves_last_success_as_stale(self):
        previous = {
            **gpu_result("alpha", "last-good"),
            "stale": False,
            "updated_at": 10,
            "last_error": None,
        }

        merged = state.merge_gpu_result(
            previous,
            {"server": "alpha", "error": "network timeout"},
            now=20,
        )

        self.assertEqual(merged["gpus"], previous["gpus"])
        self.assertIsNone(merged["error"])
        self.assertTrue(merged["stale"])
        self.assertEqual(merged["updated_at"], 10)
        self.assertEqual(merged["last_error"], "network timeout")

    def test_failure_preserves_success_with_zero_gpus(self):
        previous = {
            "server": "alpha",
            "gpus": [],
            "error": None,
            "updated_at": 10,
        }

        merged = state.merge_gpu_result(
            previous,
            {"server": "alpha", "error": "network timeout"},
            now=20,
        )

        self.assertEqual(merged["gpus"], [])
        self.assertTrue(merged["stale"])
        self.assertEqual(merged["updated_at"], 10)

    def test_first_failure_remains_an_offline_result(self):
        merged = state.merge_gpu_result(
            state.make_waiting_gpu_result("alpha"),
            {"server": "alpha", "error": "connection refused"},
            now=20,
        )

        self.assertEqual(merged["error"], "connection refused")
        self.assertFalse(merged["stale"])
        self.assertIsNone(merged["updated_at"])
        self.assertEqual(merged["last_error"], "connection refused")

    def test_malformed_result_is_not_published_as_success(self):
        merged = state.merge_gpu_result(
            None,
            {"server": "alpha", "error": None},
            now=20,
        )

        self.assertEqual(merged["error"], "Invalid GPU result")
        self.assertFalse(merged["stale"])
        self.assertIsNone(merged["updated_at"])

    def test_refresh_publishes_each_server_as_soon_as_it_completes(self):
        servers = [{"name": "alpha"}, {"name": "beta"}]
        executor = FakeExecutor(
            {
                "alpha": gpu_result("alpha", "alpha-new"),
                "beta": gpu_result("beta", "beta-new"),
            }
        )
        with self.state_store.lock:
            self.state_store.cached_data = [
                {
                    **gpu_result("alpha", "alpha-old"),
                    "stale": False,
                    "updated_at": 1,
                    "last_error": None,
                }
            ]
            self.state_store.cached_server_identities = {
                server["name"]: state.get_gpu_cache_identity(server)
                for server in servers
            }

        snapshots = []

        def completion_order(_futures):
            yield executor.by_name["beta"]
            with self.state_store.lock:
                snapshots.append(copy.deepcopy(self.state_store.cached_data))
            yield executor.by_name["alpha"]

        with (
            patch.object(collector, "get_configured_servers", return_value=servers),
            patch.object(collector, "gpu_executor", executor),
            patch.object(collector, "as_completed", side_effect=completion_order),
        ):
            collector.refresh_data()

        first_publish = {item["server"]: item for item in snapshots[0]}
        self.assertEqual(first_publish["beta"]["gpus"][0]["name"], "beta-new")
        self.assertEqual(first_publish["alpha"]["gpus"][0]["name"], "alpha-old")

        final = {item["server"]: item for item in self.state_store.cached_data}
        self.assertEqual(final["alpha"]["gpus"][0]["name"], "alpha-new")
        self.assertEqual(final["beta"]["gpus"][0]["name"], "beta-new")

    def test_future_exception_uses_stale_fallback(self):
        servers = [{"name": "alpha"}]
        executor = FakeExecutor(
            {"alpha": FakeFuture(error=TimeoutError("worker timeout"))}
        )
        with self.state_store.lock:
            self.state_store.cached_data = [
                {
                    **gpu_result("alpha", "last-good"),
                    "stale": False,
                    "updated_at": 10,
                    "last_error": None,
                }
            ]
            self.state_store.cached_server_identities = {
                "alpha": state.get_gpu_cache_identity(servers[0])
            }

        with (
            patch.object(collector, "get_configured_servers", return_value=servers),
            patch.object(collector, "gpu_executor", executor),
            patch.object(
                collector,
                "as_completed",
                side_effect=lambda futures: list(futures),
            ),
        ):
            collector.refresh_data()

        result = self.state_store.cached_data[0]
        self.assertEqual(result["gpus"][0]["name"], "last-good")
        self.assertTrue(result["stale"])
        self.assertEqual(result["last_error"], "worker timeout")

    def test_initialization_prunes_removed_servers(self):
        with self.state_store.lock:
            self.state_store.cached_data = [
                gpu_result("keep", "keep"),
                gpu_result("removed", "removed"),
            ]

        with self.state_store.lock:
            self.state_store.cached_server_identities = {
                "keep": (None, None, None),
                "removed": (None, None, None),
            }
        self.state_store.initialize_gpu_cache(
            [{"name": "keep"}, {"name": "new"}]
        )

        self.assertEqual(
            [item["server"] for item in self.state_store.cached_data],
            ["keep", "new"],
        )
        self.assertEqual(
            self.state_store.cached_data[1]["error"], "Waiting for first sample"
        )

    def test_identity_change_discards_another_server_last_success(self):
        old_server = {
            "name": "alpha",
            "host": "old.example",
            "port": 22,
            "username": "gpu",
        }
        new_server = {**old_server, "host": "new.example"}
        with self.state_store.lock:
            self.state_store.cached_data = [
                {
                    **gpu_result("alpha", "old-machine"),
                    "updated_at": 10,
                }
            ]
            self.state_store.cached_server_identities = {
                "alpha": state.get_gpu_cache_identity(old_server)
            }

        self.state_store.initialize_gpu_cache([new_server])

        self.assertEqual(
            self.state_store.cached_data[0]["error"], "Waiting for first sample"
        )
        self.assertNotIn("gpus", self.state_store.cached_data[0])


if __name__ == "__main__":
    unittest.main()
