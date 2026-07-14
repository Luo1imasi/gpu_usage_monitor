import unittest
from unittest.mock import MagicMock, patch

from gpu_monitor.runtime import Runtime


class RuntimeTests(unittest.TestCase):
    def test_start_delegates_to_collector_runtime(self):
        worker = MagicMock()
        worker.is_alive.return_value = True
        runtime = Runtime()

        with patch(
            "gpu_monitor.runtime.gpu_collector.start_background_worker",
            return_value=worker,
        ) as start, patch(
            "gpu_monitor.runtime.storage.start_background_worker",
        ) as start_storage:
            self.assertIs(runtime.start(), worker)
            self.assertIs(runtime.start(), worker)

        self.assertEqual(start.call_count, 2)
        self.assertEqual(start_storage.call_count, 2)

    def test_storage_start_failure_stops_gpu_worker(self):
        runtime = Runtime()
        with (
            patch(
                "gpu_monitor.runtime.gpu_collector.start_background_worker"
            ),
            patch(
                "gpu_monitor.runtime.storage.start_background_worker",
                side_effect=RuntimeError("storage failed"),
            ),
            patch("gpu_monitor.runtime.gpu_collector.shutdown") as gpu_shutdown,
        ):
            with self.assertRaisesRegex(RuntimeError, "storage failed"):
                runtime.start()

        gpu_shutdown.assert_called_once_with(timeout=0)

    def test_close_releases_each_resource_once(self):
        runtime = Runtime()
        with (
            patch("gpu_monitor.runtime.ssh.begin_shutdown") as begin_ssh_shutdown,
            patch("gpu_monitor.runtime.gpu_collector.shutdown") as gpu_shutdown,
            patch(
                "gpu_monitor.runtime.gpu_collector.wait_for_shutdown"
            ) as gpu_wait,
            patch("gpu_monitor.runtime.storage.shutdown") as storage_shutdown,
            patch(
                "gpu_monitor.runtime.storage.wait_for_shutdown"
            ) as storage_wait,
            patch("gpu_monitor.runtime.access_service.shutdown") as access_shutdown,
            patch(
                "gpu_monitor.runtime.access_service.wait_for_shutdown"
            ) as access_wait,
            patch("gpu_monitor.runtime.ssh.shutdown") as ssh_shutdown,
        ):
            runtime.close()
            runtime.close()

        begin_ssh_shutdown.assert_called_once_with()
        gpu_shutdown.assert_called_once_with(timeout=0)
        gpu_wait.assert_called_once_with(timeout=1)
        storage_shutdown.assert_called_once_with(timeout=0)
        storage_wait.assert_called_once_with(timeout=1)
        access_shutdown.assert_called_once_with()
        access_wait.assert_called_once_with(timeout=1)
        ssh_shutdown.assert_called_once_with()

    def test_closed_runtime_cannot_restart(self):
        runtime = Runtime()
        with (
            patch("gpu_monitor.runtime.ssh.begin_shutdown"),
            patch("gpu_monitor.runtime.gpu_collector.shutdown"),
            patch("gpu_monitor.runtime.gpu_collector.wait_for_shutdown"),
            patch("gpu_monitor.runtime.storage.shutdown"),
            patch("gpu_monitor.runtime.storage.wait_for_shutdown"),
            patch("gpu_monitor.runtime.access_service.shutdown"),
            patch("gpu_monitor.runtime.access_service.wait_for_shutdown"),
            patch("gpu_monitor.runtime.ssh.shutdown"),
        ):
            runtime.close()

        with self.assertRaisesRegex(RuntimeError, "already been closed"):
            runtime.start()


if __name__ == "__main__":
    unittest.main()
