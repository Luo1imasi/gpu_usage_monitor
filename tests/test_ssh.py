import errno
import threading
import time
import unittest
from unittest.mock import ANY, MagicMock, patch

import paramiko

import gpu_monitor.config as config_module
import gpu_monitor.ssh as ssh


SERVER = {
    "name": "test-server",
    "host": "192.0.2.10",
    "port": 22,
    "username": "tester",
    "key_file": "/tmp/test-key",
    "accept_unknown_host": True,
}


def make_transport(active=True, authenticated=True):
    transport = MagicMock()
    transport.is_active.return_value = active
    transport.is_authenticated.return_value = authenticated
    return transport


def make_client(identity=None):
    client = MagicMock()
    client._invalid = False
    client._ssh_identity = identity
    client._command_lock = threading.RLock()
    client._channel_open_timeout = 45
    client._command_idle_timeout = 45
    client.get_transport.return_value = make_transport()
    return client


def retry_settings(**overrides):
    settings = {
        "connect_timeout": 20.0,
        "banner_timeout": 30.0,
        "auth_timeout": 30.0,
        "connection_total_timeout": 90.0,
        "channel_open_timeout": 45.0,
        "reused_channel_open_timeout": 20.0,
        "command_idle_timeout": 45.0,
        "keepalive_interval": 15,
        "retry_count": 1,
        "retry_backoff_base": 0.0,
        "retry_backoff_max": 0.0,
        "retry_jitter": 0.0,
        "connect_jitter": 0.0,
    }
    settings.update(overrides)
    return settings


class FakeChannel:
    def __init__(self, stdout=b"", stderr=b"", status=0):
        self.stdout = [stdout] if stdout else []
        self.stderr = [stderr] if stderr else []
        self.status = status
        self.eof_received = not self.stdout and not self.stderr
        self.closed = False
        self.timeout = None
        self.command = None
        self.write_shutdown = False

    def recv_ready(self):
        return bool(self.stdout)

    def recv(self, _size):
        data = self.stdout.pop(0)
        self._update_eof()
        return data

    def recv_stderr_ready(self):
        return bool(self.stderr)

    def recv_stderr(self, _size):
        data = self.stderr.pop(0)
        self._update_eof()
        return data

    def _update_eof(self):
        if not self.stdout and not self.stderr:
            self.eof_received = True

    def exit_status_ready(self):
        return self.eof_received

    def recv_exit_status(self):
        return self.status

    def settimeout(self, timeout):
        self.timeout = timeout

    def exec_command(self, command):
        self.command = command

    def shutdown_write(self):
        self.write_shutdown = True

    def close(self):
        self.closed = True


class InfiniteOutputChannel(FakeChannel):
    def __init__(self):
        super().__init__()
        self.eof_received = False

    def recv_ready(self):
        return True

    def recv(self, _size):
        return b"x"

    def exit_status_ready(self):
        return False


class DelayedStatusChannel(FakeChannel):
    def __init__(self, status):
        super().__init__(status=status)
        self.status_checks = 0

    def exit_status_ready(self):
        self.status_checks += 1
        return self.status_checks >= 2


class SSHConnectionTests(unittest.TestCase):
    def setUp(self):
        with ssh.ssh_lock:
            ssh.ssh_clients.clear()
            ssh.ssh_connect_locks.clear()
            ssh.ssh_command_locks.clear()

    def tearDown(self):
        with ssh.ssh_lock:
            clients = list(ssh.ssh_clients.values())
            ssh.ssh_clients.clear()
            ssh.ssh_connect_locks.clear()
            ssh.ssh_command_locks.clear()
        for client in clients:
            ssh.close_ssh_client(client)

    def test_get_ssh_settings_supports_global_and_server_override(self):
        config = {
            "ssh": {
                "connect_timeout_seconds": 25,
                "banner_timeout_seconds": 35,
                "retry_count": 0,
            }
        }
        server = {**SERVER, "ssh": {"connect_timeout_seconds": 40}}
        with patch.object(config_module, "load_config", return_value=config):
            settings = config_module.get_ssh_settings(server)

        self.assertEqual(settings["connect_timeout"], 40.0)
        self.assertEqual(settings["banner_timeout"], 35.0)
        self.assertEqual(settings["retry_count"], 0)
        self.assertEqual(settings["command_idle_timeout"], 60.0)

    def test_cached_authenticated_client_is_reused(self):
        identity = ssh.get_ssh_connection_identity(SERVER)
        client = make_client(identity)
        key = ssh.get_ssh_cache_key(SERVER)
        ssh.ssh_clients[key] = client

        with patch.object(ssh, "create_ssh_client") as create:
            first_client, first_reused = ssh.get_ssh_client(SERVER)
            second_client, second_reused = ssh.get_ssh_client(SERVER)

        self.assertIs(first_client, client)
        self.assertIs(second_client, client)
        self.assertTrue(first_reused)
        self.assertTrue(second_reused)

        create.assert_not_called()

    def test_invalidate_only_removes_expected_client(self):
        key = ssh.get_ssh_cache_key(SERVER)
        old_client = make_client()
        new_client = make_client()
        ssh.ssh_clients[key] = new_client

        self.assertFalse(ssh.invalidate_ssh_client(SERVER, old_client))
        self.assertIs(ssh.ssh_clients[key], new_client)
        old_client.close.assert_called_once()
        new_client.close.assert_not_called()

        self.assertTrue(ssh.invalidate_ssh_client(SERVER, new_client))
        self.assertNotIn(key, ssh.ssh_clients)
        new_client.close.assert_called_once()

    def test_shutdown_fences_new_connections_and_uses_bounded_close(self):
        client = make_client()
        ssh.ssh_clients[ssh.get_ssh_cache_key(SERVER)] = client

        try:
            with patch.object(ssh, "close_ssh_client", return_value=True) as close:
                ssh.shutdown()

            self.assertTrue(ssh.ssh_shutdown_event.is_set())
            with self.assertRaisesRegex(RuntimeError, "shutting down"):
                ssh.get_ssh_client(SERVER)
            close.assert_called_once()
            self.assertIsNotNone(close.call_args.kwargs["cleanup_deadline"])
        finally:
            ssh.ssh_shutdown_event.clear()

    def test_create_client_closes_temporary_client_on_connect_failure(self):
        key = ssh.get_ssh_cache_key(SERVER)
        identity = ("/tmp/test-key", None, True)
        client = MagicMock()
        client.connect.side_effect = TimeoutError("connect timeout")

        with (
            patch.object(ssh.paramiko, "SSHClient", return_value=client),
            patch.object(ssh, "get_ssh_settings", return_value=retry_settings()),
        ):
            with self.assertRaises(TimeoutError):
                ssh.create_ssh_client(SERVER, key, identity)

        client.close.assert_called_once()
        self.assertNotIn(key, ssh.ssh_clients)

    def test_connect_has_an_overall_hard_timeout(self):
        release = threading.Event()
        client = MagicMock()
        client.connect.side_effect = lambda **_kwargs: release.wait()
        client.close.side_effect = release.set

        started = time.monotonic()
        with self.assertRaisesRegex(TimeoutError, "connection total timeout"):
            ssh.connect_ssh_client(
                client,
                {},
                deadline=time.monotonic() + 0.01,
                cleanup_timeout=0.01,
            )

        self.assertLess(time.monotonic() - started, 0.2)
        client.close.assert_called()

    def test_cleanup_wait_is_capped_by_shared_grace_deadline(self):
        with patch.object(ssh.time, "monotonic", return_value=100.75):
            cleanup_deadline = ssh.make_ssh_cleanup_deadline(100.0)
            wait_timeout = ssh.get_ssh_cleanup_wait_timeout(
                cleanup_deadline,
                timeout=1.0,
            )

        self.assertEqual(cleanup_deadline, 101.0)
        self.assertAlmostEqual(wait_timeout, 0.25)

    def test_cleanup_thread_start_failure_is_non_fatal(self):
        with patch.object(
            ssh.threading.Thread,
            "start",
            side_effect=RuntimeError("thread limit"),
        ):
            completed = ssh.run_cleanup_with_timeout(lambda: None, 0.01)

        self.assertFalse(completed)

    def test_create_client_uses_separate_connection_timeouts(self):
        key = ssh.get_ssh_cache_key(SERVER)
        identity = ("/tmp/test-key", None, True)
        client = MagicMock()
        transport = make_transport()
        client.get_transport.return_value = transport
        settings = retry_settings(
            connect_timeout=21.0,
            banner_timeout=31.0,
            auth_timeout=32.0,
            channel_open_timeout=46.0,
            keepalive_interval=14,
        )

        with (
            patch.object(ssh.paramiko, "SSHClient", return_value=client),
            patch.object(ssh, "get_ssh_settings", return_value=settings),
        ):
            created, was_reused = ssh.create_ssh_client(SERVER, key, identity)

        self.assertIs(created, client)
        self.assertFalse(was_reused)
        client.connect.assert_called_once_with(
            hostname=SERVER["host"],
            port=SERVER["port"],
            username=SERVER["username"],
            key_filename=identity[0],
            timeout=21.0,
            banner_timeout=31.0,
            auth_timeout=32.0,
            channel_timeout=46.0,
            look_for_keys=False,
            allow_agent=False,
        )
        transport.set_keepalive.assert_called_once_with(14)

    def test_connect_lock_wait_is_bounded_by_operation_deadline(self):
        connect_lock = MagicMock()
        connect_lock.acquire.return_value = False

        with (
            patch.object(ssh, "get_cached_ssh_client", return_value=None),
            patch.object(ssh, "get_ssh_connect_lock", return_value=connect_lock),
            patch.object(ssh, "create_ssh_client") as create,
            patch.object(ssh.time, "monotonic", return_value=10.0),
        ):
            with self.assertRaisesRegex(
                ssh.SSHOperationDeadlineExceeded, "connect queue deadline exceeded"
            ):
                ssh.get_ssh_client(SERVER, deadline=15.0)

        connect_lock.acquire.assert_called_once_with(timeout=5.0)
        connect_lock.release.assert_not_called()
        create.assert_not_called()

    def test_connection_semaphore_wait_is_bounded_by_operation_deadline(self):
        key = ssh.get_ssh_cache_key(SERVER)
        identity = ("/tmp/test-key", None, True)
        semaphore = MagicMock()
        semaphore.acquire.return_value = False
        client = MagicMock()

        with (
            patch.object(ssh, "ssh_connect_semaphore", semaphore),
            patch.object(ssh.paramiko, "SSHClient", return_value=client),
            patch.object(ssh, "get_ssh_settings", return_value=retry_settings()),
            patch.object(ssh.time, "monotonic", return_value=10.0),
        ):
            with self.assertRaisesRegex(
                ssh.SSHOperationDeadlineExceeded,
                "connection semaphore deadline exceeded",
            ):
                ssh.create_ssh_client(
                    SERVER,
                    key,
                    identity,
                    deadline=15.0,
                )

        semaphore.acquire.assert_called_once_with(timeout=5.0)
        semaphore.release.assert_not_called()
        client.connect.assert_not_called()


class SSHCommandTests(unittest.TestCase):
    def setUp(self):
        with ssh.ssh_lock:
            ssh.ssh_clients.clear()
            ssh.ssh_connect_locks.clear()
            ssh.ssh_command_locks.clear()

    def test_command_runner_drains_both_streams_and_uses_split_timeouts(self):
        channel = FakeChannel(stdout=b"out", stderr=b"err", status=7)
        transport = make_transport()
        transport.open_session.return_value = channel
        client = make_client()
        client.get_transport.return_value = transport

        result = ssh.run_ssh_command_status(
            client,
            "test-command",
            timeout=12,
            channel_open_timeout=8,
            total_timeout=20,
        )

        self.assertEqual(result, (7, "out", "err"))
        transport.open_session.assert_called_once_with(timeout=8)
        self.assertEqual(channel.timeout, 12)
        self.assertEqual(channel.command, "test-command")
        self.assertFalse(channel.write_shutdown)
        self.assertTrue(channel.closed)

    def test_channel_total_timeout_has_a_message(self):
        channel = FakeChannel()
        channel.eof_received = False
        channel.exit_status_ready = lambda: False

        with (
            patch.object(ssh.time, "monotonic", side_effect=[0.0, 0.0, 2.0]),
            patch.object(ssh.time, "sleep"),
        ):
            with self.assertRaisesRegex(TimeoutError, "total timeout after 1s"):
                ssh.read_ssh_channel(channel, idle_timeout=10, total_timeout=1)

    def test_exec_request_has_a_hard_timeout(self):
        release = threading.Event()
        channel = MagicMock()
        channel.exec_command.side_effect = lambda _command: release.wait()
        channel.close.side_effect = release.set

        with self.assertRaisesRegex(TimeoutError, "exec request timeout"):
            ssh.execute_ssh_channel_command(channel, "blocked", timeout=0.01)

        channel.close.assert_called_once()

    def test_exec_timeout_is_not_blocked_by_hung_channel_close(self):
        exec_release = threading.Event()
        close_release = threading.Event()
        channel = MagicMock()
        transport = MagicMock()
        channel.exec_command.side_effect = lambda _command: exec_release.wait()
        channel.close.side_effect = lambda: close_release.wait()
        transport.close.side_effect = exec_release.set

        started = time.monotonic()
        try:
            with self.assertRaisesRegex(TimeoutError, "exec request timeout"):
                ssh.execute_ssh_channel_command(
                    channel,
                    "blocked",
                    timeout=0.01,
                    transport=transport,
                    cleanup_timeout=0.01,
                )
        finally:
            close_release.set()

        self.assertLess(time.monotonic() - started, 0.2)
        transport.close.assert_called_once()

    def test_open_session_send_hang_has_a_hard_timeout(self):
        release = threading.Event()
        transport = MagicMock()
        transport.open_session.side_effect = lambda timeout: release.wait()
        transport.close.side_effect = release.set

        started = time.monotonic()
        with self.assertRaisesRegex(TimeoutError, "channel open timeout"):
            ssh.open_ssh_session(
                transport,
                timeout=0.01,
                cleanup_timeout=0.01,
            )

        self.assertLess(time.monotonic() - started, 0.2)
        transport.close.assert_called_once()

    def test_continuous_output_cannot_bypass_total_timeout(self):
        channel = InfiniteOutputChannel()
        clock = iter(i / 10 for i in range(100))

        with (
            patch.object(ssh.time, "monotonic", side_effect=lambda: next(clock)),
            patch.object(ssh.time, "sleep"),
        ):
            with self.assertRaisesRegex(TimeoutError, "total timeout after 0.5s"):
                ssh.read_ssh_channel(
                    channel,
                    idle_timeout=10,
                    total_timeout=0.5,
                )

    def test_eof_waits_for_delayed_exit_status(self):
        channel = DelayedStatusChannel(status=3)

        with patch.object(ssh.time, "sleep"):
            status, out, err = ssh.read_ssh_channel(
                channel,
                idle_timeout=1,
                total_timeout=2,
            )

        self.assertEqual((status, out, err), (3, "", ""))
        self.assertGreaterEqual(channel.status_checks, 2)

    def test_reused_client_uses_20_second_channel_open_timeout(self):
        client = make_client()

        with (
            patch.object(ssh, "get_ssh_settings", return_value=retry_settings()),
            patch.object(ssh, "get_ssh_client", return_value=(client, True)),
            patch.object(
                ssh, "run_ssh_command_status", return_value=(0, "ok", "")
            ) as run_command,
            patch.object(ssh.time, "monotonic", return_value=100.0),
        ):
            result = ssh.run_server_ssh_command_status(
                SERVER,
                "read-only",
                operation_timeout=150,
                retry_on_transport=True,
            )

        self.assertEqual(result, (0, "ok", ""))
        self.assertEqual(run_command.call_args.kwargs["channel_open_timeout"], 20.0)
        self.assertEqual(run_command.call_args.kwargs["deadline"], 250.0)

    def test_fresh_client_uses_60_second_channel_open_timeout(self):
        client = make_client()
        settings = retry_settings(channel_open_timeout=60.0)

        with (
            patch.object(ssh, "get_ssh_settings", return_value=settings),
            patch.object(ssh, "get_ssh_client", return_value=(client, False)),
            patch.object(
                ssh, "run_ssh_command_status", return_value=(0, "ok", "")
            ) as run_command,
            patch.object(ssh.time, "monotonic", return_value=100.0),
        ):
            result = ssh.run_server_ssh_command_status(
                SERVER,
                "read-only",
                operation_timeout=150,
                retry_on_transport=True,
            )

        self.assertEqual(result, (0, "ok", ""))
        self.assertEqual(run_command.call_args.kwargs["channel_open_timeout"], 60.0)
        self.assertEqual(run_command.call_args.kwargs["deadline"], 250.0)

    def test_command_namespace_uses_an_isolated_client_and_lock(self):
        client = make_client()
        with (
            patch.object(ssh, "get_ssh_settings", return_value=retry_settings()),
            patch.object(
                ssh,
                "get_ssh_client",
                return_value=(client, False),
            ) as get_client,
            patch.object(
                ssh,
                "run_ssh_command_status",
                return_value=(0, "ok", ""),
            ),
            patch.object(ssh.time, "monotonic", return_value=100.0),
        ):
            result = ssh.run_server_ssh_command_status(
                SERVER,
                "read-only",
                operation_timeout=150,
                retry_on_transport=True,
                namespace="storage",
            )

        self.assertEqual(result, (0, "ok", ""))
        get_client.assert_called_once_with(
            SERVER,
            deadline=250.0,
            namespace="storage",
        )
        self.assertIn(
            ssh.get_ssh_cache_key(SERVER, namespace="storage"),
            ssh.ssh_command_locks,
        )

    def test_retry_switches_reused_open_timeout_from_20_to_fresh_60(self):
        first_client = make_client()
        second_client = make_client()
        settings = retry_settings(channel_open_timeout=60.0)
        open_failure = ssh.SSHCommandFailure(
            TimeoutError("channel open failed"),
            ssh.SSH_STAGE_PRE_DISPATCH,
        )

        with (
            patch.object(ssh, "get_ssh_settings", return_value=settings),
            patch.object(
                ssh,
                "get_ssh_client",
                side_effect=[(first_client, True), (second_client, False)],
            ),
            patch.object(
                ssh,
                "run_ssh_command_status",
                side_effect=[open_failure, (0, "ok", "")],
            ) as run_command,
            patch.object(ssh, "invalidate_ssh_client"),
            patch.object(ssh.time, "monotonic", return_value=100.0),
        ):
            result = ssh.run_server_ssh_command_status(
                SERVER,
                "write-operation",
                operation_timeout=150,
                retry_on_transport=False,
            )

        self.assertEqual(result, (0, "ok", ""))
        self.assertEqual(
            [call.kwargs["channel_open_timeout"] for call in run_command.call_args_list],
            [20.0, 60.0],
        )

    def test_operation_deadline_bounds_command_queue_wait(self):
        command_lock = MagicMock()
        command_lock.acquire.return_value = False

        with (
            patch.object(ssh, "get_ssh_command_lock", return_value=command_lock),
            patch.object(ssh, "get_ssh_settings", return_value=retry_settings()),
            patch.object(ssh, "get_ssh_client") as get_client,
            patch.object(ssh.time, "monotonic", return_value=10.0),
        ):
            with self.assertRaisesRegex(
                ssh.SSHOperationDeadlineExceeded,
                "command queue deadline exceeded",
            ):
                ssh.run_server_ssh_command_status(
                    SERVER,
                    "read-only",
                    operation_timeout=5,
                    retry_on_transport=True,
                )

        command_lock.acquire.assert_called_once_with(timeout=5.0)
        command_lock.release.assert_not_called()
        get_client.assert_not_called()

    def test_retry_backoff_cannot_exceed_operation_deadline(self):
        client = make_client()
        settings = retry_settings(
            retry_backoff_base=2.0,
            retry_backoff_max=2.0,
            retry_jitter=0.0,
        )
        open_failure = ssh.SSHCommandFailure(
            TimeoutError("channel open failed"),
            ssh.SSH_STAGE_PRE_DISPATCH,
        )

        with (
            patch.object(ssh, "get_ssh_settings", return_value=settings),
            patch.object(
                ssh, "get_ssh_client", return_value=(client, True)
            ) as get_client,
            patch.object(
                ssh, "run_ssh_command_status", side_effect=open_failure
            ) as run_command,
            patch.object(ssh, "invalidate_ssh_client"),
            patch.object(ssh.time, "monotonic", return_value=100.0),
            patch.object(ssh.time, "sleep") as sleep,
        ):
            with self.assertRaisesRegex(
                ssh.SSHOperationDeadlineExceeded,
                "retry backoff deadline exceeded",
            ):
                ssh.run_server_ssh_command_status(
                    SERVER,
                    "read-only",
                    operation_timeout=1,
                    retry_on_transport=True,
                )

        get_client.assert_called_once_with(SERVER, deadline=101.0)
        run_command.assert_called_once()
        sleep.assert_not_called()

    def test_no_valid_connections_error_retries_before_dispatch(self):
        client = make_client()
        error = paramiko.ssh_exception.NoValidConnectionsError(
            {
                (SERVER["host"], SERVER["port"]): ConnectionRefusedError(
                    errno.ECONNREFUSED,
                    "connection refused",
                )
            }
        )

        self.assertTrue(ssh.is_retryable_ssh_transport_error(error))

        with (
            patch.object(ssh, "get_ssh_settings", return_value=retry_settings()),
            patch.object(
                ssh,
                "get_ssh_client",
                side_effect=[error, (client, False)],
            ) as get_client,
            patch.object(
                ssh, "run_ssh_command_status", return_value=(0, "ok", "")
            ) as run_command,
        ):
            result = ssh.run_server_ssh_command_status(
                SERVER,
                "write-operation",
                retry_on_transport=False,
            )

        self.assertEqual(result, (0, "ok", ""))
        self.assertEqual(get_client.call_count, 2)
        run_command.assert_called_once()

    def test_write_command_retries_channel_open_failure_before_dispatch(self):
        first_client = make_client()
        second_client = make_client()
        channel = FakeChannel(status=0)

        with (
            patch.object(ssh, "get_ssh_settings", return_value=retry_settings()),
            patch.object(
                ssh,
                "get_ssh_client",
                side_effect=[(first_client, True), (second_client, False)],
            ) as get_client,
            patch.object(
                ssh,
                "open_ssh_session",
                side_effect=[TimeoutError("open failed"), channel],
            ) as open_session,
            patch.object(ssh, "invalidate_ssh_client"),
        ):
            result = ssh.run_server_ssh_command_status(
                SERVER,
                "write-operation",
                retry_on_transport=False,
            )

        self.assertEqual(result, (0, "", ""))
        self.assertEqual(get_client.call_count, 2)
        self.assertEqual(open_session.call_count, 2)

    def test_write_command_exec_failure_is_not_replayed(self):
        client = make_client()
        channel = FakeChannel(status=0)

        def fail_exec(_command):
            raise TimeoutError("exec failed")

        channel.exec_command = fail_exec
        with (
            patch.object(ssh, "get_ssh_settings", return_value=retry_settings()),
            patch.object(
                ssh, "get_ssh_client", return_value=(client, True)
            ) as get_client,
            patch.object(ssh, "open_ssh_session", return_value=channel),
            patch.object(ssh, "invalidate_ssh_client"),
        ):
            with self.assertRaisesRegex(
                ssh.SSHCommandOutcomeUnknown, "remote command outcome is unknown"
            ):
                ssh.run_server_ssh_command_status(
                    SERVER,
                    "write-operation",
                    retry_on_transport=False,
                )

        self.assertEqual(get_client.call_count, 1)

    def test_write_command_read_failure_is_not_replayed(self):
        client = make_client()
        channel = FakeChannel(status=0)

        with (
            patch.object(ssh, "get_ssh_settings", return_value=retry_settings()),
            patch.object(
                ssh, "get_ssh_client", return_value=(client, True)
            ) as get_client,
            patch.object(ssh, "open_ssh_session", return_value=channel),
            patch.object(
                ssh, "read_ssh_channel", side_effect=TimeoutError("read failed")
            ),
            patch.object(ssh, "invalidate_ssh_client"),
        ):
            with self.assertRaisesRegex(
                ssh.SSHCommandOutcomeUnknown, "remote command outcome is unknown"
            ):
                ssh.run_server_ssh_command_status(
                    SERVER,
                    "write-operation",
                    retry_on_transport=False,
                )

        self.assertEqual(get_client.call_count, 1)

    def test_readonly_transport_failure_reconnects_once(self):
        first_client = make_client()
        second_client = make_client()
        settings = retry_settings()
        dispatched_failure = ssh.SSHCommandFailure(
            TimeoutError(), ssh.SSH_STAGE_DISPATCHED
        )

        with (
            patch.object(ssh, "get_ssh_settings", return_value=settings),
            patch.object(
                ssh,
                "get_ssh_client",
                side_effect=[(first_client, True), (second_client, False)],
            ) as get_client,
            patch.object(
                ssh,
                "run_ssh_command_status",
                side_effect=[dispatched_failure, (0, "ok", "")],
            ) as run_command,
            patch.object(ssh, "invalidate_ssh_client") as invalidate,
            patch.object(ssh.time, "sleep"),
        ):
            result = ssh.run_server_ssh_command_status(
                SERVER,
                "read-only",
                retry_on_transport=True,
                operation_name="test read",
            )

        self.assertEqual(result, (0, "ok", ""))
        self.assertEqual(get_client.call_count, 2)
        self.assertEqual(run_command.call_count, 2)
        invalidate.assert_called_once_with(
            SERVER,
            expected_client=first_client,
            cleanup_deadline=ANY,
        )

    def test_write_command_is_not_replayed_after_transport_failure(self):
        client = make_client()
        dispatched_failure = ssh.SSHCommandFailure(
            TimeoutError(), ssh.SSH_STAGE_DISPATCHED
        )

        with (
            patch.object(ssh, "get_ssh_settings", return_value=retry_settings()),
            patch.object(
                ssh, "get_ssh_client", return_value=(client, True)
            ) as get_client,
            patch.object(
                ssh, "run_ssh_command_status", side_effect=dispatched_failure
            ) as run_command,
            patch.object(ssh, "invalidate_ssh_client") as invalidate,
        ):
            with self.assertRaisesRegex(
                ssh.SSHCommandOutcomeUnknown, "remote command outcome is unknown"
            ):
                ssh.run_server_ssh_command_status(
                    SERVER,
                    "write-operation",
                    retry_on_transport=False,
                    operation_name="test write",
                )

        get_client.assert_called_once_with(SERVER, deadline=ANY)
        run_command.assert_called_once()
        invalidate.assert_called_once_with(
            SERVER,
            expected_client=client,
            cleanup_deadline=ANY,
        )

    def test_unwrapped_command_runner_failure_is_conservatively_not_replayed(self):
        client = make_client()

        with (
            patch.object(ssh, "get_ssh_settings", return_value=retry_settings()),
            patch.object(ssh, "get_ssh_client", return_value=(client, True)),
            patch.object(
                ssh,
                "run_ssh_command_status",
                side_effect=TimeoutError("unexpected runner failure"),
            ) as run_command,
            patch.object(ssh, "invalidate_ssh_client"),
        ):
            with self.assertRaisesRegex(
                ssh.SSHCommandOutcomeUnknown,
                "remote command outcome is unknown",
            ):
                ssh.run_server_ssh_command_status(
                    SERVER,
                    "write-operation",
                    retry_on_transport=False,
                )

        run_command.assert_called_once()

    def test_write_command_can_retry_connect_before_dispatch(self):
        client = make_client()

        with (
            patch.object(ssh, "get_ssh_settings", return_value=retry_settings()),
            patch.object(
                ssh,
                "get_ssh_client",
                side_effect=[TimeoutError(), (client, False)],
            ) as get_client,
            patch.object(
                ssh, "run_ssh_command_status", return_value=(0, "ok", "")
            ) as run_command,
            patch.object(ssh.time, "sleep"),
        ):
            result = ssh.run_server_ssh_command_status(
                SERVER,
                "write-operation",
                retry_on_transport=False,
                operation_name="test write",
            )

        self.assertEqual(result, (0, "ok", ""))
        self.assertEqual(get_client.call_count, 2)
        run_command.assert_called_once()

    def test_authentication_error_is_not_retried(self):
        with (
            patch.object(ssh, "get_ssh_settings", return_value=retry_settings()),
            patch.object(
                ssh,
                "get_ssh_client",
                side_effect=paramiko.AuthenticationException("denied"),
            ) as get_client,
            patch.object(ssh.time, "sleep") as sleep,
        ):
            with self.assertRaises(paramiko.AuthenticationException):
                ssh.run_server_ssh_command_status(
                    SERVER,
                    "read-only",
                    retry_on_transport=True,
                )

        get_client.assert_called_once_with(SERVER, deadline=ANY)
        sleep.assert_not_called()


if __name__ == "__main__":
    unittest.main()
