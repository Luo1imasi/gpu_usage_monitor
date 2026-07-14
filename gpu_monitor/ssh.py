import errno
import logging
import os
import random
import re
import socket
import threading
import time
from pathlib import Path

import paramiko

from .config import (
    SSH_CHANNEL_OPEN_TIMEOUT,
    SSH_COMMAND_TIMEOUT,
    SSH_OPERATION_TIMEOUT,
    get_file_signature,
    get_ssh_settings,
)


logger = logging.getLogger(__name__)

SSH_CONNECT_MAX_CONCURRENCY = 8
SSH_CLEANUP_TIMEOUT_SECONDS = 1
SSH_CLEANUP_GRACE_SECONDS = 1

ssh_clients = {}
ssh_connect_locks = {}
ssh_command_locks = {}
ssh_lock = threading.Lock()
ssh_connect_semaphore = threading.BoundedSemaphore(SSH_CONNECT_MAX_CONCURRENCY)
ssh_shutdown_event = threading.Event()


def begin_shutdown():
    """Fence new SSH work before cached transports are closed."""
    ssh_shutdown_event.set()


def ensure_ssh_runtime_open():
    if ssh_shutdown_event.is_set():
        raise RuntimeError("SSH runtime is shutting down")


class SSHCommandOutcomeUnknown(RuntimeError):
    pass


class SSHOperationDeadlineExceeded(TimeoutError):
    pass


SSH_STAGE_PRE_DISPATCH = "pre_dispatch"
SSH_STAGE_DISPATCHED = "dispatched"


class SSHCommandFailure(RuntimeError):
    def __init__(self, cause, stage):
        self.cause = cause
        self.stage = stage
        self.transport_error = is_retryable_ssh_transport_error(cause)
        super().__init__(str(cause) or cause.__class__.__name__)


def make_ssh_deadline(timeout):
    if timeout is None:
        return None
    return time.monotonic() + timeout


def make_ssh_cleanup_deadline(deadline):
    if deadline is None:
        return None
    return deadline + SSH_CLEANUP_GRACE_SECONDS


def get_ssh_cleanup_wait_timeout(cleanup_deadline, timeout):
    if cleanup_deadline is None:
        return timeout
    return max(0.0, min(timeout, cleanup_deadline - time.monotonic()))


def get_ssh_deadline_remaining(deadline, label="SSH operation"):
    if deadline is None:
        return None
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise SSHOperationDeadlineExceeded(f"{label} deadline exceeded")
    return remaining


def cap_ssh_timeout(timeout, deadline, label):
    remaining = get_ssh_deadline_remaining(deadline, label)
    if remaining is None:
        return timeout
    return min(timeout, remaining)


def acquire_until_deadline(lock, deadline, label):
    remaining = get_ssh_deadline_remaining(deadline, label)
    if remaining is None:
        lock.acquire()
        return
    if not lock.acquire(timeout=remaining):
        raise SSHOperationDeadlineExceeded(f"{label} deadline exceeded")


def sleep_until_deadline(delay, deadline, label):
    if delay <= 0:
        return
    remaining = get_ssh_deadline_remaining(deadline, label)
    if remaining is not None and delay >= remaining:
        raise SSHOperationDeadlineExceeded(f"{label} deadline exceeded")
    time.sleep(delay)


def get_ssh_cache_key(server, namespace=None):
    key = (server["host"], server["port"], server["username"])
    if namespace is None:
        return key
    return (*key, namespace)


def get_ssh_connection_identity(server):
    key_file = Path(os.path.expanduser(server["key_file"])).resolve()
    return (
        str(key_file),
        get_file_signature(key_file),
        bool(server.get("accept_unknown_host", False)),
    )


def get_ssh_connect_lock(key):
    with ssh_lock:
        if key not in ssh_connect_locks:
            ssh_connect_locks[key] = threading.Lock()
        return ssh_connect_locks[key]


def get_ssh_command_lock(key):
    with ssh_lock:
        if key not in ssh_command_locks:
            ssh_command_locks[key] = threading.RLock()
        return ssh_command_locks[key]


def close_ssh_client(client, cleanup_deadline=None):
    if client is None:
        return True
    client._invalid = True
    close_timeout = get_ssh_cleanup_wait_timeout(
        cleanup_deadline,
        SSH_CLEANUP_TIMEOUT_SECONDS,
    )
    if run_cleanup_with_timeout(client.close, close_timeout):
        return True

    try:
        transport = client.get_transport()
    except Exception:
        transport = None
    if transport is not None:
        transport_timeout = get_ssh_cleanup_wait_timeout(
            cleanup_deadline,
            SSH_CLEANUP_TIMEOUT_SECONDS,
        )
        run_cleanup_with_timeout(transport.close, transport_timeout)
    logger.warning("Timed out while closing an SSH client; transport was abandoned")
    return False


def is_ssh_client_usable(client, identity=None):
    if client is None or getattr(client, "_invalid", False):
        return False
    if identity is not None and getattr(client, "_ssh_identity", None) != identity:
        return False
    try:
        transport = client.get_transport()
        return bool(
            transport
            and transport.is_active()
            and transport.is_authenticated()
        )
    except Exception:
        return False


def get_cached_ssh_client(key, identity, cleanup_deadline=None):
    stale_client = None
    with ssh_lock:
        client = ssh_clients.get(key)
        if is_ssh_client_usable(client, identity):
            return client
        if client is not None:
            stale_client = ssh_clients.pop(key)

    close_ssh_client(stale_client, cleanup_deadline=cleanup_deadline)
    return None


def get_ssh_client(server, deadline=None, namespace=None):
    ensure_ssh_runtime_open()
    key = get_ssh_cache_key(server, namespace=namespace)
    identity = get_ssh_connection_identity(server)
    cleanup_deadline = make_ssh_cleanup_deadline(deadline)
    client = get_cached_ssh_client(
        key,
        identity,
        cleanup_deadline=cleanup_deadline,
    )
    if client is not None:
        return client, True

    connect_lock = get_ssh_connect_lock(key)
    acquire_until_deadline(connect_lock, deadline, "SSH connect queue")
    try:
        ensure_ssh_runtime_open()
        client = get_cached_ssh_client(
            key,
            identity,
            cleanup_deadline=cleanup_deadline,
        )
        if client is not None:
            return client, True
        return create_ssh_client(
            server,
            key,
            identity,
            deadline=deadline,
            cleanup_deadline=cleanup_deadline,
        )
    finally:
        connect_lock.release()


def connect_ssh_client(
    client,
    connect_kwargs,
    deadline,
    cleanup_deadline=None,
    cleanup_timeout=SSH_CLEANUP_TIMEOUT_SECONDS,
):
    if cleanup_deadline is None:
        cleanup_deadline = make_ssh_cleanup_deadline(deadline)
    completed = threading.Event()
    abandoned = threading.Event()
    errors = []

    def connect():
        try:
            client.connect(**connect_kwargs)
            if abandoned.is_set():
                close_ssh_client(
                    client,
                    cleanup_deadline=cleanup_deadline,
                )
        except Exception as e:
            errors.append(e)
        finally:
            completed.set()

    thread = threading.Thread(
        target=connect,
        name="ssh-connect",
        daemon=True,
    )
    thread.start()

    remaining = get_ssh_deadline_remaining(deadline, "SSH connection")
    if not completed.wait(remaining):
        abandoned.set()
        close_ssh_client(client, cleanup_deadline=cleanup_deadline)
        completed.wait(
            get_ssh_cleanup_wait_timeout(cleanup_deadline, cleanup_timeout)
        )
        raise TimeoutError("SSH connection total timeout")
    if errors:
        raise errors[0]


def create_ssh_client(
    server,
    key,
    identity=None,
    deadline=None,
    cleanup_deadline=None,
):
    ensure_ssh_runtime_open()
    identity = identity or get_ssh_connection_identity(server)
    if cleanup_deadline is None:
        cleanup_deadline = make_ssh_cleanup_deadline(deadline)
    settings = get_ssh_settings(server)
    new_client = paramiko.SSHClient()
    started = time.monotonic()
    semaphore_acquired = False

    try:
        new_client.load_system_host_keys()
        if server.get("accept_unknown_host", False):
            new_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_jitter = settings["connect_jitter"]
        if connect_jitter > 0:
            sleep_until_deadline(
                random.uniform(0, connect_jitter),
                deadline,
                "SSH connect jitter",
            )

        acquire_until_deadline(
            ssh_connect_semaphore,
            deadline,
            "SSH connection semaphore",
        )
        semaphore_acquired = True
        try:
            connection_deadline = time.monotonic() + settings[
                "connection_total_timeout"
            ]
            if deadline is not None:
                connection_deadline = min(connection_deadline, deadline)

            connect_ssh_client(
                new_client,
                {
                    "hostname": server["host"],
                    "port": server["port"],
                    "username": server["username"],
                    "key_filename": identity[0],
                    "timeout": cap_ssh_timeout(
                        settings["connect_timeout"],
                        connection_deadline,
                        "SSH TCP connect",
                    ),
                    "banner_timeout": cap_ssh_timeout(
                        settings["banner_timeout"],
                        connection_deadline,
                        "SSH banner",
                    ),
                    "auth_timeout": cap_ssh_timeout(
                        settings["auth_timeout"],
                        connection_deadline,
                        "SSH authentication",
                    ),
                    "channel_timeout": cap_ssh_timeout(
                        settings["channel_open_timeout"],
                        connection_deadline,
                        "SSH channel default",
                    ),
                    "look_for_keys": False,
                    "allow_agent": False,
                },
                deadline=connection_deadline,
                cleanup_deadline=cleanup_deadline,
            )
        finally:
            ssh_connect_semaphore.release()
            semaphore_acquired = False

        transport = new_client.get_transport()
        if not transport or not transport.is_active() or not transport.is_authenticated():
            raise paramiko.SSHException("SSH transport is not authenticated")
        transport.set_keepalive(settings["keepalive_interval"])

        new_client._command_lock = threading.RLock()
        new_client._invalid = False
        new_client._ssh_identity = identity
        new_client._channel_open_timeout = settings["channel_open_timeout"]
        new_client._command_idle_timeout = settings["command_idle_timeout"]
    except Exception:
        if semaphore_acquired:
            ssh_connect_semaphore.release()
        close_ssh_client(new_client, cleanup_deadline=cleanup_deadline)
        raise

    old_client = None
    existing_client = None
    shutting_down = False
    with ssh_lock:
        if ssh_shutdown_event.is_set():
            shutting_down = True
        else:
            existing = ssh_clients.get(key)
            if is_ssh_client_usable(existing, identity):
                existing_client = existing
            else:
                if existing is not None:
                    old_client = ssh_clients.pop(key)
                ssh_clients[key] = new_client

    if shutting_down:
        close_ssh_client(new_client, cleanup_deadline=cleanup_deadline)
        raise RuntimeError("SSH runtime is shutting down")

    if existing_client is not None:
        close_ssh_client(new_client, cleanup_deadline=cleanup_deadline)
        return existing_client, True
    close_ssh_client(old_client, cleanup_deadline=cleanup_deadline)
    logger.info(
        "SSH connected to %s in %.2fs",
        server["name"],
        time.monotonic() - started,
    )
    return new_client, False


def invalidate_ssh_client(
    server,
    expected_client,
    cleanup_deadline=None,
    namespace=None,
):
    key = get_ssh_cache_key(server, namespace=namespace)
    removed = False
    client_to_close = expected_client

    with ssh_lock:
        cached_client = ssh_clients.get(key)
        if cached_client is expected_client:
            client_to_close = ssh_clients.pop(key)
            removed = True

    close_ssh_client(client_to_close, cleanup_deadline=cleanup_deadline)
    return removed


def is_retryable_ssh_transport_error(error):
    if isinstance(error, SSHOperationDeadlineExceeded):
        return False
    if isinstance(error, paramiko.ssh_exception.NoValidConnectionsError):
        return True
    permanent_errors = (
        paramiko.AuthenticationException,
        paramiko.BadHostKeyException,
        paramiko.PasswordRequiredException,
        FileNotFoundError,
        PermissionError,
    )
    if isinstance(error, permanent_errors):
        return False
    if error.__class__.__name__ == "IncompatiblePeer":
        return False
    if isinstance(error, paramiko.ChannelException):
        return False
    if isinstance(error, (TimeoutError, socket.timeout, EOFError, ConnectionError)):
        return True
    if isinstance(error, OSError):
        return error.errno in {
            errno.ECONNABORTED,
            errno.ECONNRESET,
            errno.EHOSTUNREACH,
            errno.ENETDOWN,
            errno.ENETUNREACH,
            errno.EPIPE,
            errno.ETIMEDOUT,
        }
    return isinstance(error, paramiko.SSHException)


def ensure_ssh_client_active(client):
    if getattr(client, "_invalid", False):
        raise paramiko.SSHException("SSH client was invalidated")
    transport = client.get_transport()
    if not transport or not transport.is_active() or not transport.is_authenticated():
        client._invalid = True
        raise paramiko.SSHException("SSH session is not active")
    return transport


def run_cleanup_with_timeout(callback, timeout):
    completed = threading.Event()

    def cleanup_target():
        try:
            callback()
        except Exception:
            pass
        finally:
            completed.set()

    thread = threading.Thread(
        target=cleanup_target,
        name="ssh-cleanup",
        daemon=True,
    )
    try:
        thread.start()
    except Exception as e:
        logger.warning("Unable to start SSH cleanup thread: %s", e)
        return False
    return completed.wait(max(0.0, timeout))


def close_ssh_channel(
    channel,
    transport=None,
    timeout=SSH_CLEANUP_TIMEOUT_SECONDS,
    cleanup_deadline=None,
):
    if channel is None:
        return True
    close_timeout = get_ssh_cleanup_wait_timeout(cleanup_deadline, timeout)
    if run_cleanup_with_timeout(channel.close, close_timeout):
        return True
    if transport is not None:
        transport_timeout = get_ssh_cleanup_wait_timeout(
            cleanup_deadline,
            timeout,
        )
        run_cleanup_with_timeout(transport.close, transport_timeout)
    return False


def open_ssh_session(
    transport,
    timeout,
    deadline=None,
    cleanup_deadline=None,
    cleanup_timeout=SSH_CLEANUP_TIMEOUT_SECONDS,
):
    if cleanup_deadline is None:
        cleanup_deadline = make_ssh_cleanup_deadline(deadline)
    wait_timeout = cap_ssh_timeout(timeout, deadline, "SSH channel open")
    completed = threading.Event()
    abandoned = threading.Event()
    results = []
    errors = []

    def open_session():
        try:
            channel = transport.open_session(timeout=wait_timeout)
            if abandoned.is_set():
                close_ssh_channel(
                    channel,
                    transport,
                    cleanup_timeout,
                    cleanup_deadline=cleanup_deadline,
                )
            else:
                results.append(channel)
        except Exception as e:
            errors.append(e)
        finally:
            completed.set()

    thread = threading.Thread(
        target=open_session,
        name="ssh-open-session",
        daemon=True,
    )
    thread.start()

    if not completed.wait(wait_timeout):
        abandoned.set()
        run_cleanup_with_timeout(
            transport.close,
            get_ssh_cleanup_wait_timeout(cleanup_deadline, cleanup_timeout),
        )
        completed.wait(
            get_ssh_cleanup_wait_timeout(cleanup_deadline, cleanup_timeout)
        )
        raise TimeoutError(f"SSH channel open timeout after {wait_timeout:g}s")
    if errors:
        raise errors[0]
    if not results:
        raise paramiko.SSHException("SSH channel open returned no channel")
    return results[0]


def execute_ssh_channel_command(
    channel,
    command,
    timeout,
    transport=None,
    deadline=None,
    cleanup_deadline=None,
    cleanup_timeout=SSH_CLEANUP_TIMEOUT_SECONDS,
):
    if cleanup_deadline is None:
        cleanup_deadline = make_ssh_cleanup_deadline(deadline)
    wait_timeout = cap_ssh_timeout(timeout, deadline, "SSH exec request")
    completed = threading.Event()
    errors = []

    def execute():
        try:
            channel.exec_command(command)
        except Exception as e:
            errors.append(e)
        finally:
            completed.set()

    thread = threading.Thread(
        target=execute,
        name="ssh-exec-request",
        daemon=True,
    )
    thread.start()

    if not completed.wait(wait_timeout):
        close_ssh_channel(
            channel,
            transport,
            cleanup_timeout,
            cleanup_deadline=cleanup_deadline,
        )
        completed.wait(
            get_ssh_cleanup_wait_timeout(cleanup_deadline, cleanup_timeout)
        )
        raise TimeoutError(f"SSH exec request timeout after {wait_timeout:g}s")
    if errors:
        raise errors[0]


def read_ssh_channel(
    channel,
    idle_timeout,
    total_timeout,
    started_at=None,
    deadline=None,
):
    stdout_chunks = []
    stderr_chunks = []
    started = started_at if started_at is not None else time.monotonic()
    last_activity = time.monotonic()

    while True:
        received_data = False

        for _ in range(16):
            if not channel.recv_ready():
                break
            data = channel.recv(65536)
            if not data:
                break
            stdout_chunks.append(data)
            received_data = True
            last_activity = time.monotonic()
            get_ssh_deadline_remaining(deadline, "SSH command")
            if (
                total_timeout is not None
                and last_activity - started >= total_timeout
            ):
                raise TimeoutError(
                    f"SSH command total timeout after {total_timeout:g}s"
                )

        for _ in range(16):
            if not channel.recv_stderr_ready():
                break
            data = channel.recv_stderr(65536)
            if not data:
                break
            stderr_chunks.append(data)
            received_data = True
            last_activity = time.monotonic()
            get_ssh_deadline_remaining(deadline, "SSH command")
            if (
                total_timeout is not None
                and last_activity - started >= total_timeout
            ):
                raise TimeoutError(
                    f"SSH command total timeout after {total_timeout:g}s"
                )

        now = time.monotonic()
        get_ssh_deadline_remaining(deadline, "SSH command")
        if received_data:
            last_activity = now

        stdout_ready = channel.recv_ready()
        stderr_ready = channel.recv_stderr_ready()
        if not stdout_ready and not stderr_ready:
            if channel.closed or (
                getattr(channel, "eof_received", False)
                and channel.exit_status_ready()
            ):
                break

        if total_timeout is not None and now - started >= total_timeout:
            raise TimeoutError(
                f"SSH command total timeout after {total_timeout:g}s"
            )
        if now - last_activity >= idle_timeout:
            raise TimeoutError(
                f"SSH command idle timeout after {idle_timeout:g}s"
            )

        remaining_idle = max(0.01, idle_timeout - (now - last_activity))
        sleep_time = min(0.1, remaining_idle)
        if total_timeout is not None:
            remaining_total = max(0.01, total_timeout - (now - started))
            sleep_time = min(sleep_time, remaining_total)
        deadline_remaining = get_ssh_deadline_remaining(deadline, "SSH command")
        if deadline_remaining is not None:
            sleep_time = min(sleep_time, deadline_remaining)
        time.sleep(sleep_time)

    if not channel.exit_status_ready():
        raise paramiko.SSHException("SSH channel closed without exit status")
    status = channel.recv_exit_status()
    return (
        status,
        b"".join(stdout_chunks).decode("utf-8", "replace"),
        b"".join(stderr_chunks).decode("utf-8", "replace"),
    )


def run_ssh_command_status(
    client,
    command,
    timeout=None,
    channel_open_timeout=None,
    total_timeout=None,
    deadline=None,
):
    idle_timeout = timeout or getattr(
        client, "_command_idle_timeout", SSH_COMMAND_TIMEOUT
    )
    open_timeout = channel_open_timeout or getattr(
        client, "_channel_open_timeout", SSH_CHANNEL_OPEN_TIMEOUT
    )
    if total_timeout is None:
        total_timeout = idle_timeout * 2
    if deadline is None:
        deadline = make_ssh_deadline(total_timeout)
    cleanup_deadline = make_ssh_cleanup_deadline(deadline)

    lock = getattr(client, "_command_lock", None) or threading.RLock()
    acquire_until_deadline(lock, deadline, "SSH client command queue")
    try:
        channel = None
        transport = None
        stage = SSH_STAGE_PRE_DISPATCH
        try:
            transport = ensure_ssh_client_active(client)
            channel = open_ssh_session(
                transport,
                open_timeout,
                deadline=deadline,
                cleanup_deadline=cleanup_deadline,
            )
            channel.settimeout(
                cap_ssh_timeout(idle_timeout, deadline, "SSH command idle")
            )
            command_started = time.monotonic()
            exec_timeout = idle_timeout
            if total_timeout is not None:
                exec_timeout = min(exec_timeout, total_timeout)
            stage = SSH_STAGE_DISPATCHED
            execute_ssh_channel_command(
                channel,
                command,
                exec_timeout,
                transport=transport,
                deadline=deadline,
                cleanup_deadline=cleanup_deadline,
            )
            return read_ssh_channel(
                channel,
                idle_timeout,
                total_timeout,
                started_at=command_started,
                deadline=deadline,
            )
        except SSHCommandFailure:
            raise
        except Exception as e:
            if is_retryable_ssh_transport_error(e):
                client._invalid = True
            raise SSHCommandFailure(e, stage) from e
        finally:
            if channel is not None:
                try:
                    closed = close_ssh_channel(
                        channel,
                        transport,
                        cleanup_deadline=cleanup_deadline,
                    )
                except Exception as e:
                    logger.warning("Failed to schedule SSH channel cleanup: %s", e)
                    closed = False
                if not closed:
                    client._invalid = True
    finally:
        lock.release()


def get_ssh_retry_delay(settings, retry_index):
    base_delay = min(
        settings["retry_backoff_max"],
        settings["retry_backoff_base"] * (2 ** retry_index),
    )
    return base_delay + random.uniform(0, settings["retry_jitter"])


def run_server_ssh_command_status(
    server,
    command,
    *,
    timeout=None,
    channel_open_timeout=None,
    total_timeout=None,
    operation_timeout=None,
    retry_on_transport=False,
    operation_name="SSH command",
    namespace=None,
):
    if operation_timeout is None:
        operation_timeout = SSH_OPERATION_TIMEOUT
    deadline = make_ssh_deadline(operation_timeout)
    cleanup_deadline = make_ssh_cleanup_deadline(deadline)
    key = get_ssh_cache_key(server, namespace=namespace)
    command_lock = get_ssh_command_lock(key)
    settings = get_ssh_settings(server)
    idle_timeout = timeout or settings["command_idle_timeout"]
    open_timeout = channel_open_timeout or settings["channel_open_timeout"]
    if total_timeout is None:
        total_timeout = idle_timeout * 2
    max_attempts = settings["retry_count"] + 1
    acquire_until_deadline(command_lock, deadline, "SSH command queue")
    try:
        for attempt in range(max_attempts):
            client = None
            command_runner_entered = False
            try:
                if namespace is None:
                    client, was_reused = get_ssh_client(server, deadline=deadline)
                else:
                    client, was_reused = get_ssh_client(
                        server,
                        deadline=deadline,
                        namespace=namespace,
                    )
                attempt_open_timeout = open_timeout
                if was_reused:
                    attempt_open_timeout = min(
                        attempt_open_timeout,
                        settings["reused_channel_open_timeout"],
                    )
                command_runner_entered = True
                return run_ssh_command_status(
                    client,
                    command,
                    timeout=idle_timeout,
                    channel_open_timeout=attempt_open_timeout,
                    total_timeout=total_timeout,
                    deadline=deadline,
                )
            except Exception as e:
                if isinstance(e, SSHCommandFailure):
                    cause = e.cause
                    stage = e.stage
                    transport_error = e.transport_error
                else:
                    cause = e
                    stage = (
                        SSH_STAGE_DISPATCHED
                        if command_runner_entered
                        else SSH_STAGE_PRE_DISPATCH
                    )
                    transport_error = is_retryable_ssh_transport_error(e)

                if transport_error and client is not None:
                    invalidate_kwargs = {
                        "expected_client": client,
                        "cleanup_deadline": cleanup_deadline,
                    }
                    if namespace is not None:
                        invalidate_kwargs["namespace"] = namespace
                    invalidate_ssh_client(server, **invalidate_kwargs)

                can_retry = (
                    transport_error
                    and attempt + 1 < max_attempts
                    and (
                        retry_on_transport
                        or stage == SSH_STAGE_PRE_DISPATCH
                    )
                )
                if can_retry:
                    delay = get_ssh_retry_delay(settings, attempt)
                    logger.warning(
                        "%s failed for %s on attempt %s/%s: %s: %s; "
                        "reconnecting in %.2fs",
                        operation_name,
                        server["name"],
                        attempt + 1,
                        max_attempts,
                        cause.__class__.__name__,
                        str(cause) or repr(cause),
                        delay,
                    )
                    sleep_until_deadline(delay, deadline, "SSH retry backoff")
                    continue

                if stage == SSH_STAGE_DISPATCHED and not retry_on_transport:
                    message = str(cause) or cause.__class__.__name__
                    raise SSHCommandOutcomeUnknown(
                        f"{message}; remote command outcome is unknown"
                    ) from cause
                if isinstance(e, SSHCommandFailure):
                    raise cause from e
                raise
    finally:
        command_lock.release()


def sanitize_error(error_msg):
    if not error_msg:
        return "Unknown error"
    sanitized = re.sub(r"\d{1,3}(\.\d{1,3}){3}", "***", error_msg)
    sanitized = re.sub(r":\d{4,5}", ":***", sanitized)
    sanitized = re.sub(r"/home/[\w./\-]+", "/***", sanitized)
    sanitized = re.sub(r"/root/[\w./\-]+", "/***", sanitized)
    return sanitized


def shutdown():
    begin_shutdown()
    cleanup_deadline = make_ssh_deadline(SSH_CLEANUP_GRACE_SECONDS)
    with ssh_lock:
        clients = list(ssh_clients.values())
        ssh_clients.clear()
        ssh_connect_locks.clear()
        ssh_command_locks.clear()
    for client in clients:
        try:
            close_ssh_client(client, cleanup_deadline=cleanup_deadline)
        except Exception as e:
            logger.debug(f"Error closing SSH client: {e}")
