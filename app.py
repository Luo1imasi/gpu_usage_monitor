import csv
import base64
import binascii
import copy
import errno
import hashlib
import io
import json
import os
import random
import re
import secrets
import shlex
import socket
import time
import threading
import logging
import atexit
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, render_template, jsonify, request
from pathlib import Path
import paramiko

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)
logging.getLogger("paramiko").setLevel(logging.WARNING)

app = Flask(__name__)
CONFIG_PATH = Path(__file__).parent / "config.json"
USER_FILE_PATH = Path(__file__).parent / "user.txt"
USERNAME_PATTERN = re.compile(r"^[a-z_][a-z0-9_-]*\$?$")
MIN_MANAGED_UID = 1000
MAX_SSH_KEY_INPUT_SIZE = 16 * 1024
SSH_KEY_TYPES = {
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
}
SYSTEM_SHELL_NAMES = {"false", "nologin", "sync", "halt", "shutdown"}
PROTECTED_USERNAMES = {"root"}
SSH_CONNECT_TIMEOUT = 30
SSH_BANNER_TIMEOUT = 45
SSH_AUTH_TIMEOUT = 45
SSH_CONNECTION_TOTAL_TIMEOUT = 120
SSH_CHANNEL_OPEN_TIMEOUT = 60
SSH_REUSED_CHANNEL_OPEN_TIMEOUT = 20
SSH_COMMAND_TIMEOUT = 60
SSH_COMMAND_TOTAL_TIMEOUT = 90
SSH_OPERATION_TIMEOUT = 150
SSH_KEEPALIVE_SECONDS = 15
SSH_READONLY_RETRIES = 1
SSH_RETRY_BACKOFF_BASE_SECONDS = 2
SSH_RETRY_BACKOFF_MAX_SECONDS = 4
SSH_RETRY_JITTER_SECONDS = 2
SSH_CONNECT_JITTER_SECONDS = 1.5
SSH_CONNECT_MAX_CONCURRENCY = 8
SSH_CLEANUP_TIMEOUT_SECONDS = 1
SSH_CLEANUP_GRACE_SECONDS = 1
GPU_MAX_WORKERS = 8
GPU_COLLECTOR_RECONCILE_SECONDS = 2
GPU_COLLECTOR_RETRY_BACKOFF_MAX_SECONDS = 60
GPU_COLLECTOR_FRAME_MAX_BYTES = 4 * 1024 * 1024
GPU_COLLECTOR_HEADER_MAX_BYTES = 512
GPU_COLLECTOR_STDERR_TAIL_BYTES = 8 * 1024
ADMIN_MAX_WORKERS = 4
API_POLL_INTERVAL_SECONDS = 5
ACCESS_MATRIX_CACHE_TTL = 30
ACCESS_MATRIX_CACHE_MAX_ENTRIES = 64
user_file_lock = threading.RLock()

cached_data = []
cached_server_identities = {}
last_update = None
data_lock = threading.Lock()
gpu_executor = ThreadPoolExecutor(max_workers=GPU_MAX_WORKERS)
admin_executor = ThreadPoolExecutor(max_workers=ADMIN_MAX_WORKERS)
ssh_clients = {}
ssh_connect_locks = {}
ssh_command_locks = {}
ssh_lock = threading.Lock()
ssh_connect_semaphore = threading.BoundedSemaphore(SSH_CONNECT_MAX_CONCURRENCY)
access_matrix_cache = {}
access_matrix_cache_lock = threading.Lock()
gpu_collector_manager = None
shutdown_event = threading.Event()

_config_cache = None
_config_signature = None


def cleanup():
    global gpu_collector_manager
    logger.info("Cleaning up resources...")
    shutdown_event.set()
    if gpu_collector_manager is not None:
        gpu_collector_manager.stop()
    gpu_executor.shutdown(wait=False)
    admin_executor.shutdown(wait=False)
    with ssh_lock:
        clients = list(ssh_clients.values())
        ssh_clients.clear()
        ssh_connect_locks.clear()
        ssh_command_locks.clear()
    for client in clients:
        try:
            client.close()
        except Exception as e:
            logger.debug(f"Error closing SSH client: {e}")


atexit.register(cleanup)


def load_config():
    global _config_cache, _config_signature
    try:
        stat = CONFIG_PATH.stat()
        signature = (stat.st_mtime_ns, stat.st_size)
        if _config_cache is not None and signature == _config_signature:
            return _config_cache
        with open(CONFIG_PATH) as f:
            config = json.load(f)
            if not isinstance(config, dict):
                raise ValueError("Config root must be an object")
            _config_cache = config
            _config_signature = signature
            invalidate_access_matrix_cache()
            return _config_cache
    except FileNotFoundError:
        logger.error(f"Config file not found: {CONFIG_PATH}")
        return _config_cache or {"servers": [], "refresh_interval": 30}
    except (json.JSONDecodeError, ValueError) as e:
        logger.error(f"Invalid JSON in config file: {e}")
        return _config_cache or {"servers": [], "refresh_interval": 30}


def get_bounded_number(source, key, default, minimum, maximum, integer=False):
    value = source.get(key, default) if isinstance(source, dict) else default
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return default
    value = max(minimum, min(maximum, value))
    return int(value) if integer else float(value)


def get_ssh_settings(server=None):
    config = load_config()
    global_settings = config.get("ssh", {})
    if not isinstance(global_settings, dict):
        global_settings = {}

    server_settings = server.get("ssh", {}) if isinstance(server, dict) else {}
    if not isinstance(server_settings, dict):
        server_settings = {}
    settings = {**global_settings, **server_settings}

    return {
        "connect_timeout": get_bounded_number(
            settings, "connect_timeout_seconds", SSH_CONNECT_TIMEOUT, 1, 300
        ),
        "banner_timeout": get_bounded_number(
            settings, "banner_timeout_seconds", SSH_BANNER_TIMEOUT, 1, 300
        ),
        "auth_timeout": get_bounded_number(
            settings, "auth_timeout_seconds", SSH_AUTH_TIMEOUT, 1, 300
        ),
        "connection_total_timeout": get_bounded_number(
            settings,
            "connection_total_timeout_seconds",
            SSH_CONNECTION_TOTAL_TIMEOUT,
            5,
            600,
        ),
        "channel_open_timeout": get_bounded_number(
            settings,
            "channel_open_timeout_seconds",
            SSH_CHANNEL_OPEN_TIMEOUT,
            1,
            300,
        ),
        "reused_channel_open_timeout": get_bounded_number(
            settings,
            "reused_channel_open_timeout_seconds",
            SSH_REUSED_CHANNEL_OPEN_TIMEOUT,
            1,
            300,
        ),
        "command_idle_timeout": get_bounded_number(
            settings,
            "command_idle_timeout_seconds",
            SSH_COMMAND_TIMEOUT,
            1,
            300,
        ),
        "keepalive_interval": get_bounded_number(
            settings,
            "keepalive_interval_seconds",
            SSH_KEEPALIVE_SECONDS,
            1,
            300,
            integer=True,
        ),
        "retry_count": get_bounded_number(
            settings,
            "retry_count",
            SSH_READONLY_RETRIES,
            0,
            1,
            integer=True,
        ),
        "retry_backoff_base": get_bounded_number(
            settings,
            "retry_backoff_base_seconds",
            SSH_RETRY_BACKOFF_BASE_SECONDS,
            0,
            30,
        ),
        "retry_backoff_max": get_bounded_number(
            settings,
            "retry_backoff_max_seconds",
            SSH_RETRY_BACKOFF_MAX_SECONDS,
            0,
            60,
        ),
        "retry_jitter": get_bounded_number(
            settings,
            "retry_jitter_seconds",
            SSH_RETRY_JITTER_SECONDS,
            0,
            30,
        ),
        "connect_jitter": get_bounded_number(
            settings,
            "connect_jitter_seconds",
            SSH_CONNECT_JITTER_SECONDS,
            0,
            30,
        ),
    }


def get_monitoring_settings():
    config = load_config()
    settings = config.get("monitoring", {})
    if not isinstance(settings, dict):
        settings = {}

    legacy_refresh_interval = config.get("refresh_interval", 30)
    if isinstance(legacy_refresh_interval, bool) or not isinstance(
        legacy_refresh_interval, (int, float)
    ):
        legacy_refresh_interval = 30

    collector_mode = settings.get("collector_mode", "stream")
    if collector_mode not in {"stream", "poll", "batch"}:
        collector_mode = "stream"

    return {
        "refresh_interval": get_bounded_number(
            settings,
            "refresh_interval_seconds",
            legacy_refresh_interval,
            5,
            3600,
        ),
        "gpu_command_total_timeout": get_bounded_number(
            settings,
            "gpu_command_total_timeout_seconds",
            SSH_COMMAND_TOTAL_TIMEOUT,
            5,
            600,
        ),
        "gpu_operation_timeout": get_bounded_number(
            settings,
            "gpu_operation_timeout_seconds",
            SSH_OPERATION_TIMEOUT,
            5,
            900,
        ),
        "api_poll_interval": get_bounded_number(
            settings,
            "api_poll_interval_seconds",
            API_POLL_INTERVAL_SECONDS,
            1,
            60,
        ),
        "collector_mode": collector_mode,
        "collector_reconcile_interval": get_bounded_number(
            settings,
            "collector_reconcile_interval_seconds",
            GPU_COLLECTOR_RECONCILE_SECONDS,
            0.5,
            60,
        ),
        "collector_retry_backoff_max": get_bounded_number(
            settings,
            "collector_retry_backoff_max_seconds",
            GPU_COLLECTOR_RETRY_BACKOFF_MAX_SECONDS,
            2,
            600,
        ),
    }


def invalidate_access_matrix_cache():
    with access_matrix_cache_lock:
        access_matrix_cache.clear()


def get_file_signature(path):
    try:
        stat = path.stat()
        return stat.st_mtime_ns, stat.st_size
    except FileNotFoundError:
        return None


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
    with ssh_lock:
        existing = ssh_clients.get(key)
        if is_ssh_client_usable(existing, identity):
            existing_client = existing
        else:
            if existing is not None:
                old_client = ssh_clients.pop(key)
            ssh_clients[key] = new_client

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


def run_ssh_command(
    client,
    command,
    timeout=None,
    channel_open_timeout=None,
    total_timeout=None,
    deadline=None,
):
    _, out, err = run_ssh_command_status(
        client,
        command,
        timeout=timeout,
        channel_open_timeout=channel_open_timeout,
        total_timeout=total_timeout,
        deadline=deadline,
    )
    return out, err


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
):
    if operation_timeout is None:
        operation_timeout = SSH_OPERATION_TIMEOUT
    deadline = make_ssh_deadline(operation_timeout)
    cleanup_deadline = make_ssh_cleanup_deadline(deadline)
    key = get_ssh_cache_key(server)
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
                client, was_reused = get_ssh_client(server, deadline=deadline)
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
                    invalidate_ssh_client(
                        server,
                        expected_client=client,
                        cleanup_deadline=cleanup_deadline,
                    )

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

    raise RuntimeError("unreachable SSH retry state")


def sanitize_error(error_msg):
    if not error_msg:
        return "Unknown error"
    sanitized = re.sub(r"\d{1,3}(\.\d{1,3}){3}", "***", error_msg)
    sanitized = re.sub(r":\d{4,5}", ":***", sanitized)
    sanitized = re.sub(r"/home/[\w./\-]+", "/***", sanitized)
    sanitized = re.sub(r"/root/[\w./\-]+", "/***", sanitized)
    return sanitized


def normalize_ssh_key(key):
    return " ".join(key.strip().split())


def key_fingerprint(key):
    normalized = normalize_ssh_key(key)
    return hashlib.sha256(normalized.encode()).hexdigest()


def ssh_key_identity(key):
    parts = normalize_ssh_key(key).split()
    if len(parts) < 2:
        return None
    return " ".join(parts[:2])


def parse_ssh_public_key(key):
    parts = normalize_ssh_key(key).split()
    if len(parts) < 2:
        return None
    key_type, key_body = parts[0], parts[1]
    if key_type not in SSH_KEY_TYPES:
        return None
    try:
        decoded = base64.b64decode(key_body.encode(), validate=True)
    except (ValueError, binascii.Error):
        return None
    if len(decoded) < 4:
        return None

    type_length = int.from_bytes(decoded[:4], "big")
    if type_length <= 0 or type_length > len(decoded) - 4:
        return None
    try:
        embedded_type = decoded[4 : 4 + type_length].decode()
    except UnicodeDecodeError:
        return None
    if embedded_type != key_type:
        return None
    return {"key_type": key_type, "key_body": key_body}


def is_valid_ssh_public_key(key):
    return parse_ssh_public_key(key) is not None


def validate_username(username):
    return isinstance(username, str) and USERNAME_PATTERN.match(username) is not None


def validate_ssh_key_input(ssh_key):
    if not isinstance(ssh_key, str) or not normalize_ssh_key(ssh_key):
        return None, "ssh_key_required"
    if len(ssh_key) > MAX_SSH_KEY_INPUT_SIZE:
        return None, "invalid_ssh_key"

    normalized_key = normalize_ssh_key(ssh_key)
    if not is_valid_ssh_public_key(normalized_key):
        return None, "invalid_ssh_key"
    return normalized_key, None


def find_ssh_key_matches(ssh_key):
    normalized_key = normalize_ssh_key(ssh_key)
    if not is_valid_ssh_public_key(normalized_key):
        return None
    identity = ssh_key_identity(normalized_key)

    exact_fingerprint = key_fingerprint(normalized_key)
    identity_fingerprint = key_fingerprint(identity)
    matches = []

    for user in load_user_keys():
        exact_match = exact_fingerprint in user["key_hashes"]
        identity_match = False
        for stored_key in user["ssh_keys"]:
            stored_identity = ssh_key_identity(stored_key)
            if stored_identity and key_fingerprint(stored_identity) == identity_fingerprint:
                identity_match = True
                break
        if exact_match or identity_match:
            matches.append(
                {
                    "username": user["username"],
                    "key_count": len(user["key_hashes"]),
                    "match_type": "exact" if exact_match else "key_body",
                }
            )

    return {
        "exists": len(matches) > 0,
        "matches": matches,
    }


def append_user_key_unlocked(username, normalized_key):
    USER_FILE_PATH.parent.mkdir(parents=True, exist_ok=True)
    needs_newline = False
    try:
        with open(USER_FILE_PATH, "rb") as f:
            f.seek(0, os.SEEK_END)
            if f.tell() > 0:
                f.seek(-1, os.SEEK_END)
                needs_newline = f.read(1) != b"\n"
    except FileNotFoundError:
        pass

    with open(USER_FILE_PATH, "a") as f:
        if needs_newline:
            f.write("\n")
        f.write(f"{username} {normalized_key}\n")


def remove_user_from_file(username):
    if not validate_username(username):
        return {"error": "invalid_username"}, 400

    with user_file_lock:
        try:
            with open(USER_FILE_PATH) as f:
                lines = f.readlines()
        except FileNotFoundError:
            return {"username": username, "removed_lines": 0}, 200

        kept_lines = []
        removed_lines = 0
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                kept_lines.append(line)
                continue
            parts = stripped.split(None, 1)
            if len(parts) == 2 and parts[0] == username:
                removed_lines += 1
                continue
            kept_lines.append(line)

        tmp_path = USER_FILE_PATH.with_suffix(USER_FILE_PATH.suffix + ".tmp")
        with open(tmp_path, "w") as f:
            f.writelines(kept_lines)
        os.replace(tmp_path, USER_FILE_PATH)

    if removed_lines:
        invalidate_access_matrix_cache()

    return {"username": username, "removed_lines": removed_lines}, 200


def add_user_key(username, ssh_key):
    if not validate_username(username):
        return {"error": "invalid_username"}, 400

    normalized_key, error = validate_ssh_key_input(ssh_key)
    if error:
        return {"error": error}, 400

    with user_file_lock:
        existing = find_ssh_key_matches(normalized_key)
        if existing and existing["exists"]:
            return {"error": "ssh_key_already_exists", "matches": existing["matches"]}, 409

        append_user_key_unlocked(username, normalized_key)

    invalidate_access_matrix_cache()
    return {"username": username, "key_added": True}, 200


def load_user_keys():
    users = {}
    with user_file_lock:
        try:
            with open(USER_FILE_PATH) as f:
                for line_no, line in enumerate(f, start=1):
                    stripped = line.strip()
                    if not stripped or stripped.startswith("#"):
                        continue
                    parts = stripped.split(None, 1)
                    if len(parts) != 2:
                        logger.warning(f"Invalid user line {line_no} in {USER_FILE_PATH}")
                        continue
                    username, ssh_key = parts
                    if not USERNAME_PATTERN.match(username):
                        logger.warning(f"Invalid username {username} in {USER_FILE_PATH}")
                        continue
                    fingerprint = key_fingerprint(ssh_key)
                    if username not in users:
                        users[username] = {
                            "username": username,
                            "key_hashes": set(),
                            "ssh_keys": [],
                        }
                    users[username]["key_hashes"].add(fingerprint)
                    if ssh_key not in users[username]["ssh_keys"]:
                        users[username]["ssh_keys"].append(ssh_key)
        except FileNotFoundError:
            logger.error(f"User file not found: {USER_FILE_PATH}")

    return [
        {
            "username": user["username"],
            "key_hashes": sorted(user["key_hashes"]),
            "ssh_keys": user["ssh_keys"],
        }
        for user in sorted(users.values(), key=lambda item: item["username"])
    ]


def build_local_key_index(users=None):
    users = users if users is not None else load_user_keys()
    exact = {}
    identity = {}
    for user in users:
        for ssh_key in user["ssh_keys"]:
            exact.setdefault(key_fingerprint(ssh_key), set()).add(user["username"])
            key_identity = ssh_key_identity(ssh_key)
            if key_identity:
                identity.setdefault(key_fingerprint(key_identity), set()).add(user["username"])
    return exact, identity


def annotate_discovered_users(results):
    local_users = load_user_keys()
    local_usernames = {user["username"] for user in local_users}
    exact_index, identity_index = build_local_key_index(local_users)

    for server_result in results:
        for user in server_result.get("users", []):
            user["in_user_file"] = user["username"] in local_usernames
            new_keys = []
            duplicate_keys = []
            invalid_keys = []
            for ssh_key in user.get("ssh_keys", []):
                normalized_key = normalize_ssh_key(ssh_key)
                if not is_valid_ssh_public_key(normalized_key):
                    invalid_keys.append(normalized_key)
                    continue
                identity = ssh_key_identity(normalized_key)
                duplicate_users = set(exact_index.get(key_fingerprint(normalized_key), set()))
                if identity:
                    duplicate_users.update(identity_index.get(key_fingerprint(identity), set()))
                if duplicate_users:
                    duplicate_keys.append(
                        {
                            "ssh_key": normalized_key,
                            "users": sorted(duplicate_users),
                        }
                    )
                else:
                    new_keys.append(normalized_key)
            user["new_keys"] = new_keys
            user["duplicate_keys"] = duplicate_keys
            user["invalid_keys"] = invalid_keys
            user["key_count"] = len(user.get("ssh_keys", []))
    return results


def import_user_keys(items):
    if not isinstance(items, list) or not items:
        return {"error": "select_at_least_one_user_key"}, 400

    imported = []
    skipped = []
    errors = []

    with user_file_lock:
        seen_request_keys = set()
        for index, item in enumerate(items):
            if not isinstance(item, dict):
                errors.append({"index": index, "error": "items_must_be_objects"})
                continue

            username = item.get("username", "")
            if not validate_username(username):
                errors.append({"index": index, "username": username, "error": "invalid_username"})
                continue

            normalized_key, error = validate_ssh_key_input(item.get("ssh_key", ""))
            if error:
                errors.append({"index": index, "username": username, "error": error})
                continue

            identity = ssh_key_identity(normalized_key) or normalized_key
            request_key = key_fingerprint(identity)
            if request_key in seen_request_keys:
                skipped.append({"index": index, "username": username, "reason": "duplicate_in_request"})
                continue
            seen_request_keys.add(request_key)

            existing = find_ssh_key_matches(normalized_key)
            if existing and existing["exists"]:
                skipped.append(
                    {
                        "index": index,
                        "username": username,
                        "reason": "ssh_key_already_exists",
                        "matches": existing["matches"],
                    }
                )
                continue

            append_user_key_unlocked(username, normalized_key)
            imported.append({"username": username})

    if imported:
        invalidate_access_matrix_cache()

    return {
        "error": None,
        "imported": imported,
        "skipped": skipped,
        "errors": errors,
    }, 200


def get_servers_by_name():
    return {server["name"]: server for server in get_configured_servers()}


def get_configured_servers():
    config = load_config()
    servers = config.get("servers", [])
    if not isinstance(servers, list):
        return []
    configured = []
    seen_names = set()
    for server in servers:
        if not isinstance(server, dict) or not isinstance(server.get("name"), str):
            continue
        name = server["name"]
        if name in seen_names:
            logger.error("Ignoring duplicate server name in config: %s", name)
            continue
        seen_names.add(name)
        configured.append(server)
    return configured


def get_refresh_interval():
    return get_monitoring_settings()["refresh_interval"]


def get_users_by_name():
    return {user["username"]: user for user in load_user_keys()}


def normalize_name_list(value):
    if value is None:
        return None
    if isinstance(value, str):
        items = re.split(r"[\s,，;；]+", value)
    elif isinstance(value, list):
        items = []
        for item in value:
            if isinstance(item, str):
                items.extend(re.split(r"[\s,，;；]+", item))
            else:
                return value
    else:
        return value

    result = []
    seen = set()
    for item in items:
        name = item.strip()
        if name and name not in seen:
            result.append(name)
            seen.add(name)
    return result


def build_configure_users_command(users):
    safe_users = [
        {"username": user["username"], "ssh_keys": user["ssh_keys"]}
        for user in users
    ]
    script = f"""
import json
import os
import pwd
import re
import shutil
import subprocess

users = {json.dumps(safe_users)}
username_pattern = re.compile(r"^[a-z_][a-z0-9_-]*\\$?$")

def run(args):
    return subprocess.run(args, check=False, capture_output=True, text=True)

def group_exists(name):
    return run(["getent", "group", name]).returncode == 0

admin_group = None
if group_exists("sudo"):
    admin_group = "sudo"
elif group_exists("wheel"):
    admin_group = "wheel"

results = {{}}

for item in users:
    username = item["username"]
    ssh_keys = item["ssh_keys"]
    result = {{
        "created": False,
        "already_exists": False,
        "admin_group": admin_group,
        "admin_group_added": False,
        "sudoers_configured": False,
        "keys_added": 0,
        "keys_already_present": 0,
        "errors": [],
    }}
    results[username] = result

    if not username_pattern.match(username):
        result["errors"].append("invalid_username")
        continue

    try:
        pwd.getpwnam(username)
        result["already_exists"] = True
    except KeyError:
        useradd_args = ["useradd", "-m", "-s", "/bin/bash"]
        if group_exists(username):
            useradd_args.extend(["-g", username])
        useradd_args.append(username)
        proc = run(useradd_args)
        if proc.returncode != 0:
            result["errors"].append(proc.stderr.strip() or "useradd_failed")
            continue
        result["created"] = True

    try:
        entry = pwd.getpwnam(username)
        user_home = entry.pw_dir
        ssh_dir = os.path.join(user_home, ".ssh")
        auth_keys = os.path.join(ssh_dir, "authorized_keys")

        os.makedirs(ssh_dir, exist_ok=True)
        os.chmod(ssh_dir, 0o700)
        shutil.chown(ssh_dir, user=username, group=entry.pw_gid)

        if admin_group:
            groups_proc = run(["id", "-nG", username])
            groups = groups_proc.stdout.split()
            if admin_group not in groups:
                proc = run(["usermod", "-aG", admin_group, username])
                if proc.returncode == 0:
                    result["admin_group_added"] = True
                else:
                    result["errors"].append(proc.stderr.strip() or "usermod_failed")

        sudo_config_file = os.path.join("/etc/sudoers.d", username)
        with open(sudo_config_file, "w") as f:
            f.write(f"{{username}} ALL=(ALL) NOPASSWD:ALL\\n")
        os.chmod(sudo_config_file, 0o440)
        proc = run(["visudo", "-c", "-f", sudo_config_file])
        if proc.returncode == 0:
            result["sudoers_configured"] = True
        else:
            os.remove(sudo_config_file)
            result["errors"].append(proc.stderr.strip() or "visudo_failed")

        existing_keys = set()
        if os.path.exists(auth_keys):
            with open(auth_keys) as f:
                existing_keys = {{" ".join(line.strip().split()) for line in f if line.strip()}}

        with open(auth_keys, "a") as f:
            for ssh_key in ssh_keys:
                normalized_key = " ".join(ssh_key.strip().split())
                if normalized_key in existing_keys:
                    result["keys_already_present"] += 1
                    continue
                f.write(normalized_key + "\\n")
                existing_keys.add(normalized_key)
                result["keys_added"] += 1

        os.chmod(auth_keys, 0o600)
        shutil.chown(auth_keys, user=username, group=entry.pw_gid)
    except Exception as exc:
        result["errors"].append(exc.__class__.__name__)

print(json.dumps(results, ensure_ascii=False))
"""
    return f"sudo -n python3 - <<'PY'\n{script}\nPY"


def configure_access_for_server(server, users):
    try:
        status, out, err = run_server_ssh_command_status(
            server,
            build_configure_users_command(users),
            timeout=120,
            total_timeout=240,
            operation_timeout=360,
            retry_on_transport=False,
            operation_name="configure access",
        )
        if status != 0:
            message = err.strip() or out.strip() or "configure command failed"
            return {"server": server["name"], "error": sanitize_error(message), "users": {}}

        return {
            "server": server["name"],
            "error": None,
            "users": json.loads(out),
        }
    except Exception as e:
        logger.error(f"Error configuring user access for {server['name']}: {e}")
        return {"server": server["name"], "error": sanitize_error(str(e)), "users": {}}


def configure_selected_access(server_names, usernames):
    servers_by_name = get_servers_by_name()
    users_by_name = get_users_by_name()

    unknown_servers = sorted(set(server_names) - set(servers_by_name))
    unknown_users = sorted(set(usernames) - set(users_by_name))
    if unknown_servers or unknown_users:
        return {
            "error": "invalid_selection",
            "unknown_servers": unknown_servers,
            "unknown_users": unknown_users,
            "results": [],
        }, 400

    selected_servers = [servers_by_name[name] for name in server_names]
    selected_users = [users_by_name[username] for username in usernames]

    futures = {
        admin_executor.submit(configure_access_for_server, server, selected_users): server
        for server in selected_servers
    }
    results = []
    for future in as_completed(futures):
        server = futures[future]
        try:
            results.append(future.result())
        except Exception as e:
            logger.error(f"Unexpected configure error for {server['name']}: {e}")
            results.append({"server": server["name"], "error": sanitize_error(str(e)), "users": {}})

    results.sort(key=lambda item: item["server"])
    invalidate_access_matrix_cache()
    return {"error": None, "results": results}, 200


def configure_access_pairs(pairs):
    servers_by_name = get_servers_by_name()
    users_by_name = get_users_by_name()

    grouped_users = {}
    unknown_servers = set()
    unknown_users = set()

    for pair in pairs:
        if not isinstance(pair, dict):
            return {"error": "pairs_must_contain_objects", "results": []}, 400
        server_name = pair.get("server")
        username = pair.get("user")
        if not isinstance(server_name, str) or not isinstance(username, str):
            return {"error": "pair_server_and_user_must_be_strings", "results": []}, 400
        if server_name not in servers_by_name:
            unknown_servers.add(server_name)
        if username not in users_by_name:
            unknown_users.add(username)
        grouped_users.setdefault(server_name, set()).add(username)

    if unknown_servers or unknown_users:
        return {
            "error": "invalid_selection",
            "unknown_servers": sorted(unknown_servers),
            "unknown_users": sorted(unknown_users),
            "results": [],
        }, 400

    futures = {}
    for server_name, server_users in grouped_users.items():
        selected_users = [users_by_name[username] for username in sorted(server_users)]
        server = servers_by_name[server_name]
        futures[admin_executor.submit(configure_access_for_server, server, selected_users)] = server

    results = []
    for future in as_completed(futures):
        server = futures[future]
        try:
            results.append(future.result())
        except Exception as e:
            logger.error(f"Unexpected configure error for {server['name']}: {e}")
            results.append({"server": server["name"], "error": sanitize_error(str(e)), "users": {}})

    results.sort(key=lambda item: item["server"])
    invalidate_access_matrix_cache()
    return {"error": None, "results": results}, 200


def configured_ssh_usernames():
    return {
        server.get("username")
        for server in get_configured_servers()
        if isinstance(server.get("username"), str)
    }


def is_protected_username(username):
    return username in PROTECTED_USERNAMES or username in configured_ssh_usernames()


def resolve_selected_servers(server_names, allow_empty=False):
    servers_by_name = get_servers_by_name()
    if server_names is None and allow_empty:
        return [], None
    if server_names is None:
        return get_configured_servers(), None
    if not isinstance(server_names, list):
        return None, {"error": "servers_must_be_a_list"}

    clean_names = [name for name in server_names if isinstance(name, str)]
    unknown_servers = sorted(set(clean_names) - set(servers_by_name))
    if unknown_servers:
        return None, {"error": "invalid_selection", "unknown_servers": unknown_servers}
    return [servers_by_name[name] for name in clean_names], None


def build_detect_users_command(use_sudo=True):
    runner = "sudo -n python3 -" if use_sudo else "python3 -"
    script = f"""
import json
import os
import pwd

min_uid = {MIN_MANAGED_UID}
system_shell_names = {json.dumps(sorted(SYSTEM_SHELL_NAMES))}
results = []

for entry in pwd.getpwall():
    shell_name = os.path.basename(entry.pw_shell or "")
    if entry.pw_uid < min_uid or shell_name in system_shell_names:
        continue

    item = {{
        "username": entry.pw_name,
        "uid": entry.pw_uid,
        "gid": entry.pw_gid,
        "home": entry.pw_dir,
        "shell": entry.pw_shell,
        "authorized_keys_readable": False,
        "ssh_keys": [],
        "error": None,
    }}

    auth_keys = os.path.join(entry.pw_dir, ".ssh", "authorized_keys")
    try:
        with open(auth_keys) as f:
            for line in f:
                normalized = " ".join(line.strip().split())
                if normalized and not normalized.startswith("#"):
                    item["ssh_keys"].append(normalized)
        item["authorized_keys_readable"] = True
    except FileNotFoundError:
        item["authorized_keys_readable"] = True
    except PermissionError:
        item["error"] = "permission_denied"
    except OSError as exc:
        item["error"] = exc.__class__.__name__

    results.append(item)

print(json.dumps(results, ensure_ascii=False))
"""
    return f"{runner} <<'PY'\n{script}\nPY"


def detect_users_for_server(server):
    try:
        status, out, err = run_server_ssh_command_status(
            server,
            build_detect_users_command(use_sudo=True),
            timeout=60,
            total_timeout=120,
            operation_timeout=180,
            retry_on_transport=True,
            operation_name="detect users",
        )
        if status != 0:
            status, out, err = run_server_ssh_command_status(
                server,
                build_detect_users_command(use_sudo=False),
                timeout=60,
                total_timeout=120,
                operation_timeout=180,
                retry_on_transport=True,
                operation_name="detect users without sudo",
            )
        if status != 0:
            message = err.strip() or out.strip() or "detect users command failed"
            return {"server": server["name"], "error": sanitize_error(message), "users": []}

        users = json.loads(out)
        users = [
            user for user in users
            if validate_username(user.get("username", ""))
        ]
        users.sort(key=lambda item: item["username"])
        return {"server": server["name"], "error": None, "users": users}
    except Exception as e:
        logger.error(f"Error detecting users for {server['name']}: {e}")
        return {"server": server["name"], "error": sanitize_error(str(e)), "users": []}


def detect_server_users(server_names=None):
    selected_servers, error = resolve_selected_servers(server_names)
    if error:
        return {**error, "results": []}, 400

    futures = {
        admin_executor.submit(detect_users_for_server, server): server
        for server in selected_servers
    }
    results = []
    for future in as_completed(futures):
        server = futures[future]
        try:
            results.append(future.result())
        except Exception as e:
            logger.error(f"Unexpected detect error for {server['name']}: {e}")
            results.append({"server": server["name"], "error": sanitize_error(str(e)), "users": []})

    results.sort(key=lambda item: item["server"])
    return {"error": None, "results": annotate_discovered_users(results)}, 200


def build_revoke_user_command(username, ssh_keys, mode, clear_authorized_keys, remove_home):
    normalized_keys = [normalize_ssh_key(key) for key in ssh_keys if normalize_ssh_key(key)]
    script = f"""
import json
import os
import grp
import pwd
import shutil
import signal
import subprocess
import time

username = {json.dumps(username)}
ssh_keys = set({json.dumps(normalized_keys)})
mode = {json.dumps(mode)}
clear_authorized_keys = {repr(bool(clear_authorized_keys))}
remove_home = {repr(bool(remove_home))}
admin_groups = ["sudo", "wheel"]

def run(args):
    return subprocess.run(args, check=False, capture_output=True, text=True)

result = {{
    "user_exists": False,
    "uid": None,
    "keys_removed": 0,
    "authorized_keys_cleared": False,
    "sudoers_removed": False,
    "admin_groups_removed": [],
    "private_group_removed": False,
    "private_group_skipped": None,
    "password_locked": False,
    "processes_found": 0,
    "processes_terminated": 0,
    "processes_killed": 0,
    "processes_remaining": [],
    "deleted": False,
    "errors": [],
}}

def list_user_pids(uid):
    pids = []
    self_pid = os.getpid()
    for name in os.listdir("/proc"):
        if not name.isdigit():
            continue
        pid = int(name)
        if pid == self_pid:
            continue
        try:
            if os.stat(os.path.join("/proc", name)).st_uid == uid:
                pids.append(pid)
        except FileNotFoundError:
            continue
        except OSError:
            continue
    return sorted(pids)

def wait_for_user_process_exit(uid, timeout):
    deadline = time.time() + timeout
    remaining = list_user_pids(uid)
    while remaining and time.time() < deadline:
        time.sleep(0.2)
        remaining = list_user_pids(uid)
    return remaining

def signal_user_processes(uid, sig):
    signaled = 0
    for pid in list_user_pids(uid):
        try:
            os.kill(pid, sig)
            signaled += 1
        except ProcessLookupError:
            continue
        except PermissionError:
            continue
        except OSError:
            continue
    return signaled

def terminate_user_processes(uid):
    initial_pids = list_user_pids(uid)
    result["processes_found"] = len(initial_pids)
    if not initial_pids:
        return []

    result["processes_terminated"] = signal_user_processes(uid, signal.SIGTERM)
    remaining = wait_for_user_process_exit(uid, 5)
    if remaining:
        result["processes_killed"] = signal_user_processes(uid, signal.SIGKILL)
        remaining = wait_for_user_process_exit(uid, 3)

    result["processes_remaining"] = remaining
    return remaining

def remove_private_group_if_safe(group_name, gid):
    if group_name != username or gid < {MIN_MANAGED_UID}:
        result["private_group_skipped"] = "not_private_user_group"
        return

    try:
        group = grp.getgrnam(group_name)
    except KeyError:
        result["private_group_skipped"] = "group_not_found"
        return

    if group.gr_gid != gid:
        result["private_group_skipped"] = "gid_mismatch"
        return
    if group.gr_mem:
        result["private_group_skipped"] = "group_has_members"
        return

    primary_users = [
        item.pw_name
        for item in pwd.getpwall()
        if item.pw_gid == gid and item.pw_name != username
    ]
    if primary_users:
        result["private_group_skipped"] = "group_used_as_primary"
        return

    proc = run(["groupdel", group_name])
    if proc.returncode == 0:
        result["private_group_removed"] = True
        result["private_group_skipped"] = None
    else:
        result["errors"].append(proc.stderr.strip() or "groupdel_failed")

try:
    entry = pwd.getpwnam(username)
    result["user_exists"] = True
    result["uid"] = entry.pw_uid
    user_gid = entry.pw_gid
except KeyError:
    print(json.dumps(result, ensure_ascii=False))
    raise SystemExit(0)

if result["uid"] is not None and result["uid"] < {MIN_MANAGED_UID}:
    result["errors"].append("refuse_system_user")
    print(json.dumps(result, ensure_ascii=False))
    raise SystemExit(0)

auth_keys = os.path.join(entry.pw_dir, ".ssh", "authorized_keys")
try:
    if os.path.exists(auth_keys):
        if clear_authorized_keys:
            existing = []
            with open(auth_keys) as f:
                existing = [line for line in f if line.strip()]
            with open(auth_keys, "w"):
                pass
            result["keys_removed"] = len(existing)
            result["authorized_keys_cleared"] = True
        else:
            kept = []
            removed = 0
            with open(auth_keys) as f:
                for line in f:
                    normalized = " ".join(line.strip().split())
                    if normalized and normalized in ssh_keys:
                        removed += 1
                        continue
                    kept.append(line)
            with open(auth_keys, "w") as f:
                f.writelines(kept)
            result["keys_removed"] = removed
        os.chmod(auth_keys, 0o600)
        shutil.chown(auth_keys, user=username, group=entry.pw_gid)
except Exception as exc:
    result["errors"].append("authorized_keys_" + exc.__class__.__name__)

sudoers_file = os.path.join("/etc/sudoers.d", username)
try:
    if os.path.exists(sudoers_file):
        os.remove(sudoers_file)
        result["sudoers_removed"] = True
except Exception as exc:
    result["errors"].append("sudoers_" + exc.__class__.__name__)

for group_name in admin_groups:
    proc = run(["getent", "group", group_name])
    if proc.returncode != 0:
        continue
    groups_proc = run(["id", "-nG", username])
    if group_name in groups_proc.stdout.split():
        remove_proc = run(["gpasswd", "-d", username, group_name])
        if remove_proc.returncode == 0:
            result["admin_groups_removed"].append(group_name)
        else:
            result["errors"].append(remove_proc.stderr.strip() or "group_remove_failed")

lock_proc = run(["passwd", "-l", username])
if lock_proc.returncode == 0:
    result["password_locked"] = True
else:
    result["errors"].append(lock_proc.stderr.strip() or "passwd_lock_failed")

if mode == "delete_account":
    remaining_processes = terminate_user_processes(entry.pw_uid)
    if remaining_processes:
        result["errors"].append("processes_remaining: " + ",".join(str(pid) for pid in remaining_processes[:20]))

    args = ["userdel"]
    if remove_home:
        args.append("-r")
    args.append(username)
    proc = run(args)
    if proc.returncode == 0:
        result["deleted"] = True
        remove_private_group_if_safe(username, user_gid)
    else:
        result["errors"].append(proc.stderr.strip() or "userdel_failed")

print(json.dumps(result, ensure_ascii=False))
"""
    return f"sudo -n python3 - <<'PY'\n{script}\nPY"


def revoke_user_on_server(server, username, ssh_keys, mode, clear_authorized_keys, remove_home):
    try:
        status, out, err = run_server_ssh_command_status(
            server,
            build_revoke_user_command(username, ssh_keys, mode, clear_authorized_keys, remove_home),
            timeout=120,
            total_timeout=240,
            operation_timeout=360,
            retry_on_transport=False,
            operation_name="revoke user access",
        )
        if status != 0:
            message = err.strip() or out.strip() or "revoke user command failed"
            return {"server": server["name"], "error": sanitize_error(message), "result": {}}
        return {"server": server["name"], "error": None, "result": json.loads(out)}
    except Exception as e:
        logger.error(f"Error revoking user {username} for {server['name']}: {e}")
        return {"server": server["name"], "error": sanitize_error(str(e)), "result": {}}


def remote_user_change_has_errors(results):
    for server_result in results:
        if server_result.get("error"):
            return True
        user_result = server_result.get("result") or {}
        if user_result.get("errors"):
            return True
    return False


def delete_user_access(username, payload):
    if not validate_username(username):
        return {"error": "invalid_username", "results": []}, 400
    if is_protected_username(username):
        return {"error": "protected_username", "results": []}, 400

    mode = payload.get("mode", "revoke")
    if mode not in {"local_only", "revoke", "delete_account"}:
        return {"error": "invalid_delete_mode", "results": []}, 400
    if mode == "delete_account" and payload.get("confirm") != username:
        return {"error": "username_confirmation_required", "results": []}, 400

    users_by_name = get_users_by_name()
    user = users_by_name.get(username, {"ssh_keys": []})

    if mode == "local_only":
        local_result, _ = remove_user_from_file(username)
        return {"error": None, "local": local_result, "results": []}, 200

    selected_servers, error = resolve_selected_servers(payload.get("servers"), allow_empty=True)
    if error:
        return {**error, "results": []}, 400
    if not selected_servers:
        return {"error": "select_at_least_one_server", "results": []}, 400

    clear_authorized_keys = bool(payload.get("clear_authorized_keys", True))
    remove_home = bool(payload.get("remove_home", False))
    remove_from_user_file = bool(payload.get("remove_from_user_file", True))

    futures = {
        admin_executor.submit(
            revoke_user_on_server,
            server,
            username,
            user.get("ssh_keys", []),
            mode,
            clear_authorized_keys,
            remove_home,
        ): server
        for server in selected_servers
    }
    results = []
    for future in as_completed(futures):
        server = futures[future]
        try:
            results.append(future.result())
        except Exception as e:
            logger.error(f"Unexpected delete error for {server['name']}: {e}")
            results.append({"server": server["name"], "error": sanitize_error(str(e)), "result": {}})

    results.sort(key=lambda item: item["server"])
    local_result = None
    if remove_from_user_file:
        if remote_user_change_has_errors(results):
            local_result = {
                "username": username,
                "removed_lines": 0,
                "skipped": True,
                "reason": "remote_errors",
            }
        else:
            local_result, _ = remove_user_from_file(username)

    invalidate_access_matrix_cache()
    return {"error": None, "local": local_result, "results": results}, 200


def is_admin_authorized():
    expected_token = load_config().get("admin_token", "")
    if not expected_token:
        return False
    supplied_token = request.headers.get("X-Admin-Token", "")
    return supplied_token == expected_token


def build_access_check_command(usernames, use_sudo=True):
    runner = "sudo -n python3 -" if use_sudo else "python3 -"
    script = f"""
import hashlib
import json
import os
import pwd

usernames = {json.dumps(usernames)}
results = {{}}

for username in usernames:
    item = {{
        "user_exists": False,
        "authorized_keys_readable": False,
        "authorized_key_hashes": [],
        "error": None,
    }}
    try:
        entry = pwd.getpwnam(username)
        item["user_exists"] = True
        auth_keys = os.path.join(entry.pw_dir, ".ssh", "authorized_keys")
        try:
            with open(auth_keys) as f:
                hashes = []
                for line in f:
                    normalized = " ".join(line.strip().split())
                    if normalized and not normalized.startswith("#"):
                        hashes.append(hashlib.sha256(normalized.encode()).hexdigest())
                item["authorized_keys_readable"] = True
                item["authorized_key_hashes"] = sorted(set(hashes))
        except FileNotFoundError:
            item["authorized_keys_readable"] = True
        except PermissionError:
            item["error"] = "permission_denied"
        except OSError as exc:
            item["error"] = exc.__class__.__name__
    except KeyError:
        pass
    results[username] = item

print(json.dumps(results))
"""
    return f"{runner} <<'PY'\n{script}\nPY"


def check_access_matrix_for_server(server, users):
    usernames = [user["username"] for user in users]
    try:
        status, out, err = run_server_ssh_command_status(
            server,
            build_access_check_command(usernames, use_sudo=True),
            timeout=60,
            total_timeout=120,
            operation_timeout=180,
            retry_on_transport=True,
            operation_name="check access matrix",
        )
        if status != 0:
            status, out, err = run_server_ssh_command_status(
                server,
                build_access_check_command(usernames, use_sudo=False),
                timeout=60,
                total_timeout=120,
                operation_timeout=180,
                retry_on_transport=True,
                operation_name="check access matrix without sudo",
            )
        if status != 0:
            message = err.strip() or out.strip() or "access check command failed"
            return {"server": server["name"], "error": sanitize_error(message), "users": {}}

        remote_users = json.loads(out)
        return {"server": server["name"], "error": None, "users": remote_users}
    except Exception as e:
        logger.error(f"Error checking user access for {server['name']}: {e}")
        return {"server": server["name"], "error": sanitize_error(str(e)), "users": {}}


def resolve_access_matrix_scope(server_names=None, usernames=None):
    all_servers = get_configured_servers()
    servers_by_name = {
        server["name"]: server
        for server in all_servers
        if isinstance(server.get("name"), str)
    }
    server_names = normalize_name_list(server_names)
    if server_names is None:
        selected_servers = all_servers
    elif not isinstance(server_names, list):
        return None, None, None, {"error": "servers_must_be_a_list"}
    else:
        clean_server_names = [name for name in server_names if isinstance(name, str)]
        unknown_servers = sorted(set(clean_server_names) - set(servers_by_name))
        if unknown_servers:
            return None, None, None, {
                "error": "invalid_selection",
                "unknown_servers": unknown_servers,
            }
        requested_servers = set(clean_server_names)
        selected_servers = [
            server for server in all_servers if server["name"] in requested_servers
        ]

    all_users = load_user_keys()
    users_by_name = {user["username"]: user for user in all_users}
    usernames = normalize_name_list(usernames)
    if usernames is None:
        selected_users = all_users
    elif not isinstance(usernames, list):
        return None, None, None, {"error": "users_must_be_a_list"}
    else:
        clean_usernames = [name for name in usernames if isinstance(name, str)]
        unknown_users = sorted(set(clean_usernames) - set(users_by_name))
        if unknown_users:
            return None, None, None, {
                "error": "invalid_selection",
                "unknown_users": unknown_users,
            }
        requested_users = set(clean_usernames)
        selected_users = [
            user for user in all_users if user["username"] in requested_users
        ]

    scope = {
        "server_count": len(selected_servers),
        "total_server_count": len(all_servers),
        "user_count": len(selected_users),
        "total_user_count": len(all_users),
        "partial": len(selected_servers) != len(all_servers)
        or len(selected_users) != len(all_users),
    }
    return selected_servers, selected_users, scope, None


def access_matrix_cache_key(servers, users):
    return (
        tuple(server["name"] for server in servers),
        tuple(user["username"] for user in users),
        get_file_signature(USER_FILE_PATH),
        get_file_signature(CONFIG_PATH),
    )


def get_cached_access_matrix(key):
    now = time.time()
    with access_matrix_cache_lock:
        cached = access_matrix_cache.get(key)
        if not cached:
            return None
        created_at, matrix = cached
        if now - created_at > ACCESS_MATRIX_CACHE_TTL:
            del access_matrix_cache[key]
            return None
        result = copy.deepcopy(matrix)
        result["cached"] = True
        result["cache_age"] = round(now - created_at, 1)
        return result


def set_cached_access_matrix(key, matrix):
    with access_matrix_cache_lock:
        access_matrix_cache[key] = (time.time(), copy.deepcopy(matrix))
        if len(access_matrix_cache) > ACCESS_MATRIX_CACHE_MAX_ENTRIES:
            oldest_key = min(
                access_matrix_cache,
                key=lambda item: access_matrix_cache[item][0],
            )
            del access_matrix_cache[oldest_key]


def build_access_matrix(server_names=None, usernames=None):
    servers, users, scope, error = resolve_access_matrix_scope(server_names, usernames)
    if error:
        return {**error, "servers": [], "users": []}, 400

    cache_key = access_matrix_cache_key(servers, users)
    cached = get_cached_access_matrix(cache_key)
    if cached:
        return cached, 200

    matrix = {
        "servers": [{"name": server["name"]} for server in servers],
        "users": [
            {"username": user["username"], "key_count": len(user["key_hashes"]), "servers": []}
            for user in users
        ],
        "scope": {
            **scope,
            "cache_ttl": ACCESS_MATRIX_CACHE_TTL,
        },
        "cached": False,
    }

    if not users or not servers:
        set_cached_access_matrix(cache_key, matrix)
        return matrix, 200

    futures = {
        admin_executor.submit(check_access_matrix_for_server, server, users): server
        for server in servers
    }
    server_results = {}
    for future in as_completed(futures):
        server = futures[future]
        try:
            result = future.result()
        except Exception as e:
            logger.error(f"Unexpected access check error for {server['name']}: {e}")
            result = {"server": server["name"], "error": sanitize_error(str(e)), "users": {}}
        server_results[result["server"]] = result

    for user_item, source_user in zip(matrix["users"], users):
        expected_hashes = set(source_user["key_hashes"])
        for server in servers:
            server_name = server["name"]
            server_result = server_results.get(server_name, {"error": "No result", "users": {}})
            remote_user = server_result.get("users", {}).get(source_user["username"], {})
            installed_hashes = set(remote_user.get("authorized_key_hashes", []))
            matching_keys = len(expected_hashes & installed_hashes)
            key_installed = matching_keys > 0 if remote_user.get("authorized_keys_readable") else None
            user_item["servers"].append(
                {
                    "server": server_name,
                    "user_exists": bool(remote_user.get("user_exists")),
                    "key_installed": key_installed,
                    "accessible": bool(remote_user.get("user_exists")) and key_installed is True,
                    "matching_key_count": matching_keys,
                    "error": server_result.get("error") or remote_user.get("error"),
                }
            )

    set_cached_access_matrix(cache_key, matrix)
    return matrix, 200


def parse_gpu_query(output):
    gpus = {}
    bus_to_idx = {}
    reader = csv.reader(io.StringIO(output))
    for row in reader:
        if len(row) < 6:
            continue
        try:
            idx = int(row[0].strip())
            bus_id = row[1].strip()
            name = row[2].strip()
            util_str = row[3].strip()
            mem_used_str = row[4].strip()
            mem_total_str = row[5].strip()
            gpu_util = int(float(util_str)) if util_str not in ("[N/A]", "") else 0
            mem_used = (
                int(float(mem_used_str)) if mem_used_str not in ("[N/A]", "") else 0
            )
            mem_total = (
                int(float(mem_total_str)) if mem_total_str not in ("[N/A]", "") else 0
            )
            gpus[idx] = {
                "index": idx,
                "name": name,
                "gpu_util": gpu_util,
                "memory_used": mem_used,
                "memory_total": mem_total,
                "processes": [],
            }
            bus_to_idx[bus_id] = idx
        except (ValueError, IndexError):
            continue
    return gpus, bus_to_idx


def parse_compute_apps(output, bus_to_idx, gpus):
    if not output.strip() or "No running" in output:
        return
    reader = csv.reader(io.StringIO(output))
    for row in reader:
        if len(row) < 3:
            continue
        bus_id = row[0].strip()
        pid_str = row[1].strip()
        mem_str = row[2].strip()
        if bus_id not in bus_to_idx:
            continue
        idx = bus_to_idx[bus_id]
        try:
            pid = int(pid_str)
        except ValueError:
            continue
        mem = 0
        try:
            mem = int(float(mem_str.replace(" MiB", "").replace(",", "").strip()))
        except ValueError:
            pass
        if idx in gpus:
            gpus[idx]["processes"].append(
                {"pid": pid, "memory": mem, "user": "unknown"}
            )


GPU_INFO_GPU_START = "__GPU_MONITOR_GPU_START__"
GPU_INFO_GPU_END = "__GPU_MONITOR_GPU_END__"
GPU_INFO_APPS_START = "__GPU_MONITOR_APPS_START__"
GPU_INFO_APPS_END = "__GPU_MONITOR_APPS_END__"
GPU_INFO_PS_START = "__GPU_MONITOR_PS_START__"
GPU_INFO_PS_END = "__GPU_MONITOR_PS_END__"


def build_gpu_info_command():
    gpu_fields = "index,gpu_bus_id,name,utilization.gpu,memory.used,memory.total"
    app_fields = "gpu_bus_id,pid,used_gpu_memory"
    return f"""
gpu_status=0
echo {GPU_INFO_GPU_START}
gpu_output="$(nvidia-smi --query-gpu={gpu_fields} --format=csv,noheader,nounits)" || gpu_status=$?
printf '%s\n' "$gpu_output"
echo {GPU_INFO_GPU_END}
echo {GPU_INFO_APPS_START}
has_gpu_memory="$(printf '%s\n' "$gpu_output" | awk -F, '{{gsub(/^[ \\t]+|[ \\t]+$/, "", $5); if (($5 + 0) > 0) {{print "1"; exit}}}}')"
apps=""
if [ "$gpu_status" -eq 0 ] && [ "$has_gpu_memory" = "1" ]; then
    apps="$(nvidia-smi --query-compute-apps={app_fields} --format=csv,noheader 2>/dev/null || true)"
fi
printf '%s\n' "$apps"
echo {GPU_INFO_APPS_END}
echo {GPU_INFO_PS_START}
pids="$(printf '%s\n' "$apps" | awk -F, '{{gsub(/^[ \\t]+|[ \\t]+$/, "", $2); if ($2 ~ /^[0-9]+$/) {{printf "%s%s", sep, $2; sep=","}}}}')"
if [ -n "$pids" ]; then
    ps -o pid=,user= -p "$pids" 2>/dev/null
fi
echo {GPU_INFO_PS_END}
exit "$gpu_status"
""".strip()


def build_gpu_collector_command(nonce, sample_timeout):
    gpu_fields = "index,gpu_bus_id,name,utilization.gpu,memory.used,memory.total"
    app_fields = "gpu_bus_id,pid,used_gpu_memory"
    sample_timeout = max(1, int(sample_timeout))
    script = f"""
LC_ALL=C
export LC_ALL
nonce={shlex.quote(nonce)}
gpu_fields={shlex.quote(gpu_fields)}
app_fields={shlex.quote(app_fields)}
sample_timeout={sample_timeout}
has_timeout=0
if command -v timeout >/dev/null 2>&1; then
    has_timeout=1
fi
run_limited() {{
    if [ "$has_timeout" = "1" ]; then
        timeout "$sample_timeout" "$@"
    else
        "$@"
    fi
}}
trap 'exit 0' HUP INT TERM PIPE
printf '\\036GUM1|%s|READY|1\\n' "$nonce" || exit 1
while IFS= read -r request; do
    case "$request" in
        QUIT)
            printf '\\036GUM1|%s|BYE\\n' "$nonce"
            break
            ;;
        POLL\\|*)
            seq="${{request#POLL|}}"
            case "$seq" in
                ''|*[!0-9]*) continue ;;
            esac
            ;;
        *)
            continue
            ;;
    esac

    gpu_capture="$(run_limited nvidia-smi "--query-gpu=$gpu_fields" --format=csv,noheader,nounits 2>&1)"
    gpu_status=$?
    gpu_output=""
    gpu_error=""
    if [ "$gpu_status" -eq 0 ]; then
        gpu_output="$gpu_capture"
    else
        gpu_error="$gpu_capture"
    fi

    apps=""
    if [ "$gpu_status" -eq 0 ]; then
        has_gpu_memory="$(printf '%s\\n' "$gpu_output" | awk -F, '{{gsub(/^[ \\t]+|[ \\t]+$/, "", $5); if (($5 + 0) > 0) {{print "1"; exit}}}}')"
        if [ "$has_gpu_memory" = "1" ]; then
            apps="$(run_limited nvidia-smi "--query-compute-apps=$app_fields" --format=csv,noheader 2>/dev/null || true)"
        fi
    fi

    ps_output=""
    pids="$(printf '%s\\n' "$apps" | awk -F, '{{gsub(/^[ \\t]+|[ \\t]+$/, "", $2); if ($2 ~ /^[0-9]+$/) {{printf "%s%s", sep, $2; sep=","}}}}')"
    if [ -n "$pids" ]; then
        ps_output="$(ps -o pid=,user= -p "$pids" 2>/dev/null || true)"
    fi

    epoch="$(date +%s 2>/dev/null || printf 0)"
    printf '\\036GUM1|%s|DATA|%s|%s|%s|%s|%s|%s|%s\\n' \\
        "$nonce" "$seq" "$epoch" "$gpu_status" \\
        "${{#gpu_output}}" "${{#apps}}" "${{#ps_output}}" "${{#gpu_error}}" || exit 1
    printf '%s%s%s%s' "$gpu_output" "$apps" "$ps_output" "$gpu_error" || exit 1
    printf '\\036GUM1|%s|END|%s\\n' "$nonce" "$seq" || exit 1
done
""".strip()
    return "sh -c " + shlex.quote(script)


class GPUStreamFrameParser:
    def __init__(self, nonce):
        self.reset(nonce)

    def reset(self, nonce):
        if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{32}", nonce):
            raise ValueError("Invalid GPU collector nonce")
        self.nonce = nonce
        self.buffer = bytearray()
        self.data_prefix = f"\x1eGUM1|{nonce}|DATA|".encode("ascii")

    def feed(self, data):
        if data:
            self.buffer.extend(data)
        frames = []

        while True:
            start = self.buffer.find(self.data_prefix)
            if start < 0:
                if len(self.buffer) > GPU_COLLECTOR_FRAME_MAX_BYTES:
                    raise ValueError("GPU collector frame prefix not found")
                keep = max(0, len(self.data_prefix) - 1)
                if len(self.buffer) > keep:
                    del self.buffer[:-keep]
                break
            if start:
                del self.buffer[:start]

            header_end = self.buffer.find(b"\n")
            if header_end < 0:
                if len(self.buffer) > GPU_COLLECTOR_HEADER_MAX_BYTES:
                    raise ValueError("GPU collector frame header is too large")
                break
            if header_end > GPU_COLLECTOR_HEADER_MAX_BYTES:
                raise ValueError("GPU collector frame header is too large")

            fields = bytes(
                self.buffer[len(self.data_prefix):header_end]
            ).split(b"|")
            if len(fields) != 7:
                raise ValueError("Invalid GPU collector frame header")
            try:
                seq, epoch, status, gpu_len, apps_len, ps_len, error_len = (
                    int(field) for field in fields
                )
            except ValueError as e:
                raise ValueError("Invalid GPU collector frame number") from e
            if min(seq, epoch, status, gpu_len, apps_len, ps_len, error_len) < 0:
                raise ValueError("Negative GPU collector frame number")

            lengths = (gpu_len, apps_len, ps_len, error_len)
            payload_length = sum(lengths)
            if payload_length > GPU_COLLECTOR_FRAME_MAX_BYTES:
                raise ValueError("GPU collector frame is too large")
            payload_start = header_end + 1
            payload_end = payload_start + payload_length
            footer = f"\x1eGUM1|{self.nonce}|END|{seq}\n".encode("ascii")
            frame_end = payload_end + len(footer)
            if len(self.buffer) < frame_end:
                break
            if bytes(self.buffer[payload_end:frame_end]) != footer:
                raise ValueError("Invalid GPU collector frame footer")

            cursor = payload_start
            segments = []
            for length in lengths:
                segments.append(bytes(self.buffer[cursor:cursor + length]))
                cursor += length
            del self.buffer[:frame_end]
            frames.append(
                {
                    "seq": seq,
                    "epoch": epoch,
                    "status": status,
                    "gpu": segments[0],
                    "apps": segments[1],
                    "ps": segments[2],
                    "error": segments[3],
                }
            )

        return frames


def extract_marked_section(output, start_marker, end_marker):
    start = output.find(start_marker)
    if start == -1:
        return ""
    start += len(start_marker)
    end = output.find(end_marker, start)
    if end == -1:
        return ""
    return output[start:end].strip()


def apply_process_users(ps_output, gpus):
    if not ps_output:
        return

    user_map = {}
    for line in ps_output.strip().split("\n"):
        if line.strip():
            parts = line.strip().split()
            if len(parts) >= 2:
                user_map[parts[0]] = parts[1]

    for gpu in gpus.values():
        for proc in gpu["processes"]:
            if str(proc["pid"]) in user_map:
                proc["user"] = user_map[str(proc["pid"])]


def build_gpu_result(
    server,
    status,
    gpu_output,
    apps_output="",
    ps_output="",
    error_output="",
):
    if status != 0 or not gpu_output.strip():
        error_msg = error_output.strip() or "No GPU info returned"
        logger.error("nvidia-smi error on %s: %s", server["name"], error_msg)
        return {"error": sanitize_error(error_msg), "server": server["name"]}

    gpus, bus_to_idx = parse_gpu_query(gpu_output)
    parse_compute_apps(apps_output, bus_to_idx, gpus)
    apply_process_users(ps_output, gpus)

    for gpu in gpus.values():
        user_memory = {}
        for proc in gpu["processes"]:
            user = proc["user"]
            if user not in user_memory:
                user_memory[user] = 0
            user_memory[user] += proc["memory"]

        total_proc_mem = sum(user_memory.values())
        if total_proc_mem > 0 and gpu["memory_used"] > 0:
            ratio = gpu["memory_used"] / total_proc_mem
            if ratio > 1.5:
                if len(user_memory) == 1:
                    user_memory[list(user_memory.keys())[0]] = gpu["memory_used"]
                else:
                    for user in user_memory:
                        proportion = user_memory[user] / total_proc_mem
                        user_memory[user] = int(gpu["memory_used"] * proportion)

        gpu["processes"] = [
            {"user": user, "memory": memory}
            for user, memory in user_memory.items()
        ]

    return {
        "server": server["name"],
        "gpus": sorted(gpus.values(), key=lambda item: item["index"]),
        "error": None,
    }


def get_gpu_info_ssh(server):
    try:
        monitoring_settings = get_monitoring_settings()
        status, out, err = run_server_ssh_command_status(
            server,
            build_gpu_info_command(),
            total_timeout=monitoring_settings["gpu_command_total_timeout"],
            operation_timeout=monitoring_settings["gpu_operation_timeout"],
            retry_on_transport=True,
            operation_name="GPU query",
        )
        return build_gpu_result(
            server,
            status,
            extract_marked_section(out, GPU_INFO_GPU_START, GPU_INFO_GPU_END),
            extract_marked_section(out, GPU_INFO_APPS_START, GPU_INFO_APPS_END),
            extract_marked_section(out, GPU_INFO_PS_START, GPU_INFO_PS_END),
            err,
        )
    except Exception as e:
        error_message = str(e) or e.__class__.__name__
        logger.error("Error getting GPU info for %s: %s", server["name"], error_message)
        return {"error": sanitize_error(error_message), "server": server["name"]}


def make_waiting_gpu_result(server_name):
    return {
        "server": server_name,
        "error": "Waiting for first sample",
        "stale": False,
        "updated_at": None,
        "last_error": None,
    }


def merge_gpu_result(previous, result, now=None):
    now = time.time() if now is None else now
    merged_result = copy.deepcopy(result)
    error = merged_result.get("error")
    is_success = error is None and "gpus" in merged_result

    if is_success:
        merged_result["stale"] = False
        merged_result["updated_at"] = now
        merged_result["last_error"] = None
        return merged_result

    if error is None:
        error = "Invalid GPU result"
        merged_result["error"] = error

    has_previous_success = (
        isinstance(previous, dict)
        and "gpus" in previous
        and previous.get("error") is None
    )
    if has_previous_success:
        stale_result = copy.deepcopy(previous)
        stale_result["error"] = None
        stale_result["stale"] = True
        stale_result["last_error"] = error
        return stale_result

    merged_result["stale"] = False
    merged_result["updated_at"] = None
    merged_result["last_error"] = error
    return merged_result


def get_gpu_cache_identity(server):
    return (
        server.get("host"),
        server.get("port"),
        server.get("username"),
    )


def initialize_gpu_cache(servers):
    global cached_data, cached_server_identities
    current_identities = {
        server["name"]: get_gpu_cache_identity(server)
        for server in servers
    }
    ordered_names = sorted(current_identities)
    with data_lock:
        existing = {item["server"]: item for item in cached_data}
        cached_data = [
            existing.get(name, make_waiting_gpu_result(name))
            if cached_server_identities.get(name) == current_identities[name]
            else make_waiting_gpu_result(name)
            for name in ordered_names
        ]
        cached_server_identities = current_identities


def publish_gpu_result(result, server_names):
    global cached_data, last_update
    server_name = result["server"]
    ordered_names = sorted(server_names)
    now = time.time()

    with data_lock:
        current = {item["server"]: item for item in cached_data}
        current[server_name] = merge_gpu_result(
            current.get(server_name),
            result,
            now=now,
        )
        cached_data = [
            current.get(name, make_waiting_gpu_result(name))
            for name in ordered_names
        ]
        last_update = now


def compute_collector_backoff(attempt, base, maximum, jitter):
    delay = min(maximum, base * (2 ** max(0, attempt)))
    if jitter > 0:
        delay += random.uniform(0, jitter)
    return min(maximum, delay)


def get_gpu_collector_signature(server, monitoring_settings):
    return (
        get_gpu_cache_identity(server),
        get_ssh_connection_identity(server),
        json.dumps(get_ssh_settings(server), sort_keys=True),
        monitoring_settings["collector_mode"],
        monitoring_settings["refresh_interval"],
        monitoring_settings["gpu_command_total_timeout"],
        monitoring_settings["gpu_operation_timeout"],
        monitoring_settings["collector_retry_backoff_max"],
    )


class GPUCollector:
    SSH_NAMESPACE_PREFIX = "gpu-collector"

    def __init__(self, server, monitoring_settings, publish_callback):
        self.server = copy.deepcopy(server)
        self.monitoring_settings = dict(monitoring_settings)
        self.publish_callback = publish_callback
        self.ssh_namespace = (
            f"{self.SSH_NAMESPACE_PREFIX}:{self.server['name']}:"
            f"{secrets.token_hex(8)}"
        )
        self.signature = get_gpu_collector_signature(
            self.server,
            self.monitoring_settings,
        )
        self.stop_event = threading.Event()
        self.state_lock = threading.Lock()
        self.send_lock = threading.Lock()
        self.thread = None
        self.client = None
        self.channel = None
        self.backoff_attempt = 0
        self.stderr_tail = bytearray()

    def start(self):
        if self.thread is not None and self.thread.is_alive():
            return
        self.thread = threading.Thread(
            target=self._run,
            name=f"gpu-collector-{self.server['name']}",
            daemon=True,
        )
        self.thread.start()

    def is_alive(self):
        return self.thread is not None and self.thread.is_alive()

    def stop(self, timeout=2):
        self.stop_event.set()
        cleanup_deadline = make_ssh_deadline(max(0, min(1, timeout)))
        with self.state_lock:
            client = self.client
            channel = self.channel
        if channel is not None:
            close_ssh_channel(
                channel,
                timeout=min(1, timeout),
                cleanup_deadline=cleanup_deadline,
            )
        if client is not None:
            invalidate_ssh_client(
                self.server,
                expected_client=client,
                cleanup_deadline=cleanup_deadline,
                namespace=self.ssh_namespace,
            )
        if (
            self.thread is not None
            and self.thread is not threading.current_thread()
        ):
            self.thread.join(timeout=max(0, timeout))

    def _publish_error(self, error):
        message = str(error) or error.__class__.__name__
        self.publish_callback(
            self,
            {
                "server": self.server["name"],
                "error": sanitize_error(message),
            },
        )

    def _run(self):
        if self.monitoring_settings["collector_mode"] in {"poll", "batch"}:
            self._run_polling()
            return

        ssh_settings = get_ssh_settings(self.server)
        retry_base = max(1.0, ssh_settings["retry_backoff_base"])
        retry_max = self.monitoring_settings["collector_retry_backoff_max"]
        retry_jitter = ssh_settings["retry_jitter"]

        while not self.stop_event.is_set():
            try:
                self._run_stream_session()
                if not self.stop_event.is_set():
                    raise paramiko.SSHException("GPU collector stream ended")
            except Exception as e:
                if self.stop_event.is_set():
                    break
                self._publish_error(e)
                delay = compute_collector_backoff(
                    self.backoff_attempt,
                    retry_base,
                    retry_max,
                    retry_jitter,
                )
                self.backoff_attempt += 1
                logger.warning(
                    "GPU collector for %s failed: %s: %s; reconnecting in %.2fs",
                    self.server["name"],
                    e.__class__.__name__,
                    str(e) or repr(e),
                    delay,
                )
                self.stop_event.wait(delay)

    def _run_polling(self):
        interval = self.monitoring_settings["refresh_interval"]
        while not self.stop_event.is_set():
            result = get_gpu_info_ssh(self.server)
            if self.stop_event.is_set():
                break
            self.publish_callback(self, result)
            self.stop_event.wait(interval)

    def _set_session_state(self, client, channel):
        with self.state_lock:
            self.client = client
            self.channel = channel

    def _clear_session_state(self, client, channel):
        with self.state_lock:
            if self.client is client:
                self.client = None
            if self.channel is channel:
                self.channel = None

    def _append_stderr(self, data):
        if not data:
            return
        self.stderr_tail.extend(data)
        if len(self.stderr_tail) > GPU_COLLECTOR_STDERR_TAIL_BYTES:
            del self.stderr_tail[:-GPU_COLLECTOR_STDERR_TAIL_BYTES]

    def _read_frame(self, channel, parser, expected_seq, deadline=None):
        if deadline is None:
            deadline = make_ssh_deadline(
                self.monitoring_settings["gpu_command_total_timeout"]
            )
        while not self.stop_event.is_set():
            for _ in range(16):
                if not channel.recv_ready():
                    break
                data = channel.recv(65536)
                if not data:
                    raise EOFError("GPU collector channel closed")
                for frame in parser.feed(data):
                    if frame["seq"] < expected_seq:
                        continue
                    if frame["seq"] != expected_seq:
                        raise ValueError("Unexpected GPU collector frame sequence")
                    return frame

            for _ in range(16):
                if not channel.recv_stderr_ready():
                    break
                self._append_stderr(channel.recv_stderr(65536))

            if channel.closed or channel.exit_status_ready():
                error = self.stderr_tail.decode("utf-8", "replace").strip()
                raise paramiko.SSHException(
                    error or "GPU collector channel exited"
                )
            get_ssh_deadline_remaining(deadline, "GPU collector sample")
            self.stop_event.wait(0.05)

        raise InterruptedError("GPU collector stopped")

    def _run_stream_session(self):
        operation_deadline = make_ssh_deadline(
            self.monitoring_settings["gpu_operation_timeout"]
        )
        cleanup_deadline = make_ssh_cleanup_deadline(operation_deadline)
        ssh_settings = get_ssh_settings(self.server)
        client = None
        channel = None
        transport = None
        self.stderr_tail.clear()
        nonce = secrets.token_hex(16)
        parser = GPUStreamFrameParser(nonce)
        sample_timeout = max(
            1,
            min(
                60,
                self.monitoring_settings["gpu_command_total_timeout"] / 2,
            ),
        )

        try:
            client, was_reused = get_ssh_client(
                self.server,
                deadline=operation_deadline,
                namespace=self.ssh_namespace,
            )
            self._set_session_state(client, None)
            if self.stop_event.is_set():
                raise InterruptedError("GPU collector stopped during connect")
            transport = ensure_ssh_client_active(client)
            open_timeout = ssh_settings["channel_open_timeout"]
            if was_reused:
                open_timeout = min(
                    open_timeout,
                    ssh_settings["reused_channel_open_timeout"],
                )
            channel = open_ssh_session(
                transport,
                open_timeout,
                deadline=operation_deadline,
                cleanup_deadline=cleanup_deadline,
            )
            self._set_session_state(client, channel)
            if self.stop_event.is_set():
                raise InterruptedError("GPU collector stopped during channel open")
            channel.settimeout(
                cap_ssh_timeout(
                    ssh_settings["command_idle_timeout"],
                    operation_deadline,
                    "GPU collector channel",
                )
            )
            execute_ssh_channel_command(
                channel,
                build_gpu_collector_command(nonce, sample_timeout),
                ssh_settings["command_idle_timeout"],
                transport=transport,
                deadline=operation_deadline,
                cleanup_deadline=cleanup_deadline,
            )
            if self.stop_event.is_set():
                raise InterruptedError("GPU collector stopped during stream start")
            logger.info("GPU collector stream started for %s", self.server["name"])

            seq = 0
            interval = self.monitoring_settings["refresh_interval"]
            next_poll_at = time.monotonic()
            while not self.stop_event.is_set():
                wait_time = max(0.0, next_poll_at - time.monotonic())
                if self.stop_event.wait(wait_time):
                    break
                seq += 1
                poll_started = time.monotonic()
                sample_deadline = make_ssh_deadline(
                    self.monitoring_settings["gpu_command_total_timeout"]
                )
                channel.settimeout(
                    cap_ssh_timeout(
                        min(
                            ssh_settings["command_idle_timeout"],
                            self.monitoring_settings["gpu_command_total_timeout"],
                        ),
                        sample_deadline,
                        "GPU collector sample send",
                    )
                )
                with self.send_lock:
                    channel.sendall(f"POLL|{seq}\n".encode("ascii"))
                frame = self._read_frame(
                    channel,
                    parser,
                    seq,
                    sample_deadline,
                )
                self.backoff_attempt = 0
                result = build_gpu_result(
                    self.server,
                    frame["status"],
                    frame["gpu"].decode("utf-8", "replace"),
                    frame["apps"].decode("utf-8", "replace"),
                    frame["ps"].decode("utf-8", "replace"),
                    frame["error"].decode("utf-8", "replace"),
                )
                self.publish_callback(self, result)
                next_poll_at = max(
                    poll_started + interval,
                    time.monotonic(),
                )
        finally:
            self._clear_session_state(client, channel)
            cleanup_deadline = make_ssh_deadline(SSH_CLEANUP_GRACE_SECONDS)
            if channel is not None:
                close_ssh_channel(
                    channel,
                    transport,
                    cleanup_deadline=cleanup_deadline,
                )
            if client is not None:
                invalidate_ssh_client(
                    self.server,
                    expected_client=client,
                    cleanup_deadline=cleanup_deadline,
                    namespace=self.ssh_namespace,
                )


class GPUCollectorManager:
    def __init__(self, collector_factory=GPUCollector):
        self.collector_factory = collector_factory
        self.collectors = {}
        self.lock = threading.RLock()
        self.stop_event = threading.Event()

    def publish_from(self, collector, result):
        server_name = collector.server["name"]
        with self.lock:
            if self.collectors.get(server_name) is not collector:
                return False
            publish_gpu_result(result, list(self.collectors))
            return True

    def reconcile_once(self, servers=None, monitoring_settings=None):
        if servers is None:
            servers = get_configured_servers()
        if monitoring_settings is None:
            monitoring_settings = get_monitoring_settings()
        desired = {server["name"]: server for server in servers}
        to_stop = []
        to_start = []

        with self.lock:
            current = self.collectors
            planned = {}
            for name, server in desired.items():
                signature = get_gpu_collector_signature(
                    server,
                    monitoring_settings,
                )
                collector = current.get(name)
                collector_running = (
                    collector is not None
                    and (
                        not hasattr(collector, "is_alive")
                        or collector.is_alive()
                    )
                )
                if collector_running and collector.signature == signature:
                    planned[name] = collector
                    continue
                collector = self.collector_factory(
                    server,
                    monitoring_settings,
                    self.publish_from,
                )
                planned[name] = collector
                to_start.append(collector)

            to_stop = [
                collector
                for name, collector in current.items()
                if planned.get(name) is not collector
            ]
            self.collectors = planned
            initialize_gpu_cache(servers)

        for collector in to_stop:
            collector.stop()
        start_errors = []
        for collector in to_start:
            with self.lock:
                should_start = (
                    not self.stop_event.is_set()
                    and self.collectors.get(collector.server["name"])
                    is collector
                )
            if should_start:
                try:
                    collector.start()
                except Exception as e:
                    with self.lock:
                        if (
                            self.collectors.get(collector.server["name"])
                            is collector
                        ):
                            self.collectors.pop(collector.server["name"], None)
                    collector.stop(timeout=0)
                    start_errors.append(e)
            else:
                collector.stop(timeout=0)
        if start_errors:
            raise start_errors[0]

    def run(self):
        logger.info("Starting independent GPU collector manager")
        try:
            while not self.stop_event.is_set() and not shutdown_event.is_set():
                try:
                    monitoring_settings = get_monitoring_settings()
                    self.reconcile_once(
                        monitoring_settings=monitoring_settings,
                    )
                    delay = monitoring_settings["collector_reconcile_interval"]
                except Exception as e:
                    logger.error("GPU collector reconciliation failed: %s", e)
                    delay = GPU_COLLECTOR_RECONCILE_SECONDS
                self.stop_event.wait(delay)
        finally:
            self.stop()

    def stop(self, timeout=5):
        self.stop_event.set()
        with self.lock:
            collectors = list(self.collectors.values())
            self.collectors.clear()
        if not collectors:
            return
        per_collector_timeout = max(0.1, timeout / len(collectors))
        for collector in collectors:
            collector.stop(timeout=per_collector_timeout)


def refresh_data():
    servers = get_configured_servers()
    server_names = [server["name"] for server in servers]
    initialize_gpu_cache(servers)
    completed = 0

    futures = {
        gpu_executor.submit(get_gpu_info_ssh, server): server
        for server in servers
    }
    for future in as_completed(futures):
        try:
            result = future.result()
        except Exception as e:
            server = futures[future]
            logger.error(f"Unexpected error for {server['name']}: {e}")
            result = {
                "error": sanitize_error(str(e)),
                "server": server["name"],
            }
        publish_gpu_result(result, server_names)
        completed += 1

    logger.info(f"Refreshed data for {completed} servers")


def background_worker():
    global gpu_collector_manager
    monitoring_settings = get_monitoring_settings()
    if monitoring_settings["collector_mode"] == "batch":
        logger.info("Starting legacy batch GPU worker")
        while not shutdown_event.is_set():
            try:
                refresh_data()
            except Exception as e:
                logger.error(f"Error in background worker: {e}")
            shutdown_event.wait(get_refresh_interval())
        return

    gpu_collector_manager = GPUCollectorManager()
    gpu_collector_manager.run()


@app.route("/")
def index():
    return render_template("index.html", refresh_interval=get_refresh_interval())


@app.route("/api/gpu")
def get_gpu():
    with data_lock:
        return jsonify(cached_data)


@app.route("/api/servers")
def get_servers():
    servers = [{"name": s["name"]} for s in get_configured_servers()]
    monitoring_settings = get_monitoring_settings()
    return jsonify(
        {
            "servers": servers,
            "refresh_interval": monitoring_settings["refresh_interval"],
            "poll_interval": monitoring_settings["api_poll_interval"],
            "collector_mode": monitoring_settings["collector_mode"],
            "gpu_workers": GPU_MAX_WORKERS,
        }
    )


def get_query_name_list(name):
    values = request.args.getlist(name)
    if not values:
        return None
    return normalize_name_list(values)


@app.route("/api/access-matrix", methods=["GET", "POST"])
def get_access_matrix():
    if request.method == "POST":
        payload = request.get_json(silent=True) or {}
        server_names = payload.get("servers")
        usernames = payload.get("users")
    else:
        server_names = get_query_name_list("servers")
        usernames = get_query_name_list("users")

    result, status_code = build_access_matrix(server_names, usernames)
    return jsonify(result), status_code


@app.route("/api/check-ssh-key", methods=["POST"])
def check_ssh_key():
    if not is_admin_authorized():
        return jsonify({"error": "admin_token_required"}), 403

    payload = request.get_json(silent=True) or {}
    ssh_key = payload.get("ssh_key", "")
    if not isinstance(ssh_key, str) or not normalize_ssh_key(ssh_key):
        return jsonify({"error": "ssh_key_required"}), 400
    if len(ssh_key) > MAX_SSH_KEY_INPUT_SIZE:
        return jsonify({"error": "invalid_ssh_key"}), 400

    result = find_ssh_key_matches(ssh_key)
    if result is None:
        return jsonify({"error": "invalid_ssh_key"}), 400
    return jsonify(result)


@app.route("/api/users", methods=["POST"])
def add_user():
    if not is_admin_authorized():
        return jsonify({"error": "admin_token_required"}), 403

    payload = request.get_json(silent=True) or {}
    username = payload.get("username", "")
    ssh_key = payload.get("ssh_key", "")
    result, status_code = add_user_key(username, ssh_key)
    return jsonify(result), status_code


@app.route("/api/detect-users", methods=["POST"])
def detect_users():
    if not is_admin_authorized():
        return jsonify({"error": "admin_token_required"}), 403

    payload = request.get_json(silent=True) or {}
    result, status_code = detect_server_users(payload.get("servers"))
    return jsonify(result), status_code


@app.route("/api/import-users", methods=["POST"])
def import_users():
    if not is_admin_authorized():
        return jsonify({"error": "admin_token_required"}), 403

    payload = request.get_json(silent=True) or {}
    result, status_code = import_user_keys(payload.get("items"))
    return jsonify(result), status_code


@app.route("/api/users/<username>", methods=["DELETE"])
def delete_user(username):
    if not is_admin_authorized():
        return jsonify({"error": "admin_token_required"}), 403

    payload = request.get_json(silent=True) or {}
    result, status_code = delete_user_access(username, payload)
    return jsonify(result), status_code


@app.route("/api/configure-access", methods=["POST"])
def configure_access():
    if not is_admin_authorized():
        return jsonify({"error": "admin_token_required"}), 403

    payload = request.get_json(silent=True) or {}
    pairs = payload.get("pairs")
    if pairs is not None:
        if not isinstance(pairs, list) or not pairs:
            return jsonify({"error": "select_at_least_one_access_pair"}), 400
        result, status_code = configure_access_pairs(pairs)
        return jsonify(result), status_code

    server_names = payload.get("servers", [])
    usernames = payload.get("users", [])

    if not isinstance(server_names, list) or not isinstance(usernames, list):
        return jsonify({"error": "servers_and_users_must_be_lists"}), 400

    server_names = [name for name in server_names if isinstance(name, str)]
    usernames = [username for username in usernames if isinstance(username, str)]

    if not server_names or not usernames:
        return jsonify({"error": "select_at_least_one_server_and_user"}), 400

    result, status_code = configure_selected_access(server_names, usernames)
    return jsonify(result), status_code


if __name__ == "__main__":
    logger.info("Starting GPU usage monitor...")

    worker_thread = threading.Thread(target=background_worker, daemon=True)
    worker_thread.start()

    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    logger.info(f"Running Flask app on 0.0.0.0:5000 (debug={debug})")
    app.run(host="0.0.0.0", port=5000, debug=debug)
