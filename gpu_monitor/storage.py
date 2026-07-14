"""Low-frequency collection and caching of ``/home`` disk usage."""

import copy
import json
import logging
import shlex
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from functools import partial

from .config import (
    STORAGE_REFRESH_INTERVAL_SECONDS,
    STORAGE_USER_MIN_SIZE_MB,
    get_configured_servers,
    get_monitoring_settings,
)
from .ssh import run_server_ssh_command_status, sanitize_error


logger = logging.getLogger(__name__)

STORAGE_MAX_WORKERS = 4
STORAGE_COMMAND_TOTAL_TIMEOUT_SECONDS = 180
STORAGE_OPERATION_TIMEOUT_SECONDS = 210
REMOTE_COLLECTION_TIMEOUT_SECONDS = 150
REMOTE_DU_TIMEOUT_SECONDS = 60
MEBIBYTE = 1024 * 1024
DEFAULT_STORAGE_USER_MIN_BYTES = STORAGE_USER_MIN_SIZE_MB * MEBIBYTE


_REMOTE_STORAGE_SCRIPT = f"""
import json
import os
import pwd
import subprocess
import time

root = "/home"
stat = os.statvfs(root)
block_size = stat.f_frsize or stat.f_bsize
total = stat.f_blocks * block_size
free = stat.f_bfree * block_size
available = stat.f_bavail * block_size
used = max(0, total - free)
deadline = time.monotonic() + {REMOTE_COLLECTION_TIMEOUT_SECONDS}
users = []
usage_by_home = {{}}

for entry in sorted(pwd.getpwall(), key=lambda item: item.pw_name):
    home = os.path.abspath(entry.pw_dir or "")
    try:
        under_home = os.path.commonpath((root, home)) == root and home != root
    except ValueError:
        under_home = False
    if entry.pw_uid < 1000 or not under_home or not os.path.isdir(home):
        continue

    item = {{
        "username": entry.pw_name,
        "used": None,
    }}
    if home in usage_by_home:
        item.update(usage_by_home[home])
        users.append(item)
        continue
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        item["error"] = "collection timeout"
        users.append(item)
        continue
    try:
        result = subprocess.run(
            ["du", "-skx", home],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=max(1, min({REMOTE_DU_TIMEOUT_SECONDS}, remaining)),
            check=False,
        )
        fields = result.stdout.split()
        if result.returncode == 0 and fields:
            item["used"] = int(fields[0]) * 1024
        else:
            item["error"] = "unavailable"
    except (OSError, subprocess.SubprocessError, ValueError):
        item["error"] = "unavailable"
    usage_by_home[home] = {{
        key: value for key, value in item.items() if key != "username"
    }}
    users.append(item)

user_error_count = sum(1 for item in users if item.get("error"))

print(json.dumps({{
    "filesystem": {{
        "path": root,
        "total": total,
        "used": used,
        "available": available,
        "percent": round(
            (used * 100.0 / (used + available)) if used + available else 0.0,
            1,
        ),
    }},
    "users": users,
    "partial": user_error_count > 0,
    "user_error_count": user_error_count,
}}, separators=(",", ":")))
""".strip()


def build_storage_command(use_sudo=True):
    """Build the remote Python command without interpolating remote data."""
    python = "sudo -n python3" if use_sudo else "python3"
    return f"{python} -c {shlex.quote(_REMOTE_STORAGE_SCRIPT)}"


def get_storage_user_min_bytes():
    value = get_monitoring_settings().get(
        "storage_user_min_size_mb",
        STORAGE_USER_MIN_SIZE_MB,
    )
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
        value = STORAGE_USER_MIN_SIZE_MB
    return int(value * MEBIBYTE)


def make_waiting_storage_result(server_name, user_min_bytes=None):
    if user_min_bytes is None:
        user_min_bytes = get_storage_user_min_bytes()
    return {
        "server": server_name,
        "filesystem": None,
        "users": [],
        "user_min_bytes": user_min_bytes,
        "filtered_user_count": 0,
        "error": "Waiting for first sample",
        "updated_at": None,
        "stale": False,
        "last_error": None,
        "partial": False,
        "user_error_count": 0,
    }


def _is_successful_storage_result(result):
    return (
        isinstance(result, dict)
        and result.get("error") is None
        and isinstance(result.get("filesystem"), dict)
        and isinstance(result.get("users"), list)
    )


def merge_storage_result(previous, result, now=None):
    """Publish a result while retaining the last successful sample on failure."""
    now = time.time() if now is None else now
    merged = copy.deepcopy(result)

    if _is_successful_storage_result(merged):
        merged["stale"] = False
        merged["updated_at"] = now
        merged["last_error"] = None
        return merged

    error = merged.get("error") or "Invalid storage result"
    merged["error"] = error
    if _is_successful_storage_result(previous):
        stale = copy.deepcopy(previous)
        stale["error"] = None
        stale["stale"] = True
        stale["last_error"] = error
        return stale

    merged.setdefault("filesystem", None)
    merged.setdefault("users", [])
    merged.setdefault("partial", False)
    merged.setdefault("user_error_count", 0)
    merged.setdefault("user_min_bytes", DEFAULT_STORAGE_USER_MIN_BYTES)
    merged.setdefault("filtered_user_count", 0)
    merged["updated_at"] = None
    merged["stale"] = False
    merged["last_error"] = error
    return merged


def get_storage_cache_identity(server):
    return (
        server.get("host"),
        server.get("port"),
        server.get("username"),
    )


class StorageStateStore:
    """Own storage samples and their server identities behind one lock."""

    def __init__(self):
        self.lock = threading.Lock()
        self.cached_data = []
        self.cached_server_identities = {}

    def initialize_storage_cache(self, servers, user_min_bytes=None):
        if user_min_bytes is None:
            user_min_bytes = get_storage_user_min_bytes()
        identities = {
            server["name"]: get_storage_cache_identity(server) for server in servers
        }
        ordered_names = sorted(identities)
        with self.lock:
            existing = {item["server"]: item for item in self.cached_data}
            self.cached_data = [
                existing[name]
                if (
                    name in existing
                    and self.cached_server_identities.get(name) == identities[name]
                )
                else make_waiting_storage_result(name, user_min_bytes)
                for name in ordered_names
            ]
            self.cached_server_identities = identities

    def publish_storage_result(self, result, server_names):
        server_name = result["server"]
        ordered_names = sorted(server_names)
        user_min_bytes = result.get("user_min_bytes")
        if user_min_bytes is None:
            user_min_bytes = get_storage_user_min_bytes()
        with self.lock:
            current = {item["server"]: item for item in self.cached_data}
            current[server_name] = merge_storage_result(
                current.get(server_name),
                result,
            )
            self.cached_data = [
                current[name]
                if name in current
                else make_waiting_storage_result(name, user_min_bytes)
                for name in ordered_names
            ]

    def get_cached_data(self):
        with self.lock:
            return copy.deepcopy(self.cached_data)


storage_state = StorageStateStore()
storage_executor = ThreadPoolExecutor(max_workers=STORAGE_MAX_WORKERS)
shutdown_event = threading.Event()
_background_worker_thread = None
_background_worker_lock = threading.Lock()
_shutdown_lock = threading.Lock()


def _parse_storage_response(server, output, user_min_bytes=None):
    if user_min_bytes is None:
        user_min_bytes = get_storage_user_min_bytes()
    payload = json.loads(output.strip())
    if not isinstance(payload, dict):
        raise ValueError("Storage response must be an object")
    if not isinstance(payload.get("filesystem"), dict):
        raise ValueError("Storage response has no filesystem data")
    if not isinstance(payload.get("users"), list):
        raise ValueError("Storage response has no user data")
    filesystem = payload["filesystem"]
    normalized_filesystem = {"path": "/home"}
    for key in ("total", "used", "available", "percent"):
        value = filesystem.get(key)
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ValueError(f"Storage filesystem field {key} is invalid")
        normalized_filesystem[key] = max(0, value)
    normalized_filesystem["percent"] = min(
        100,
        normalized_filesystem["percent"],
    )

    users = []
    filtered_user_count = 0
    for item in payload["users"]:
        if not isinstance(item, dict) or not isinstance(item.get("username"), str):
            raise ValueError("Storage user record is invalid")
        used = item.get("used")
        if used is not None and (
            isinstance(used, bool) or not isinstance(used, (int, float))
        ):
            raise ValueError("Storage user usage is invalid")
        user = {
            "username": item["username"],
            "used": max(0, used) if used is not None else None,
        }
        if (
            user["used"] is not None
            and not item.get("error")
            and user["used"] < user_min_bytes
        ):
            filtered_user_count += 1
            continue
        if user["used"] is None or item.get("error"):
            user["error"] = str(item.get("error") or "unavailable")
        users.append(user)

    user_error_count = sum(1 for item in users if item.get("error"))
    return {
        "server": server["name"],
        "filesystem": normalized_filesystem,
        "users": users,
        "partial": bool(payload.get("partial")) or user_error_count > 0,
        "user_error_count": user_error_count,
        "user_min_bytes": user_min_bytes,
        "filtered_user_count": filtered_user_count,
        "error": None,
    }


def collect_storage_for_server(server, user_min_bytes=None):
    """Collect one server, falling back when passwordless sudo is unavailable."""
    last_message = "storage query failed"
    if user_min_bytes is None:
        user_min_bytes = get_storage_user_min_bytes()
    try:
        for use_sudo in (True, False):
            operation_name = "storage query" if use_sudo else "storage query without sudo"
            status, out, err = run_server_ssh_command_status(
                server,
                build_storage_command(use_sudo=use_sudo),
                timeout=STORAGE_COMMAND_TOTAL_TIMEOUT_SECONDS,
                total_timeout=STORAGE_COMMAND_TOTAL_TIMEOUT_SECONDS,
                operation_timeout=STORAGE_OPERATION_TIMEOUT_SECONDS,
                retry_on_transport=True,
                operation_name=operation_name,
                namespace="storage",
            )
            if status != 0:
                last_message = err.strip() or out.strip() or last_message
                continue
            try:
                return _parse_storage_response(
                    server,
                    out,
                    user_min_bytes=user_min_bytes,
                )
            except (json.JSONDecodeError, TypeError, ValueError) as error:
                last_message = str(error) or error.__class__.__name__

        return {
            "server": server["name"],
            "filesystem": None,
            "users": [],
            "partial": False,
            "user_error_count": 0,
            "user_min_bytes": user_min_bytes,
            "filtered_user_count": 0,
            "error": sanitize_error(last_message),
        }
    except Exception as error:
        message = str(error) or error.__class__.__name__
        logger.error("Error collecting storage for %s: %s", server["name"], message)
        return {
            "server": server["name"],
            "filesystem": None,
            "users": [],
            "partial": False,
            "user_error_count": 0,
            "user_min_bytes": user_min_bytes,
            "filtered_user_count": 0,
            "error": sanitize_error(message),
        }


def refresh_storage_data():
    servers = get_configured_servers()
    server_names = [server["name"] for server in servers]
    user_min_bytes = get_storage_user_min_bytes()
    storage_state.initialize_storage_cache(
        servers,
        user_min_bytes=user_min_bytes,
    )
    collect = partial(
        collect_storage_for_server,
        user_min_bytes=user_min_bytes,
    )
    futures = {
        storage_executor.submit(collect, server): server
        for server in servers
    }

    for future in as_completed(futures):
        server = futures[future]
        try:
            result = future.result()
        except Exception as error:
            message = str(error) or error.__class__.__name__
            logger.error("Unexpected storage error for %s: %s", server["name"], message)
            result = {
                "server": server["name"],
                "filesystem": None,
                "users": [],
                "partial": False,
                "user_error_count": 0,
                "user_min_bytes": user_min_bytes,
                "filtered_user_count": 0,
                "error": sanitize_error(message),
            }
        storage_state.publish_storage_result(result, server_names)

    logger.info("Refreshed storage data for %s servers", len(futures))
    return storage_state.get_cached_data()


def _get_storage_refresh_interval():
    value = get_monitoring_settings().get(
        "storage_refresh_interval",
        STORAGE_REFRESH_INTERVAL_SECONDS,
    )
    if isinstance(value, bool) or not isinstance(value, (int, float)) or value <= 0:
        return STORAGE_REFRESH_INTERVAL_SECONDS
    return float(value)


def background_worker():
    logger.info("Starting storage background worker")
    while not shutdown_event.is_set():
        try:
            refresh_storage_data()
        except Exception as error:
            logger.error("Error in storage background worker: %s", error)
        shutdown_event.wait(_get_storage_refresh_interval())


def start_background_worker():
    global _background_worker_thread

    with _background_worker_lock:
        if _background_worker_thread is not None and _background_worker_thread.is_alive():
            return _background_worker_thread
        if shutdown_event.is_set():
            raise RuntimeError("Storage collector runtime has been shut down")
        storage_state.initialize_storage_cache(get_configured_servers())
        _background_worker_thread = threading.Thread(
            target=background_worker,
            name="storage-background-worker",
            daemon=True,
        )
        _background_worker_thread.start()
        return _background_worker_thread


def wait_for_shutdown(timeout=2):
    thread = _background_worker_thread
    if thread is None or thread is threading.current_thread():
        return True
    thread.join(timeout=max(0, timeout))
    return not thread.is_alive()


def shutdown(timeout=2):
    """Stop the worker and reject new executor work; safe to call repeatedly."""
    with _shutdown_lock:
        if not shutdown_event.is_set():
            shutdown_event.set()
            storage_executor.shutdown(wait=False, cancel_futures=True)
    return wait_for_shutdown(timeout)
