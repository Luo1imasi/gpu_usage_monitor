import json
import logging
from pathlib import Path


logger = logging.getLogger(__name__)

CONFIG_PATH = Path(__file__).resolve().parent.parent / "config.json"

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

GPU_COLLECTOR_RECONCILE_SECONDS = 2
GPU_COLLECTOR_RETRY_BACKOFF_MAX_SECONDS = 60
GPU_MAX_WORKERS = 8
STORAGE_REFRESH_INTERVAL_SECONDS = 300
STORAGE_USER_MIN_SIZE_MB = 100

_config_cache = None
_config_signature = None


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
            return _config_cache
    except FileNotFoundError:
        logger.error(f"Config file not found: {CONFIG_PATH}")
        return _config_cache or {"servers": []}
    except (json.JSONDecodeError, ValueError) as e:
        logger.error(f"Invalid JSON in config file: {e}")
        return _config_cache or {"servers": []}


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

    collector_mode = settings.get("collector_mode", "stream")
    if collector_mode not in {"stream", "poll", "batch"}:
        collector_mode = "stream"

    return {
        "refresh_interval": get_bounded_number(
            settings,
            "refresh_interval_seconds",
            30,
            1,
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
        "storage_refresh_interval": get_bounded_number(
            settings,
            "storage_refresh_interval_seconds",
            STORAGE_REFRESH_INTERVAL_SECONDS,
            60,
            3600,
        ),
        "storage_user_min_size_mb": get_bounded_number(
            settings,
            "storage_user_min_size_mb",
            STORAGE_USER_MIN_SIZE_MB,
            0,
            1024 * 1024,
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


def get_file_signature(path):
    try:
        stat = path.stat()
        return stat.st_mtime_ns, stat.st_size
    except FileNotFoundError:
        return None


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
