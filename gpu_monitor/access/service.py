"""Business operations for managing remote user access."""

import copy
import json
import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from gpu_monitor.access.remote_commands import (
    build_access_check_command,
    build_configure_users_command,
    build_detect_users_command,
    build_revoke_user_command,
)
from gpu_monitor.config import (
    CONFIG_PATH,
    get_configured_servers,
    get_file_signature,
    get_servers_by_name,
)
from gpu_monitor.ssh import run_server_ssh_command_status, sanitize_error
from gpu_monitor.user_store import (
    USER_FILE_PATH,
    annotate_discovered_users,
    get_user_store_generation,
    get_users_by_name,
    load_user_keys,
    remove_user_from_file,
    validate_username,
)


logger = logging.getLogger(__name__)

ADMIN_MAX_WORKERS = 4
ACCESS_MATRIX_CACHE_TTL = 30
ACCESS_MATRIX_CACHE_MAX_ENTRIES = 64
PROTECTED_USERNAMES = {"root"}

admin_executor = ThreadPoolExecutor(max_workers=ADMIN_MAX_WORKERS)
access_matrix_cache = {}
access_matrix_cache_lock = threading.Lock()


def shutdown():
    """Stop accepting new administrative work during application shutdown."""
    admin_executor.shutdown(wait=False, cancel_futures=True)


def wait_for_shutdown(timeout=2):
    """Wait for in-flight admin work without making process cleanup unbounded."""
    completed = threading.Event()

    def wait_for_executor():
        try:
            admin_executor.shutdown(wait=True, cancel_futures=True)
        finally:
            completed.set()

    waiter = threading.Thread(
        target=wait_for_executor,
        name="admin-executor-shutdown",
        daemon=True,
    )
    waiter.start()
    return completed.wait(max(0, timeout))


def invalidate_access_matrix_cache():
    with access_matrix_cache_lock:
        access_matrix_cache.clear()


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
            return {
                "server": server["name"],
                "error": sanitize_error(message),
                "users": {},
            }

        return {
            "server": server["name"],
            "error": None,
            "users": json.loads(out),
        }
    except Exception as e:
        logger.error("Error configuring user access for %s: %s", server["name"], e)
        return {
            "server": server["name"],
            "error": sanitize_error(str(e)),
            "users": {},
        }


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
        admin_executor.submit(
            configure_access_for_server, server, selected_users
        ): server
        for server in selected_servers
    }
    results = []
    for future in as_completed(futures):
        server = futures[future]
        try:
            results.append(future.result())
        except Exception as e:
            logger.error("Unexpected configure error for %s: %s", server["name"], e)
            results.append(
                {
                    "server": server["name"],
                    "error": sanitize_error(str(e)),
                    "users": {},
                }
            )

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
            return {
                "error": "pair_server_and_user_must_be_strings",
                "results": [],
            }, 400
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
        futures[
            admin_executor.submit(
                configure_access_for_server, server, selected_users
            )
        ] = server

    results = []
    for future in as_completed(futures):
        server = futures[future]
        try:
            results.append(future.result())
        except Exception as e:
            logger.error("Unexpected configure error for %s: %s", server["name"], e)
            results.append(
                {
                    "server": server["name"],
                    "error": sanitize_error(str(e)),
                    "users": {},
                }
            )

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
        return None, {
            "error": "invalid_selection",
            "unknown_servers": unknown_servers,
        }
    return [servers_by_name[name] for name in clean_names], None


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
            return {
                "server": server["name"],
                "error": sanitize_error(message),
                "users": [],
            }

        users = json.loads(out)
        users = [
            user for user in users if validate_username(user.get("username", ""))
        ]
        users.sort(key=lambda item: item["username"])
        return {"server": server["name"], "error": None, "users": users}
    except Exception as e:
        logger.error("Error detecting users for %s: %s", server["name"], e)
        return {
            "server": server["name"],
            "error": sanitize_error(str(e)),
            "users": [],
        }


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
            logger.error("Unexpected detect error for %s: %s", server["name"], e)
            results.append(
                {
                    "server": server["name"],
                    "error": sanitize_error(str(e)),
                    "users": [],
                }
            )

    results.sort(key=lambda item: item["server"])
    return {"error": None, "results": annotate_discovered_users(results)}, 200


def revoke_user_on_server(
    server, username, ssh_keys, mode, clear_authorized_keys, remove_home
):
    try:
        status, out, err = run_server_ssh_command_status(
            server,
            build_revoke_user_command(
                username, ssh_keys, mode, clear_authorized_keys, remove_home
            ),
            timeout=120,
            total_timeout=240,
            operation_timeout=360,
            retry_on_transport=False,
            operation_name="revoke user access",
        )
        if status != 0:
            message = err.strip() or out.strip() or "revoke user command failed"
            return {
                "server": server["name"],
                "error": sanitize_error(message),
                "result": {},
            }
        return {
            "server": server["name"],
            "error": None,
            "result": json.loads(out),
        }
    except Exception as e:
        logger.error("Error revoking user %s for %s: %s", username, server["name"], e)
        return {
            "server": server["name"],
            "error": sanitize_error(str(e)),
            "result": {},
        }


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
        if local_result.get("removed_lines"):
            invalidate_access_matrix_cache()
        return {"error": None, "local": local_result, "results": []}, 200

    selected_servers, error = resolve_selected_servers(
        payload.get("servers"), allow_empty=True
    )
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
            logger.error("Unexpected delete error for %s: %s", server["name"], e)
            results.append(
                {
                    "server": server["name"],
                    "error": sanitize_error(str(e)),
                    "result": {},
                }
            )

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
            return {
                "server": server["name"],
                "error": sanitize_error(message),
                "users": {},
            }

        remote_users = json.loads(out)
        return {"server": server["name"], "error": None, "users": remote_users}
    except Exception as e:
        logger.error("Error checking user access for %s: %s", server["name"], e)
        return {
            "server": server["name"],
            "error": sanitize_error(str(e)),
            "users": {},
        }


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
        get_user_store_generation(),
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
    servers, users, scope, error = resolve_access_matrix_scope(
        server_names, usernames
    )
    if error:
        return {**error, "servers": [], "users": []}, 400

    cache_key = access_matrix_cache_key(servers, users)
    cached = get_cached_access_matrix(cache_key)
    if cached:
        return cached, 200

    matrix = {
        "servers": [{"name": server["name"]} for server in servers],
        "users": [
            {
                "username": user["username"],
                "key_count": len(user["key_hashes"]),
                "servers": [],
            }
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
            logger.error("Unexpected access check error for %s: %s", server["name"], e)
            result = {
                "server": server["name"],
                "error": sanitize_error(str(e)),
                "users": {},
            }
        server_results[result["server"]] = result

    for user_item, source_user in zip(matrix["users"], users):
        expected_hashes = set(source_user["key_hashes"])
        for server in servers:
            server_name = server["name"]
            server_result = server_results.get(
                server_name, {"error": "No result", "users": {}}
            )
            remote_user = server_result.get("users", {}).get(
                source_user["username"], {}
            )
            installed_hashes = set(remote_user.get("authorized_key_hashes", []))
            matching_keys = len(expected_hashes & installed_hashes)
            key_installed = (
                matching_keys > 0
                if remote_user.get("authorized_keys_readable")
                else None
            )
            user_item["servers"].append(
                {
                    "server": server_name,
                    "user_exists": bool(remote_user.get("user_exists")),
                    "key_installed": key_installed,
                    "accessible": bool(remote_user.get("user_exists"))
                    and key_installed is True,
                    "matching_key_count": matching_keys,
                    "error": server_result.get("error") or remote_user.get("error"),
                }
            )

    set_cached_access_matrix(cache_key, matrix)
    return matrix, 200
