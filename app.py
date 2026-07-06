import csv
import base64
import binascii
import hashlib
import io
import json
import os
import re
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
user_file_lock = threading.RLock()

cached_data = []
last_update = None
data_lock = threading.Lock()
executor = ThreadPoolExecutor(max_workers=10)
ssh_clients = {}
ssh_lock = threading.Lock()

_config_cache = None
_config_mtime = 0.0


def cleanup():
    logger.info("Cleaning up resources...")
    executor.shutdown(wait=False)
    with ssh_lock:
        for client in ssh_clients.values():
            try:
                client.close()
            except Exception as e:
                logger.debug(f"Error closing SSH client: {e}")
        ssh_clients.clear()


atexit.register(cleanup)


def load_config():
    global _config_cache, _config_mtime
    try:
        mtime = CONFIG_PATH.stat().st_mtime
        if _config_cache is not None and mtime == _config_mtime:
            return _config_cache
        with open(CONFIG_PATH) as f:
            _config_cache = json.load(f)
            _config_mtime = mtime
            return _config_cache
    except FileNotFoundError:
        logger.error(f"Config file not found: {CONFIG_PATH}")
        return {"servers": [], "refresh_interval": 5}
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in config file: {e}")
        return {"servers": [], "refresh_interval": 5}


def get_ssh_client(server):
    key = (server["host"], server["port"], server["username"])

    with ssh_lock:
        if key in ssh_clients:
            client = ssh_clients[key]
            if client.get_transport() and client.get_transport().is_active():
                return client
            try:
                client.close()
            except Exception as e:
                logger.debug(f"Error closing stale SSH client: {e}")
            del ssh_clients[key]

    new_client = paramiko.SSHClient()
    new_client.load_system_host_keys()
    if server.get("accept_unknown_host", False):
        new_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    key_file = os.path.expanduser(server["key_file"])
    new_client.connect(
        hostname=server["host"],
        port=server["port"],
        username=server["username"],
        key_filename=key_file,
        timeout=10,
        banner_timeout=10,
    )
    transport = new_client.get_transport()
    if transport:
        transport.set_keepalive(30)

    with ssh_lock:
        if key in ssh_clients:
            old = ssh_clients[key]
            if old.get_transport() and old.get_transport().is_active():
                new_client.close()
                return old
            try:
                old.close()
            except Exception:
                pass
        ssh_clients[key] = new_client
        return new_client


def invalidate_ssh_client(server):
    key = (server["host"], server["port"], server["username"])
    with ssh_lock:
        if key in ssh_clients:
            try:
                ssh_clients[key].close()
            except Exception:
                pass
            del ssh_clients[key]


def run_ssh_command(client, command, timeout=30):
    stdin = stdout = stderr = None
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode()
        err = stderr.read().decode()
        return out, err
    finally:
        for ch in (stdin, stdout, stderr):
            if ch is not None:
                try:
                    ch.close()
                except Exception:
                    pass


def run_ssh_command_status(client, command, timeout=30):
    stdin = stdout = stderr = None
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode()
        err = stderr.read().decode()
        status = stdout.channel.recv_exit_status()
        return status, out, err
    finally:
        for ch in (stdin, stdout, stderr):
            if ch is not None:
                try:
                    ch.close()
                except Exception:
                    pass


def sanitize_error(error_msg):
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

    return {
        "error": None,
        "imported": imported,
        "skipped": skipped,
        "errors": errors,
    }, 200


def get_servers_by_name():
    config = load_config()
    servers = config.get("servers", [])
    if not isinstance(servers, list):
        return {}
    return {
        server["name"]: server
        for server in servers
        if isinstance(server, dict) and isinstance(server.get("name"), str)
    }


def get_configured_servers():
    config = load_config()
    servers = config.get("servers", [])
    if not isinstance(servers, list):
        return []
    return [
        server
        for server in servers
        if isinstance(server, dict) and isinstance(server.get("name"), str)
    ]


def get_refresh_interval():
    config = load_config()
    interval = config.get("refresh_interval", 5)
    return interval if isinstance(interval, (int, float)) else 5


def get_users_by_name():
    return {user["username"]: user for user in load_user_keys()}


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
        proc = run(["useradd", "-m", "-s", "/bin/bash", username])
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
        client = get_ssh_client(server)
        status, out, err = run_ssh_command_status(
            client, build_configure_users_command(users), timeout=120
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
        invalidate_ssh_client(server)
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
        executor.submit(configure_access_for_server, server, selected_users): server
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
        futures[executor.submit(configure_access_for_server, server, selected_users)] = server

    results = []
    for future in as_completed(futures):
        server = futures[future]
        try:
            results.append(future.result())
        except Exception as e:
            logger.error(f"Unexpected configure error for {server['name']}: {e}")
            results.append({"server": server["name"], "error": sanitize_error(str(e)), "users": {}})

    results.sort(key=lambda item: item["server"])
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
        client = get_ssh_client(server)
        status, out, err = run_ssh_command_status(
            client, build_detect_users_command(use_sudo=True), timeout=45
        )
        if status != 0:
            status, out, err = run_ssh_command_status(
                client, build_detect_users_command(use_sudo=False), timeout=45
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
        invalidate_ssh_client(server)
        return {"server": server["name"], "error": sanitize_error(str(e)), "users": []}


def detect_server_users(server_names=None):
    selected_servers, error = resolve_selected_servers(server_names)
    if error:
        return {**error, "results": []}, 400

    futures = {
        executor.submit(detect_users_for_server, server): server
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
import pwd
import shutil
import subprocess

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
    "password_locked": False,
    "deleted": False,
    "errors": [],
}}

try:
    entry = pwd.getpwnam(username)
    result["user_exists"] = True
    result["uid"] = entry.pw_uid
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
    args = ["userdel"]
    if remove_home:
        args.append("-r")
    args.append(username)
    proc = run(args)
    if proc.returncode == 0:
        result["deleted"] = True
    else:
        result["errors"].append(proc.stderr.strip() or "userdel_failed")

print(json.dumps(result, ensure_ascii=False))
"""
    return f"sudo -n python3 - <<'PY'\n{script}\nPY"


def revoke_user_on_server(server, username, ssh_keys, mode, clear_authorized_keys, remove_home):
    try:
        client = get_ssh_client(server)
        status, out, err = run_ssh_command_status(
            client,
            build_revoke_user_command(username, ssh_keys, mode, clear_authorized_keys, remove_home),
            timeout=120,
        )
        if status != 0:
            message = err.strip() or out.strip() or "revoke user command failed"
            return {"server": server["name"], "error": sanitize_error(message), "result": {}}
        return {"server": server["name"], "error": None, "result": json.loads(out)}
    except Exception as e:
        logger.error(f"Error revoking user {username} for {server['name']}: {e}")
        invalidate_ssh_client(server)
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
        executor.submit(
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
        client = get_ssh_client(server)
        status, out, err = run_ssh_command_status(
            client, build_access_check_command(usernames, use_sudo=True), timeout=30
        )
        if status != 0:
            status, out, err = run_ssh_command_status(
                client, build_access_check_command(usernames, use_sudo=False), timeout=30
            )
        if status != 0:
            message = err.strip() or out.strip() or "access check command failed"
            return {"server": server["name"], "error": sanitize_error(message), "users": {}}

        remote_users = json.loads(out)
        return {"server": server["name"], "error": None, "users": remote_users}
    except Exception as e:
        logger.error(f"Error checking user access for {server['name']}: {e}")
        invalidate_ssh_client(server)
        return {"server": server["name"], "error": sanitize_error(str(e)), "users": {}}


def build_access_matrix():
    users = load_user_keys()
    servers = get_configured_servers()

    matrix = {
        "servers": [{"name": server["name"]} for server in servers],
        "users": [
            {"username": user["username"], "key_count": len(user["key_hashes"]), "servers": []}
            for user in users
        ],
    }

    if not users or not servers:
        return matrix

    futures = {
        executor.submit(check_access_matrix_for_server, server, users): server
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

    return matrix


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


def get_gpu_info_ssh(server):
    try:
        client = get_ssh_client(server)

        gpu_fields = "index,gpu_bus_id,name,utilization.gpu,memory.used,memory.total"
        out, err = run_ssh_command(
            client,
            f"nvidia-smi --query-gpu={gpu_fields} --format=csv,noheader,nounits",
        )
        if not out.strip():
            error_msg = err.strip() if err else "No GPU info returned"
            logger.error(f"nvidia-smi error on {server['name']}: {error_msg}")
            return {"error": sanitize_error(error_msg), "server": server["name"]}

        gpus, bus_to_idx = parse_gpu_query(out)

        proc_out, _ = run_ssh_command(
            client,
            "nvidia-smi --query-compute-apps=gpu_bus_id,pid,used_gpu_memory --format=csv,noheader",
        )
        parse_compute_apps(proc_out, bus_to_idx, gpus)

        pids = []
        for gpu in gpus.values():
            for proc in gpu["processes"]:
                pids.append(str(proc["pid"]))

        if pids:
            pid_list = ",".join(pids)
            ps_out, _ = run_ssh_command(
                client,
                f"ps -o pid=,user= -p {pid_list} 2>/dev/null",
            )
            if ps_out:
                user_map = {}
                for line in ps_out.strip().split("\n"):
                    if line.strip():
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            user_map[parts[0]] = parts[1]
                for gpu in gpus.values():
                    for proc in gpu["processes"]:
                        if str(proc["pid"]) in user_map:
                            proc["user"] = user_map[str(proc["pid"])]

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
                {"user": u, "memory": m} for u, m in user_memory.items()
            ]

        return {
            "server": server["name"],
            "gpus": sorted(gpus.values(), key=lambda x: x["index"]),
            "error": None,
        }
    except Exception as e:
        logger.error(f"Error getting GPU info for {server['name']}: {e}")
        invalidate_ssh_client(server)
        return {"error": sanitize_error(str(e)), "server": server["name"]}


def refresh_data():
    global cached_data, last_update

    servers = get_configured_servers()
    results = []

    futures = {
        executor.submit(get_gpu_info_ssh, server): server
        for server in servers
    }
    for future in as_completed(futures):
        try:
            results.append(future.result())
        except Exception as e:
            server = futures[future]
            logger.error(f"Unexpected error for {server['name']}: {e}")
            results.append({"error": sanitize_error(str(e)), "server": server["name"]})

    results.sort(key=lambda x: x["server"])

    with data_lock:
        cached_data = results
        last_update = time.time()

    logger.info(f"Refreshed data for {len(results)} servers")


def background_worker():
    logger.info("Starting background worker")
    while True:
        try:
            refresh_data()
        except Exception as e:
            logger.error(f"Error in background worker: {e}")
        time.sleep(get_refresh_interval())


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
    return jsonify(
        {"servers": servers, "refresh_interval": get_refresh_interval()}
    )


@app.route("/api/access-matrix")
def get_access_matrix():
    return jsonify(build_access_matrix())


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
    refresh_data()

    worker_thread = threading.Thread(target=background_worker, daemon=True)
    worker_thread.start()

    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    logger.info(f"Running Flask app on 0.0.0.0:5000 (debug={debug})")
    app.run(host="0.0.0.0", port=5000, debug=debug)
