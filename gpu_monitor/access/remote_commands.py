"""Build the Python commands executed on managed servers.

This module is deliberately side-effect free.  Keeping command construction here
makes the privileged remote behaviour easy to review without pulling in the web
application or the access-service state.
"""

import json

from gpu_monitor.user_store import normalize_ssh_key


MIN_MANAGED_UID = 1000
SYSTEM_SHELL_NAMES = {"false", "nologin", "sync", "halt", "shutdown"}


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


def build_revoke_user_command(
    username, ssh_keys, mode, clear_authorized_keys, remove_home
):
    normalized_keys = [
        normalize_ssh_key(key) for key in ssh_keys if normalize_ssh_key(key)
    ]
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
