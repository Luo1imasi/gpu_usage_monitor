"""Build the Python commands executed on managed servers.

This module is deliberately side-effect free.  Keeping command construction here
makes the privileged remote behaviour easy to review without pulling in the web
application or the access-service state.
"""

import json

from gpu_monitor.user_store import SSH_KEY_TYPES, normalize_ssh_key, ssh_key_id


MIN_MANAGED_UID = 1000
SYSTEM_SHELL_NAMES = {"false", "nologin", "sync", "halt", "shutdown"}


def _public_key_identity_helper_source():
    """Return shared remote code for strict authorized_keys identity parsing."""
    return f"""
import base64
import binascii

key_types = set({json.dumps(sorted(SSH_KEY_TYPES))})

def authorized_key_prefix_fields(line):
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return []

    in_quotes = False
    escaped = False
    for index, char in enumerate(stripped):
        if escaped:
            escaped = False
            continue
        if char == "\\\\":
            escaped = True
            continue
        if char == '\"':
            in_quotes = not in_quotes
            continue
        if char.isspace() and not in_quotes:
            first_field = stripped[:index]
            remaining = stripped[index:].strip().split(None, 2)
            return [first_field] + remaining[:2]
    return [stripped]

def public_key_identity(line):
    parts = authorized_key_prefix_fields(line)
    for index, candidate_type in enumerate(parts[:-1]):
        key_body = parts[index + 1]
        try:
            decoded = base64.b64decode(key_body.encode(), validate=True)
        except (ValueError, binascii.Error):
            continue
        if len(decoded) < 4:
            continue
        type_length = int.from_bytes(decoded[:4], "big")
        if type_length <= 0 or type_length > len(decoded) - 4:
            continue
        try:
            embedded_type = decoded[4 : 4 + type_length].decode()
        except UnicodeDecodeError:
            continue
        if embedded_type != candidate_type:
            continue
        if candidate_type not in key_types:
            return None
        return candidate_type + " " + key_body
    return None
"""


def _authorized_keys_lock_helper_source():
    """Return remote code that serializes writers on one opened key file."""
    return """
import fcntl
import os
from contextlib import contextmanager

@contextmanager
def locked_authorized_keys_file(file_fd):
    fcntl.flock(file_fd, fcntl.LOCK_EX)
    try:
        yield
    finally:
        fcntl.flock(file_fd, fcntl.LOCK_UN)

def same_open_entry(file_fd, directory_fd, name):
    opened_stat = os.fstat(file_fd)
    try:
        named_stat = os.stat(
            name,
            dir_fd=directory_fd,
            follow_symlinks=False,
        )
    except FileNotFoundError:
        return False
    return (
        named_stat.st_dev == opened_stat.st_dev
        and named_stat.st_ino == opened_stat.st_ino
    )
"""


def build_configure_users_command(users):
    safe_users = [
        {"username": user["username"], "ssh_keys": user["ssh_keys"]}
        for user in users
    ]
    identity_helper = _public_key_identity_helper_source()
    lock_helper = _authorized_keys_lock_helper_source()
    script = f"""
import json
import os
import pwd
import re
import stat
import subprocess

{identity_helper}
{lock_helper}

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

        home_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
        home_fd = os.open(user_home, home_flags)
        ssh_fd = None
        auth_fd = None
        try:
            ssh_flags = (
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                ssh_fd = os.open(".ssh", ssh_flags, dir_fd=home_fd)
            except FileNotFoundError:
                try:
                    os.mkdir(".ssh", mode=0o700, dir_fd=home_fd)
                except FileExistsError:
                    pass
                ssh_fd = os.open(".ssh", ssh_flags, dir_fd=home_fd)

            ssh_stat = os.fstat(ssh_fd)
            if not stat.S_ISDIR(ssh_stat.st_mode):
                raise OSError("ssh_directory_not_directory")
            if not same_open_entry(ssh_fd, home_fd, ".ssh"):
                raise OSError("ssh_directory_changed")
            os.fchmod(ssh_fd, 0o700)
            os.fchown(ssh_fd, entry.pw_uid, entry.pw_gid)

            auth_flags = (
                os.O_RDWR
                | os.O_APPEND
                | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                auth_fd = os.open(
                    "authorized_keys",
                    auth_flags,
                    dir_fd=ssh_fd,
                )
            except FileNotFoundError:
                auth_fd = os.open(
                    "authorized_keys",
                    auth_flags | os.O_CREAT | os.O_EXCL,
                    0o600,
                    dir_fd=ssh_fd,
                )

            with locked_authorized_keys_file(auth_fd):
                opened_stat = os.fstat(auth_fd)
                if not stat.S_ISREG(opened_stat.st_mode):
                    raise OSError("authorized_keys_not_regular")
                if (
                    not same_open_entry(ssh_fd, home_fd, ".ssh")
                    or not same_open_entry(
                        auth_fd, ssh_fd, "authorized_keys"
                    )
                ):
                    raise OSError("authorized_keys_changed")

                os.fchmod(auth_fd, 0o600)
                os.fchown(auth_fd, entry.pw_uid, entry.pw_gid)
                original_size = opened_stat.st_size
                existing_content = b""
                while len(existing_content) < original_size:
                    chunk = os.pread(
                        auth_fd,
                        original_size - len(existing_content),
                        len(existing_content),
                    )
                    if not chunk:
                        break
                    existing_content += chunk
                if len(existing_content) != original_size:
                    raise OSError("authorized_keys_changed")

                existing_key_identities = set()
                for line in existing_content.decode(
                    "utf-8", "surrogateescape"
                ).splitlines():
                    identity = public_key_identity(line)
                    if identity is not None:
                        existing_key_identities.add(identity)

                for ssh_key in ssh_keys:
                    normalized_key = " ".join(ssh_key.strip().split())
                    identity = public_key_identity(normalized_key)
                    if identity is not None and identity in existing_key_identities:
                        result["keys_already_present"] += 1
                        continue
                    # Keep this key on its own line even if another writer
                    # concurrently appended an unterminated line.
                    encoded_key = b"\\n" + (normalized_key + "\\n").encode()
                    if os.write(auth_fd, encoded_key) != len(encoded_key):
                        raise OSError("authorized_keys_short_write")
                    if identity is not None:
                        existing_key_identities.add(identity)
                    result["keys_added"] += 1
                os.fsync(auth_fd)

                if (
                    not same_open_entry(ssh_fd, home_fd, ".ssh")
                    or not same_open_entry(
                        auth_fd, ssh_fd, "authorized_keys"
                    )
                ):
                    raise OSError("authorized_keys_changed")
        finally:
            if auth_fd is not None:
                os.close(auth_fd)
            if ssh_fd is not None:
                os.close(ssh_fd)
            os.close(home_fd)
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


def build_remove_user_keys_command(username, ssh_keys):
    """Build a narrowly scoped command that only removes selected SSH keys."""
    selected_key_ids = sorted(
        {
            ssh_key_id(key)
            for key in ssh_keys
            if isinstance(key, str) and normalize_ssh_key(key)
        }
    )
    identity_helper = _public_key_identity_helper_source()
    lock_helper = _authorized_keys_lock_helper_source()
    script = f"""
import hashlib
import json
import os
import pwd
import stat

{identity_helper}
{lock_helper}

username = {json.dumps(username)}
selected_key_ids = set({json.dumps(selected_key_ids)})

result = {{
    "user_exists": False,
    "uid": None,
    "authorized_keys_exists": False,
    "requested_key_count": len(selected_key_ids),
    "keys_removed": 0,
    "removed_key_ids": [],
    "errors": [],
}}

def public_key_id(line):
    identity = public_key_identity(line)
    if identity is None:
        return None
    return hashlib.sha256(identity.encode()).hexdigest()

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

def read_prefix(file_fd, size):
    content = b""
    while len(content) < size:
        chunk = os.pread(file_fd, size - len(content), len(content))
        if not chunk:
            break
        content += chunk
    return content

def revoked_line(line):
    if line.endswith(b"\\r\\n"):
        body = line[:-2]
        ending = b"\\r\\n"
    elif line.endswith((b"\\n", b"\\r")):
        body = line[:-1]
        ending = line[-1:]
    else:
        body = line
        ending = b""
    if not body:
        return line
    marker = b"# gpu-monitor revoked"
    if len(body) < len(marker):
        marker = b"#"
    return marker + (b" " * (len(body) - len(marker))) + ending

home_fd = None
ssh_fd = None
auth_fd = None
try:
    home_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        home_fd = os.open(entry.pw_dir, home_flags)
    except FileNotFoundError:
        home_fd = None

    if home_fd is not None:
        ssh_flags = (
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            ssh_fd = os.open(".ssh", ssh_flags, dir_fd=home_fd)
        except FileNotFoundError:
            ssh_fd = None

    if ssh_fd is not None:
        auth_flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0)
        try:
            auth_fd = os.open(
                "authorized_keys",
                auth_flags,
                dir_fd=ssh_fd,
            )
        except FileNotFoundError:
            auth_fd = None

    if auth_fd is not None:
        result["authorized_keys_exists"] = True
        with locked_authorized_keys_file(auth_fd):
            ssh_stat = os.fstat(ssh_fd)
            opened_stat = os.fstat(auth_fd)
            if not stat.S_ISDIR(ssh_stat.st_mode):
                raise OSError("ssh_directory_not_directory")
            if not stat.S_ISREG(opened_stat.st_mode):
                raise OSError("authorized_keys_not_regular")
            if (
                not same_open_entry(ssh_fd, home_fd, ".ssh")
                or not same_open_entry(
                    auth_fd, ssh_fd, "authorized_keys"
                )
            ):
                result["errors"].append("authorized_keys_changed")
            else:
                original_size = opened_stat.st_size
                original_content = read_prefix(auth_fd, original_size)
                if len(original_content) != original_size:
                    result["errors"].append("authorized_keys_changed")
                else:
                    replacements = []
                    offset = 0
                    for line in original_content.splitlines(keepends=True):
                        key_id = public_key_id(
                            line.decode("utf-8", "surrogateescape")
                        )
                        if key_id is not None and key_id in selected_key_ids:
                            replacements.append(
                                (offset, line, revoked_line(line), key_id)
                            )
                        offset += len(line)

                    prefix_unchanged = (
                        same_open_entry(ssh_fd, home_fd, ".ssh")
                        and same_open_entry(
                            auth_fd, ssh_fd, "authorized_keys"
                        )
                        and os.fstat(auth_fd).st_size >= original_size
                        and read_prefix(auth_fd, original_size) == original_content
                    )
                    if not prefix_unchanged:
                        result["errors"].append("authorized_keys_changed")
                    else:
                        removed_key_ids = set()
                        for offset, original_line, replacement, key_id in replacements:
                            if (
                                os.pread(auth_fd, len(original_line), offset)
                                != original_line
                            ):
                                result["errors"].append("authorized_keys_changed")
                                break
                            written = os.pwrite(auth_fd, replacement, offset)
                            if written != len(replacement):
                                raise OSError("authorized_keys_short_write")
                            result["keys_removed"] += 1
                            removed_key_ids.add(key_id)
                        if replacements:
                            os.fsync(auth_fd)
                        result["removed_key_ids"] = sorted(removed_key_ids)
                        if (
                            not same_open_entry(ssh_fd, home_fd, ".ssh")
                            or not same_open_entry(
                                auth_fd, ssh_fd, "authorized_keys"
                            )
                        ):
                            result["errors"].append("authorized_keys_changed")
except Exception as exc:
    result["errors"].append("authorized_keys_" + exc.__class__.__name__)
finally:
    if auth_fd is not None:
        os.close(auth_fd)
    if ssh_fd is not None:
        os.close(ssh_fd)
    if home_fd is not None:
        os.close(home_fd)

print(json.dumps(result, ensure_ascii=False))
"""
    return f"sudo -n python3 - <<'PY'\n{script}\nPY"


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
    identity_helper = _public_key_identity_helper_source()
    script = f"""
import hashlib
import json
import os
import pwd

{identity_helper}

usernames = {json.dumps(usernames)}
results = {{}}

def public_key_id(line):
    identity = public_key_identity(line)
    if identity is None:
        return None
    return hashlib.sha256(identity.encode()).hexdigest()

for username in usernames:
    item = {{
        "user_exists": False,
        "authorized_keys_readable": False,
        "authorized_key_hashes": [],
        "authorized_key_ids": [],
        "authorized_key_count": 0,
        "error": None,
    }}
    try:
        entry = pwd.getpwnam(username)
        item["user_exists"] = True
        auth_keys = os.path.join(entry.pw_dir, ".ssh", "authorized_keys")
        try:
            with open(auth_keys) as f:
                hashes = []
                key_ids = []
                for line in f:
                    normalized = " ".join(line.strip().split())
                    if normalized and not normalized.startswith("#"):
                        hashes.append(hashlib.sha256(normalized.encode()).hexdigest())
                        key_id = public_key_id(normalized)
                        if key_id is not None:
                            key_ids.append(key_id)
                item["authorized_keys_readable"] = True
                item["authorized_key_hashes"] = sorted(set(hashes))
                item["authorized_key_ids"] = sorted(set(key_ids))
                item["authorized_key_count"] = len(item["authorized_key_ids"])
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
