import base64
import binascii
import hashlib
import logging
import os
import re
import threading
from pathlib import Path


logger = logging.getLogger(__name__)

USER_FILE_PATH = Path(__file__).resolve().parent.parent / "user.txt"
USERNAME_PATTERN = re.compile(r"^[a-z_][a-z0-9_-]*\$?$")
MAX_SSH_KEY_INPUT_SIZE = 16 * 1024
SSH_KEY_TYPES = {
    "ssh-ed25519",
    "ssh-rsa",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
}

user_file_lock = threading.RLock()
_user_store_generation = 0


def _bump_user_store_generation():
    global _user_store_generation
    with user_file_lock:
        _user_store_generation += 1


def get_user_store_generation():
    with user_file_lock:
        return _user_store_generation


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


def ssh_key_id(key):
    """Return a stable identifier for the cryptographic public key.

    Comments are intentionally excluded so that changing a key label does not
    make the same public key look like a different credential.
    """
    normalized = normalize_ssh_key(key)
    identity = ssh_key_identity(normalized) or normalized
    return key_fingerprint(identity)


def describe_ssh_key(key):
    normalized = normalize_ssh_key(key)
    parts = normalized.split()
    return {
        "key_id": ssh_key_id(normalized),
        "ssh_key": normalized,
        "key_type": parts[0] if parts else None,
        "comment": " ".join(parts[2:]) if len(parts) > 2 else "",
    }


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
    _bump_user_store_generation()


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
            _bump_user_store_generation()

    return {"username": username, "removed_lines": removed_lines}, 200


def remove_user_keys_from_file(username, key_ids):
    """Remove only selected keys for a user, identified independently of comments."""
    if not validate_username(username):
        return {"error": "invalid_username"}, 400
    if not isinstance(key_ids, (list, tuple, set)):
        return {"error": "key_ids_must_be_a_list"}, 400

    requested_key_ids = {
        key_id for key_id in key_ids if isinstance(key_id, str) and key_id
    }
    if not requested_key_ids:
        return {"error": "select_at_least_one_key"}, 400

    with user_file_lock:
        try:
            with open(USER_FILE_PATH) as f:
                lines = f.readlines()
        except FileNotFoundError:
            return {
                "username": username,
                "requested_key_count": len(requested_key_ids),
                "removed_keys": 0,
                "removed_lines": 0,
                "removed_key_ids": [],
                "remaining_key_count": 0,
            }, 200

        kept_lines = []
        removed_lines = 0
        removed_key_ids = set()
        remaining_key_ids = set()
        for line in lines:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                kept_lines.append(line)
                continue

            parts = stripped.split(None, 1)
            if len(parts) != 2 or parts[0] != username:
                kept_lines.append(line)
                continue

            key_id = ssh_key_id(parts[1])
            if key_id in requested_key_ids:
                removed_lines += 1
                removed_key_ids.add(key_id)
                continue

            remaining_key_ids.add(key_id)
            kept_lines.append(line)

        if removed_lines:
            tmp_path = USER_FILE_PATH.with_suffix(USER_FILE_PATH.suffix + ".tmp")
            with open(tmp_path, "w") as f:
                f.writelines(kept_lines)
            os.replace(tmp_path, USER_FILE_PATH)
            _bump_user_store_generation()

    return {
        "username": username,
        "requested_key_count": len(requested_key_ids),
        "removed_keys": len(removed_key_ids),
        "removed_lines": removed_lines,
        "removed_key_ids": sorted(removed_key_ids),
        "remaining_key_count": len(remaining_key_ids),
    }, 200


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
                            "key_ids": set(),
                            "ssh_keys": [],
                        }
                    users[username]["key_hashes"].add(fingerprint)
                    users[username]["key_ids"].add(ssh_key_id(ssh_key))
                    if ssh_key not in users[username]["ssh_keys"]:
                        users[username]["ssh_keys"].append(ssh_key)
        except FileNotFoundError:
            logger.error(f"User file not found: {USER_FILE_PATH}")

    return [
        {
            "username": user["username"],
            "key_hashes": sorted(user["key_hashes"]),
            "key_ids": sorted(user["key_ids"]),
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


def get_users_by_name():
    return {user["username"]: user for user in load_user_keys()}


def get_user_key_records(username):
    user = get_users_by_name().get(username)
    if user is None:
        return None

    records = []
    seen_key_ids = set()
    for ssh_key in user["ssh_keys"]:
        record = describe_ssh_key(ssh_key)
        if record["key_id"] in seen_key_ids:
            continue
        seen_key_ids.add(record["key_id"])
        records.append(record)
    return records
