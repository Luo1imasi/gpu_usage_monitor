import base64
import unittest

from gpu_monitor.access import remote_commands
from gpu_monitor.access.remote_commands import (
    build_access_check_command,
    build_configure_users_command,
    build_remove_user_keys_command,
)
from gpu_monitor.user_store import ssh_key_id, ssh_key_identity


def make_public_key(comment="test-key"):
    key_type = b"ssh-ed25519"
    payload = len(key_type).to_bytes(4, "big") + key_type + b"test-payload"
    return f"ssh-ed25519 {base64.b64encode(payload).decode()} {comment}"


class RemoteCommandTests(unittest.TestCase):
    def test_identity_parser_ignores_options_and_comments(self):
        ssh_key = make_public_key("laptop")
        namespace = {}
        exec(remote_commands._public_key_identity_helper_source(), namespace)

        identity = namespace["public_key_identity"](
            'command="echo ssh-ed25519 not-a-key",no-agent-forwarding '
            + ssh_key
            + " renamed"
        )

        self.assertEqual(identity, ssh_key_identity(ssh_key))

    def test_key_removal_command_is_narrowly_scoped_and_supports_options(self):
        ssh_key = "ssh-ed25519 key-body laptop"
        command = build_remove_user_keys_command("alice", [ssh_key])

        self.assertIn(ssh_key_id(ssh_key), command)
        self.assertIn("for index, key_type in enumerate(parts[:-1])", command)
        self.assertIn("base64.b64decode(key_body.encode(), validate=True)", command)
        self.assertIn("embedded_type == key_type", command)
        self.assertIn("os.lstat(auth_keys)", command)
        self.assertIn("stat.S_ISREG", command)
        self.assertIn("kept_lines.append(line)", command)
        for forbidden in (
            "/etc/sudoers.d",
            "gpasswd",
            "passwd",
            "userdel",
            "usermod",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, command)

        script = command.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
        compile(script, "<remove-user-keys>", "exec")

    def test_access_check_reports_identity_key_ids(self):
        command = build_access_check_command(["alice"])

        self.assertIn('"authorized_key_ids": []', command)
        self.assertIn('"authorized_key_count": 0', command)
        self.assertIn("identity = public_key_identity(line)", command)

    def test_configure_command_deduplicates_by_validated_key_identity(self):
        command = build_configure_users_command(
            [{"username": "alice", "ssh_keys": ["ssh-ed25519 body comment"]}]
        )

        self.assertIn("existing_key_identities", command)
        self.assertIn("identity = public_key_identity(line)", command)
        self.assertIn("identity = public_key_identity(normalized_key)", command)
        self.assertIn("base64.b64decode(key_body.encode(), validate=True)", command)
        script = command.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
        compile(script, "<configure-users>", "exec")


if __name__ == "__main__":
    unittest.main()
