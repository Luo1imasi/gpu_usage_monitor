import base64
import contextlib
import fcntl
import io
import json
import os
import pwd
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from gpu_monitor.access import remote_commands
from gpu_monitor.access.remote_commands import (
    build_access_check_command,
    build_configure_users_command,
    build_remove_user_keys_command,
)
from gpu_monitor.user_store import ssh_key_id, ssh_key_identity


def make_public_key(comment="test-key", payload=b"test-payload"):
    key_type = b"ssh-ed25519"
    wire_payload = len(key_type).to_bytes(4, "big") + key_type + payload
    return f"ssh-ed25519 {base64.b64encode(wire_payload).decode()} {comment}"


class RemoteCommandTests(unittest.TestCase):
    def execute_remove_command(
        self,
        home,
        selected_keys,
        open_hook=None,
        pwrite_hook=None,
    ):
        command = build_remove_user_keys_command("alice", selected_keys)
        script = command.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
        output = io.StringIO()
        original_open = os.open
        original_pwrite = os.pwrite

        with contextlib.ExitStack() as stack:
            stack.enter_context(
                patch.object(
                    pwd,
                    "getpwnam",
                    return_value=SimpleNamespace(pw_uid=1000, pw_dir=home),
                )
            )
            if open_hook is not None:
                stack.enter_context(
                    patch.object(
                        os,
                        "open",
                        side_effect=lambda *args, **kwargs: open_hook(
                            original_open, *args, **kwargs
                        ),
                    )
                )
            if pwrite_hook is not None:
                stack.enter_context(
                    patch.object(
                        os,
                        "pwrite",
                        side_effect=lambda *args: pwrite_hook(
                            original_pwrite, *args
                        ),
                    )
                )
            with contextlib.redirect_stdout(output):
                exec(compile(script, "<remove-user-keys>", "exec"), {})

        return json.loads(output.getvalue())

    def test_authorized_keys_lock_helper_locks_the_opened_file(self):
        namespace = {}
        exec(remote_commands._authorized_keys_lock_helper_source(), namespace)

        with tempfile.NamedTemporaryFile() as auth_keys:
            competing_fd = os.open(auth_keys.name, os.O_RDWR)
            try:
                with namespace["locked_authorized_keys_file"](
                    auth_keys.fileno()
                ):
                    with self.assertRaises(BlockingIOError):
                        fcntl.flock(
                            competing_fd,
                            fcntl.LOCK_EX | fcntl.LOCK_NB,
                        )
            finally:
                os.close(competing_fd)

    def test_authorized_keys_helper_detects_a_replaced_named_entry(self):
        namespace = {}
        exec(remote_commands._authorized_keys_lock_helper_source(), namespace)

        with tempfile.TemporaryDirectory() as directory:
            directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            auth_path = os.path.join(directory, "authorized_keys")
            with open(auth_path, "w") as f:
                f.write("original\n")
            auth_fd = os.open(auth_path, os.O_RDWR)
            try:
                self.assertTrue(
                    namespace["same_open_entry"](
                        auth_fd,
                        directory_fd,
                        "authorized_keys",
                    )
                )
                os.rename(auth_path, auth_path + ".old")
                with open(auth_path, "w") as f:
                    f.write("replacement\n")
                self.assertFalse(
                    namespace["same_open_entry"](
                        auth_fd,
                        directory_fd,
                        "authorized_keys",
                    )
                )
            finally:
                os.close(auth_fd)
                os.close(directory_fd)

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

    def test_identity_parser_does_not_scan_key_text_inside_quoted_options(self):
        managed_key = make_public_key("managed")
        actual_key_type = b"ssh-ed25519"
        actual_payload = (
            len(actual_key_type).to_bytes(4, "big")
            + actual_key_type
            + b"different-payload"
        )
        actual_key = (
            "ssh-ed25519 " + base64.b64encode(actual_payload).decode() + " actual"
        )
        line = (
            'command="echo '
            + managed_key
            + ' >/tmp/audit",no-pty '
            + actual_key
        )
        namespace = {}
        exec(remote_commands._public_key_identity_helper_source(), namespace)

        self.assertEqual(
            namespace["public_key_identity"](line),
            ssh_key_identity(actual_key),
        )

    def test_identity_parser_does_not_treat_an_unsupported_key_comment_as_a_key(self):
        unsupported_type = b"sk-ssh-ed25519@openssh.com"
        unsupported_payload = (
            len(unsupported_type).to_bytes(4, "big")
            + unsupported_type
            + b"security-key-payload"
        )
        managed_key_in_comment = make_public_key("managed-comment")
        line = (
            unsupported_type.decode()
            + " "
            + base64.b64encode(unsupported_payload).decode()
            + " "
            + managed_key_in_comment
        )
        namespace = {}
        exec(remote_commands._public_key_identity_helper_source(), namespace)

        self.assertIsNone(namespace["public_key_identity"](line))

    def test_key_removal_command_is_narrowly_scoped_and_supports_options(self):
        ssh_key = "ssh-ed25519 key-body laptop"
        command = build_remove_user_keys_command("alice", [ssh_key])

        self.assertIn(ssh_key_id(ssh_key), command)
        self.assertIn("for index, candidate_type in enumerate(parts[:-1])", command)
        self.assertIn("base64.b64decode(key_body.encode(), validate=True)", command)
        self.assertIn("embedded_type != candidate_type", command)
        self.assertIn("stat.S_ISREG", command)
        self.assertIn("with locked_authorized_keys_file(auth_fd):", command)
        self.assertIn("fcntl.flock(file_fd, fcntl.LOCK_EX)", command)
        self.assertIn('getattr(os, "O_NOFOLLOW", 0)', command)
        self.assertIn('dir_fd=ssh_fd', command)
        self.assertIn("os.pread(auth_fd", command)
        self.assertIn("os.pwrite(auth_fd", command)
        self.assertIn('same_open_entry(ssh_fd, home_fd, ".ssh")', command)
        self.assertIn('auth_fd, ssh_fd, "authorized_keys"', command)
        self.assertIn('result["errors"].append("authorized_keys_changed")', command)
        self.assertIn("revoked_line(line)", command)
        self.assertNotIn("os.replace", command)
        self.assertNotIn("tempfile", command)
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

    def test_key_removal_replaces_key_lines_with_equal_length_comments(self):
        command = build_remove_user_keys_command(
            "alice",
            [make_public_key()],
        )
        script = command.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
        helper_source = script[
            script.index("def revoked_line(line):") : script.index(
                "\nhome_fd = None"
            )
        ]
        namespace = {}
        exec(helper_source, namespace)

        for original in (
            b"ssh-ed25519 body comment\n",
            b"ssh-ed25519 body comment\r\n",
            b"ssh-ed25519 body comment",
        ):
            with self.subTest(original=original):
                replacement = namespace["revoked_line"](original)
                self.assertEqual(len(replacement), len(original))
                self.assertTrue(replacement.startswith(b"#"))
                self.assertEqual(
                    replacement.endswith(b"\n"),
                    original.endswith(b"\n"),
                )

    def test_key_removal_preserves_a_concurrent_unmanaged_append(self):
        managed_key = make_public_key("managed", b"managed-payload")
        unmanaged_key = make_public_key("unmanaged", b"unmanaged-payload")

        with tempfile.TemporaryDirectory() as home:
            ssh_dir = os.path.join(home, ".ssh")
            os.mkdir(ssh_dir)
            auth_path = os.path.join(ssh_dir, "authorized_keys")
            with open(auth_path, "w") as f:
                f.write(managed_key + "\n")

            append_pending = True

            def append_before_first_write(original_pwrite, fd, data, offset):
                nonlocal append_pending
                if append_pending:
                    append_pending = False
                    with open(auth_path, "a") as f:
                        f.write(unmanaged_key + "\n")
                return original_pwrite(fd, data, offset)

            result = self.execute_remove_command(
                home,
                [managed_key],
                pwrite_hook=append_before_first_write,
            )
            with open(auth_path) as f:
                final_content = f.read()

        self.assertEqual(result["errors"], [])
        self.assertEqual(result["keys_removed"], 1)
        self.assertNotIn(managed_key, final_content)
        self.assertIn(unmanaged_key + "\n", final_content)

    def test_key_removal_rejects_a_replaced_ssh_directory(self):
        managed_key = make_public_key("managed", b"managed-payload")

        with tempfile.TemporaryDirectory() as home:
            ssh_dir = os.path.join(home, ".ssh")
            old_ssh_dir = ssh_dir + ".old"
            os.mkdir(ssh_dir)
            auth_path = os.path.join(ssh_dir, "authorized_keys")
            original_content = managed_key + "\n"
            with open(auth_path, "w") as f:
                f.write(original_content)

            swap_pending = True

            def swap_after_ssh_open(original_open, path, flags, *args, **kwargs):
                nonlocal swap_pending
                fd = original_open(path, flags, *args, **kwargs)
                if path == ".ssh" and kwargs.get("dir_fd") is not None and swap_pending:
                    swap_pending = False
                    os.rename(ssh_dir, old_ssh_dir)
                    os.mkdir(ssh_dir)
                    with open(os.path.join(ssh_dir, "authorized_keys"), "w") as f:
                        f.write(original_content)
                return fd

            result = self.execute_remove_command(
                home,
                [managed_key],
                open_hook=swap_after_ssh_open,
            )
            with open(os.path.join(ssh_dir, "authorized_keys")) as f:
                current_content = f.read()
            with open(os.path.join(old_ssh_dir, "authorized_keys")) as f:
                detached_content = f.read()

        self.assertEqual(result["keys_removed"], 0)
        self.assertIn("authorized_keys_changed", result["errors"])
        self.assertEqual(current_content, original_content)
        self.assertEqual(detached_content, original_content)

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
        self.assertIn("with locked_authorized_keys_file(auth_fd):", command)
        self.assertIn('getattr(os, "O_NOFOLLOW", 0)', command)
        self.assertIn('os.open(".ssh", ssh_flags, dir_fd=home_fd)', command)
        self.assertIn('same_open_entry(ssh_fd, home_fd, ".ssh")', command)
        self.assertIn("os.fchmod(ssh_fd, 0o700)", command)
        self.assertIn("os.fstat(auth_fd)", command)
        self.assertIn("os.fchown(auth_fd, entry.pw_uid, entry.pw_gid)", command)
        self.assertIn(
            'encoded_key = b"\\n" + (normalized_key + "\\n").encode()',
            command,
        )
        self.assertNotIn("os.chmod(ssh_dir", command)
        self.assertNotIn("shutil.chown", command)
        script = command.split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
        compile(script, "<configure-users>", "exec")


if __name__ == "__main__":
    unittest.main()
