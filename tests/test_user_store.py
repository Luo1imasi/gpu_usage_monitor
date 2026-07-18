import base64
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from gpu_monitor import user_store


def make_public_key(comment="test-key", payload=b"test-payload"):
    key_type = b"ssh-ed25519"
    key_data = len(key_type).to_bytes(4, "big") + key_type + payload
    encoded = base64.b64encode(key_data).decode()
    return f"ssh-ed25519 {encoded} {comment}"


class UserStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.user_file = Path(self.temp_dir.name) / "user.txt"
        self.user_file.touch()
        self.path_patch = patch.object(user_store, "USER_FILE_PATH", self.user_file)
        self.path_patch.start()

    def tearDown(self):
        self.path_patch.stop()
        self.temp_dir.cleanup()

    def test_add_load_and_remove_user_key(self):
        ssh_key = make_public_key()

        added, status = user_store.add_user_key("alice", ssh_key)
        self.assertEqual(status, 200)
        self.assertEqual(added, {"username": "alice", "key_added": True})

        users = user_store.load_user_keys()
        self.assertEqual(len(users), 1)
        self.assertEqual(users[0]["username"], "alice")
        self.assertEqual(users[0]["ssh_keys"], [ssh_key])

        removed, status = user_store.remove_user_from_file("alice")
        self.assertEqual(status, 200)
        self.assertEqual(removed["removed_lines"], 1)
        self.assertEqual(user_store.load_user_keys(), [])

    def test_same_key_body_with_a_different_comment_is_rejected(self):
        first_key = make_public_key("first")
        second_key = make_public_key("second")
        user_store.add_user_key("alice", first_key)

        result, status = user_store.add_user_key("bob", second_key)

        self.assertEqual(status, 409)
        self.assertEqual(result["error"], "ssh_key_already_exists")
        self.assertEqual(result["matches"][0]["username"], "alice")
        self.assertEqual(result["matches"][0]["match_type"], "key_body")

    def test_key_id_is_stable_when_comment_changes(self):
        first_key = make_public_key("laptop")
        second_key = make_public_key("renamed")

        self.assertEqual(
            user_store.ssh_key_id(first_key),
            user_store.ssh_key_id(second_key),
        )

    def test_remove_selected_user_key_keeps_other_keys(self):
        first_key = make_public_key("laptop", b"first-key")
        second_key = make_public_key("desktop", b"second-key")
        user_store.add_user_key("alice", first_key)
        user_store.add_user_key("alice", second_key)

        first_key_id = user_store.ssh_key_id(first_key)
        result, status = user_store.remove_user_keys_from_file(
            "alice", [first_key_id]
        )

        self.assertEqual(status, 200)
        self.assertEqual(result["removed_keys"], 1)
        self.assertEqual(result["removed_lines"], 1)
        self.assertEqual(result["removed_key_ids"], [first_key_id])
        self.assertEqual(result["remaining_key_count"], 1)
        users = user_store.load_user_keys()
        self.assertEqual(users[0]["ssh_keys"], [second_key])

    def test_generation_changes_after_successful_mutations(self):
        original_generation = user_store.get_user_store_generation()
        user_store.add_user_key("alice", make_public_key())
        after_add = user_store.get_user_store_generation()
        user_store.remove_user_from_file("alice")

        self.assertGreater(after_add, original_generation)
        self.assertGreater(user_store.get_user_store_generation(), after_add)

    def test_invalid_username_and_key_are_rejected(self):
        result, status = user_store.add_user_key("Bad Name", make_public_key())
        self.assertEqual((result, status), ({"error": "invalid_username"}, 400))

        result, status = user_store.add_user_key("alice", "not-a-key")
        self.assertEqual((result, status), ({"error": "invalid_ssh_key"}, 400))


if __name__ == "__main__":
    unittest.main()
