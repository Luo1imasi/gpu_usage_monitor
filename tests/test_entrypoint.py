import os
import unittest
from unittest.mock import patch

import app


class EntrypointTests(unittest.TestCase):
    def test_runtime_starts_for_normal_server(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertTrue(app._should_start_runtime(debug=False))

    def test_debug_reloader_parent_does_not_start_runtime(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertFalse(app._should_start_runtime(debug=True))

    def test_debug_reloader_child_starts_runtime(self):
        with patch.dict(
            os.environ,
            {"WERKZEUG_RUN_MAIN": "true"},
            clear=True,
        ):
            self.assertTrue(app._should_start_runtime(debug=True))


if __name__ == "__main__":
    unittest.main()
