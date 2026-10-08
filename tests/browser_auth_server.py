"""Isolated server used by the browser authentication tests."""

import sys
from pathlib import Path

from gpu_monitor import config, user_store
from gpu_monitor.web import create_app

directory = Path(sys.argv[1])
user_store.USER_FILE_PATH = directory / "user.txt"
config.CONFIG_PATH = directory / "config.json"
app = create_app({"AUTH_DATABASE": str(directory / "auth.sqlite3")})
app.run(host="127.0.0.1", port=int(sys.argv[2]), use_reloader=False)
