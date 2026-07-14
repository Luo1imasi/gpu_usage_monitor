"""WSGI entry point for the GPU usage monitor."""

import atexit
import logging
import os

from gpu_monitor.runtime import Runtime
from gpu_monitor.web import create_app


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
)
logging.getLogger("paramiko").setLevel(logging.WARNING)
logger = logging.getLogger(__name__)

app = create_app()
runtime = Runtime()


def _should_start_runtime(debug):
    """Avoid running collectors in Werkzeug's reloader parent process."""
    return not debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true"


atexit.register(runtime.close)


if __name__ == "__main__":
    logger.info("Starting GPU usage monitor...")
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    runtime_started = _should_start_runtime(debug)

    if runtime_started:
        runtime.start()

    logger.info("Running Flask app on 0.0.0.0:5000 (debug=%s)", debug)
    try:
        app.run(host="0.0.0.0", port=5000, debug=debug)
    finally:
        if runtime_started:
            runtime.close()
