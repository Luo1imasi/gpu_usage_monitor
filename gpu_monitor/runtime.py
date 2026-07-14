"""Process lifecycle for background collectors and shared resources."""

import logging
import threading

from . import ssh, storage
from .access import service as access_service
from .gpu import collector as gpu_collector


logger = logging.getLogger(__name__)


class Runtime:
    """Own the background worker and make startup/shutdown idempotent."""

    def __init__(self):
        self._lock = threading.Lock()
        self._closed = False

    def start(self):
        with self._lock:
            if self._closed:
                raise RuntimeError("Runtime has already been closed")
            gpu_worker = gpu_collector.start_background_worker()
            try:
                storage.start_background_worker()
            except Exception:
                gpu_collector.shutdown(timeout=0)
                raise
            return gpu_worker

    def close(self):
        with self._lock:
            if self._closed:
                return
            self._closed = True
        logger.info("Cleaning up resources...")
        ssh.begin_shutdown()
        access_service.shutdown()
        gpu_collector.shutdown(timeout=0)
        storage.shutdown(timeout=0)
        ssh.shutdown()
        gpu_collector.wait_for_shutdown(timeout=1)
        storage.wait_for_shutdown(timeout=1)
        access_service.wait_for_shutdown(timeout=1)
