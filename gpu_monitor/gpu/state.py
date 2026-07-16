"""Thread-safe state for the latest GPU samples."""

import copy
import threading
import time


def make_waiting_gpu_result(server_name):
    return {
        "server": server_name,
        "error": "Waiting for first sample",
        "stale": False,
        "updated_at": None,
        "last_error": None,
    }


def merge_gpu_result(previous, result, now=None):
    now = time.time() if now is None else now
    merged_result = copy.deepcopy(result)
    error = merged_result.get("error")
    is_success = error is None and "gpus" in merged_result

    if is_success:
        merged_result["stale"] = False
        merged_result["updated_at"] = now
        merged_result["last_error"] = None
        return merged_result

    if error is None:
        error = "Invalid GPU result"
        merged_result["error"] = error

    has_previous_success = (
        isinstance(previous, dict)
        and "gpus" in previous
        and previous.get("error") is None
    )
    if has_previous_success:
        stale_result = copy.deepcopy(previous)
        stale_result["error"] = None
        stale_result["stale"] = True
        stale_result["last_error"] = error
        return stale_result

    merged_result["stale"] = False
    merged_result["updated_at"] = None
    merged_result["last_error"] = error
    return merged_result


def get_gpu_cache_identity(server):
    return (
        server.get("host"),
        server.get("port"),
        server.get("username"),
    )


class GPUStateStore:
    """Own cached samples and their server identities behind one lock."""

    def __init__(self):
        self.lock = threading.Lock()
        self.cached_data = []
        self.cached_server_identities = {}

    def initialize_gpu_cache(self, servers):
        current_identities = {
            server["name"]: get_gpu_cache_identity(server) for server in servers
        }
        ordered_names = list(current_identities)
        with self.lock:
            existing = {item["server"]: item for item in self.cached_data}
            self.cached_data = [
                existing.get(name, make_waiting_gpu_result(name))
                if self.cached_server_identities.get(name) == current_identities[name]
                else make_waiting_gpu_result(name)
                for name in ordered_names
            ]
            self.cached_server_identities = current_identities

    def publish_gpu_result(self, result, server_names):
        server_name = result["server"]
        ordered_names = list(server_names)
        now = time.time()

        with self.lock:
            current = {item["server"]: item for item in self.cached_data}
            current[server_name] = merge_gpu_result(
                current.get(server_name),
                result,
                now=now,
            )
            self.cached_data = [
                current.get(name, make_waiting_gpu_result(name))
                for name in ordered_names
            ]

    def get_cached_data(self):
        with self.lock:
            return copy.deepcopy(self.cached_data)


gpu_state = GPUStateStore()
