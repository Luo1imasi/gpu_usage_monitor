"""GPU collection orchestration over SSH."""

import copy
import json
import logging
import random
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import paramiko

from ..config import (
    GPU_COLLECTOR_RECONCILE_SECONDS,
    GPU_MAX_WORKERS,
    get_configured_servers,
    get_monitoring_settings,
    get_ssh_settings,
)
from ..ssh import (
    SSH_CLEANUP_GRACE_SECONDS,
    cap_ssh_timeout,
    close_ssh_channel,
    ensure_ssh_client_active,
    execute_ssh_channel_command,
    get_ssh_client,
    get_ssh_connection_identity,
    get_ssh_deadline_remaining,
    invalidate_ssh_client,
    make_ssh_cleanup_deadline,
    make_ssh_deadline,
    open_ssh_session,
    run_server_ssh_command_status,
    sanitize_error,
)
from .commands import (
    GPU_INFO_APPS_END,
    GPU_INFO_APPS_START,
    GPU_INFO_GPU_END,
    GPU_INFO_GPU_START,
    GPU_INFO_PS_END,
    GPU_INFO_PS_START,
    build_gpu_collector_command,
    build_gpu_info_command,
)
from .parsing import GPUStreamFrameParser, build_gpu_result, extract_marked_section
from .state import get_gpu_cache_identity, gpu_state


logger = logging.getLogger(__name__)

GPU_COLLECTOR_STDERR_TAIL_BYTES = 8 * 1024

gpu_executor = ThreadPoolExecutor(max_workers=GPU_MAX_WORKERS)
shutdown_event = threading.Event()
gpu_collector_manager = None
_background_worker_thread = None
_background_worker_lock = threading.Lock()
_shutdown_lock = threading.Lock()


def get_gpu_info_ssh(server):
    try:
        monitoring_settings = get_monitoring_settings()
        status, out, err = run_server_ssh_command_status(
            server,
            build_gpu_info_command(),
            total_timeout=monitoring_settings["gpu_command_total_timeout"],
            operation_timeout=monitoring_settings["gpu_operation_timeout"],
            retry_on_transport=True,
            operation_name="GPU query",
        )
        return build_gpu_result(
            server,
            status,
            extract_marked_section(out, GPU_INFO_GPU_START, GPU_INFO_GPU_END),
            extract_marked_section(out, GPU_INFO_APPS_START, GPU_INFO_APPS_END),
            extract_marked_section(out, GPU_INFO_PS_START, GPU_INFO_PS_END),
            err,
        )
    except Exception as error:
        error_message = str(error) or error.__class__.__name__
        logger.error("Error getting GPU info for %s: %s", server["name"], error_message)
        return {"error": sanitize_error(error_message), "server": server["name"]}


def compute_collector_backoff(attempt, base, maximum, jitter):
    delay = min(maximum, base * (2 ** max(0, attempt)))
    if jitter > 0:
        delay += random.uniform(0, jitter)
    return min(maximum, delay)


def get_gpu_collector_signature(server, monitoring_settings):
    return (
        get_gpu_cache_identity(server),
        get_ssh_connection_identity(server),
        json.dumps(get_ssh_settings(server), sort_keys=True),
        monitoring_settings["collector_mode"],
        monitoring_settings["refresh_interval"],
        monitoring_settings["gpu_command_total_timeout"],
        monitoring_settings["gpu_operation_timeout"],
        monitoring_settings["collector_retry_backoff_max"],
    )


class GPUCollector:
    SSH_NAMESPACE_PREFIX = "gpu-collector"

    def __init__(self, server, monitoring_settings, publish_callback):
        self.server = copy.deepcopy(server)
        self.monitoring_settings = dict(monitoring_settings)
        self.publish_callback = publish_callback
        self.ssh_namespace = (
            f"{self.SSH_NAMESPACE_PREFIX}:{self.server['name']}:"
            f"{secrets.token_hex(8)}"
        )
        self.signature = get_gpu_collector_signature(
            self.server,
            self.monitoring_settings,
        )
        self.stop_event = threading.Event()
        self.state_lock = threading.Lock()
        self.thread = None
        self.client = None
        self.channel = None
        self.backoff_attempt = 0
        self.stderr_tail = bytearray()

    def start(self):
        if self.thread is not None and self.thread.is_alive():
            return
        self.thread = threading.Thread(
            target=self._run,
            name=f"gpu-collector-{self.server['name']}",
            daemon=True,
        )
        self.thread.start()

    def is_alive(self):
        return self.thread is not None and self.thread.is_alive()

    def stop(self, timeout=2):
        self.stop_event.set()
        cleanup_deadline = make_ssh_deadline(max(0, min(1, timeout)))
        with self.state_lock:
            client = self.client
            channel = self.channel
        if channel is not None:
            close_ssh_channel(
                channel,
                timeout=min(1, timeout),
                cleanup_deadline=cleanup_deadline,
            )
        if client is not None:
            invalidate_ssh_client(
                self.server,
                expected_client=client,
                cleanup_deadline=cleanup_deadline,
                namespace=self.ssh_namespace,
            )
        if self.thread is not None and self.thread is not threading.current_thread():
            self.thread.join(timeout=max(0, timeout))

    def _publish_error(self, error):
        message = str(error) or error.__class__.__name__
        self.publish_callback(
            self,
            {
                "server": self.server["name"],
                "error": sanitize_error(message),
            },
        )

    def _run(self):
        if self.monitoring_settings["collector_mode"] in {"poll", "batch"}:
            self._run_polling()
            return

        ssh_settings = get_ssh_settings(self.server)
        retry_base = max(1.0, ssh_settings["retry_backoff_base"])
        retry_max = self.monitoring_settings["collector_retry_backoff_max"]
        retry_jitter = ssh_settings["retry_jitter"]

        while not self.stop_event.is_set():
            try:
                self._run_stream_session()
                if not self.stop_event.is_set():
                    raise paramiko.SSHException("GPU collector stream ended")
            except Exception as error:
                if self.stop_event.is_set():
                    break
                self._publish_error(error)
                delay = compute_collector_backoff(
                    self.backoff_attempt,
                    retry_base,
                    retry_max,
                    retry_jitter,
                )
                self.backoff_attempt += 1
                logger.warning(
                    "GPU collector for %s failed: %s: %s; reconnecting in %.2fs",
                    self.server["name"],
                    error.__class__.__name__,
                    str(error) or repr(error),
                    delay,
                )
                self.stop_event.wait(delay)

    def _run_polling(self):
        interval = self.monitoring_settings["refresh_interval"]
        while not self.stop_event.is_set():
            result = get_gpu_info_ssh(self.server)
            if self.stop_event.is_set():
                break
            self.publish_callback(self, result)
            self.stop_event.wait(interval)

    def _set_session_state(self, client, channel):
        with self.state_lock:
            self.client = client
            self.channel = channel

    def _clear_session_state(self, client, channel):
        with self.state_lock:
            if self.client is client:
                self.client = None
            if self.channel is channel:
                self.channel = None

    def _append_stderr(self, data):
        if not data:
            return
        self.stderr_tail.extend(data)
        if len(self.stderr_tail) > GPU_COLLECTOR_STDERR_TAIL_BYTES:
            del self.stderr_tail[:-GPU_COLLECTOR_STDERR_TAIL_BYTES]

    def _read_frame(self, channel, parser, expected_seq, deadline=None):
        if deadline is None:
            deadline = make_ssh_deadline(
                self.monitoring_settings["gpu_command_total_timeout"]
            )
        while not self.stop_event.is_set():
            for _ in range(16):
                if not channel.recv_ready():
                    break
                data = channel.recv(65536)
                if not data:
                    raise EOFError("GPU collector channel closed")
                for frame in parser.feed(data):
                    if frame["seq"] < expected_seq:
                        continue
                    if frame["seq"] != expected_seq:
                        raise ValueError("Unexpected GPU collector frame sequence")
                    return frame

            for _ in range(16):
                if not channel.recv_stderr_ready():
                    break
                self._append_stderr(channel.recv_stderr(65536))

            if channel.closed or channel.exit_status_ready():
                error = self.stderr_tail.decode("utf-8", "replace").strip()
                raise paramiko.SSHException(error or "GPU collector channel exited")
            get_ssh_deadline_remaining(deadline, "GPU collector sample")
            self.stop_event.wait(0.05)

        raise InterruptedError("GPU collector stopped")

    def _run_stream_session(self):
        operation_deadline = make_ssh_deadline(
            self.monitoring_settings["gpu_operation_timeout"]
        )
        cleanup_deadline = make_ssh_cleanup_deadline(operation_deadline)
        ssh_settings = get_ssh_settings(self.server)
        client = None
        channel = None
        transport = None
        self.stderr_tail.clear()
        nonce = secrets.token_hex(16)
        parser = GPUStreamFrameParser(nonce)
        sample_timeout = max(
            1,
            min(
                60,
                self.monitoring_settings["gpu_command_total_timeout"] / 2,
            ),
        )

        try:
            client, was_reused = get_ssh_client(
                self.server,
                deadline=operation_deadline,
                namespace=self.ssh_namespace,
            )
            self._set_session_state(client, None)
            if self.stop_event.is_set():
                raise InterruptedError("GPU collector stopped during connect")
            transport = ensure_ssh_client_active(client)
            open_timeout = ssh_settings["channel_open_timeout"]
            if was_reused:
                open_timeout = min(
                    open_timeout,
                    ssh_settings["reused_channel_open_timeout"],
                )
            channel = open_ssh_session(
                transport,
                open_timeout,
                deadline=operation_deadline,
                cleanup_deadline=cleanup_deadline,
            )
            self._set_session_state(client, channel)
            if self.stop_event.is_set():
                raise InterruptedError("GPU collector stopped during channel open")
            channel.settimeout(
                cap_ssh_timeout(
                    ssh_settings["command_idle_timeout"],
                    operation_deadline,
                    "GPU collector channel",
                )
            )
            execute_ssh_channel_command(
                channel,
                build_gpu_collector_command(nonce, sample_timeout),
                ssh_settings["command_idle_timeout"],
                transport=transport,
                deadline=operation_deadline,
                cleanup_deadline=cleanup_deadline,
            )
            if self.stop_event.is_set():
                raise InterruptedError("GPU collector stopped during stream start")
            logger.info("GPU collector stream started for %s", self.server["name"])

            seq = 0
            interval = self.monitoring_settings["refresh_interval"]
            next_poll_at = time.monotonic()
            while not self.stop_event.is_set():
                wait_time = max(0.0, next_poll_at - time.monotonic())
                if self.stop_event.wait(wait_time):
                    break
                seq += 1
                poll_started = time.monotonic()
                sample_deadline = make_ssh_deadline(
                    self.monitoring_settings["gpu_command_total_timeout"]
                )
                channel.settimeout(
                    cap_ssh_timeout(
                        min(
                            ssh_settings["command_idle_timeout"],
                            self.monitoring_settings["gpu_command_total_timeout"],
                        ),
                        sample_deadline,
                        "GPU collector sample send",
                    )
                )
                channel.sendall(f"POLL|{seq}\n".encode("ascii"))
                frame = self._read_frame(channel, parser, seq, sample_deadline)
                self.backoff_attempt = 0
                result = build_gpu_result(
                    self.server,
                    frame["status"],
                    frame["gpu"].decode("utf-8", "replace"),
                    frame["apps"].decode("utf-8", "replace"),
                    frame["ps"].decode("utf-8", "replace"),
                    frame["error"].decode("utf-8", "replace"),
                )
                self.publish_callback(self, result)
                next_poll_at = max(poll_started + interval, time.monotonic())
        finally:
            self._clear_session_state(client, channel)
            cleanup_deadline = make_ssh_deadline(SSH_CLEANUP_GRACE_SECONDS)
            if channel is not None:
                close_ssh_channel(
                    channel,
                    transport,
                    cleanup_deadline=cleanup_deadline,
                )
            if client is not None:
                invalidate_ssh_client(
                    self.server,
                    expected_client=client,
                    cleanup_deadline=cleanup_deadline,
                    namespace=self.ssh_namespace,
                )


class GPUCollectorManager:
    def __init__(self, collector_factory=GPUCollector):
        self.collector_factory = collector_factory
        self.collectors = {}
        self.lock = threading.RLock()
        self.stop_event = threading.Event()

    def publish_from(self, collector, result):
        server_name = collector.server["name"]
        with self.lock:
            if self.collectors.get(server_name) is not collector:
                return False
            gpu_state.publish_gpu_result(result, list(self.collectors))
            return True

    def reconcile_once(self, servers=None, monitoring_settings=None):
        if servers is None:
            servers = get_configured_servers()
        if monitoring_settings is None:
            monitoring_settings = get_monitoring_settings()
        desired = {server["name"]: server for server in servers}
        to_start = []

        with self.lock:
            current = self.collectors
            planned = {}
            for name, server in desired.items():
                signature = get_gpu_collector_signature(server, monitoring_settings)
                collector = current.get(name)
                collector_running = collector is not None and (
                    not hasattr(collector, "is_alive") or collector.is_alive()
                )
                if collector_running and collector.signature == signature:
                    planned[name] = collector
                    continue
                collector = self.collector_factory(
                    server,
                    monitoring_settings,
                    self.publish_from,
                )
                planned[name] = collector
                to_start.append(collector)

            to_stop = [
                collector
                for name, collector in current.items()
                if planned.get(name) is not collector
            ]
            self.collectors = planned
            gpu_state.initialize_gpu_cache(servers)

        for collector in to_stop:
            collector.stop()
        start_errors = []
        for collector in to_start:
            with self.lock:
                should_start = (
                    not self.stop_event.is_set()
                    and self.collectors.get(collector.server["name"]) is collector
                )
            if should_start:
                try:
                    collector.start()
                except Exception as error:
                    with self.lock:
                        if self.collectors.get(collector.server["name"]) is collector:
                            self.collectors.pop(collector.server["name"], None)
                    collector.stop(timeout=0)
                    start_errors.append(error)
            else:
                collector.stop(timeout=0)
        if start_errors:
            raise start_errors[0]

    def run(self):
        logger.info("Starting independent GPU collector manager")
        try:
            while not self.stop_event.is_set() and not shutdown_event.is_set():
                try:
                    monitoring_settings = get_monitoring_settings()
                    self.reconcile_once(monitoring_settings=monitoring_settings)
                    delay = monitoring_settings["collector_reconcile_interval"]
                except Exception as error:
                    logger.error("GPU collector reconciliation failed: %s", error)
                    delay = GPU_COLLECTOR_RECONCILE_SECONDS
                self.stop_event.wait(delay)
        finally:
            self.stop()

    def stop(self, timeout=5):
        self.stop_event.set()
        with self.lock:
            collectors = list(self.collectors.values())
            self.collectors.clear()
        if not collectors:
            return
        per_collector_timeout = max(0.1, timeout / len(collectors))
        for collector in collectors:
            collector.stop(timeout=per_collector_timeout)


def refresh_data():
    servers = get_configured_servers()
    server_names = [server["name"] for server in servers]
    gpu_state.initialize_gpu_cache(servers)
    completed = 0

    futures = {
        gpu_executor.submit(get_gpu_info_ssh, server): server for server in servers
    }
    for future in as_completed(futures):
        try:
            result = future.result()
        except Exception as error:
            server = futures[future]
            logger.error("Unexpected error for %s: %s", server["name"], error)
            result = {
                "error": sanitize_error(str(error)),
                "server": server["name"],
            }
        gpu_state.publish_gpu_result(result, server_names)
        completed += 1

    logger.info("Refreshed data for %s servers", completed)


def background_worker():
    global gpu_collector_manager

    monitoring_settings = get_monitoring_settings()
    if monitoring_settings["collector_mode"] == "batch":
        logger.info("Starting batch GPU worker")
        while not shutdown_event.is_set():
            try:
                refresh_data()
            except Exception as error:
                logger.error("Error in background worker: %s", error)
            shutdown_event.wait(get_monitoring_settings()["refresh_interval"])
        return

    manager = GPUCollectorManager()
    gpu_collector_manager = manager
    try:
        manager.run()
    finally:
        if gpu_collector_manager is manager:
            gpu_collector_manager = None


def start_background_worker():
    global _background_worker_thread

    with _background_worker_lock:
        if _background_worker_thread is not None and _background_worker_thread.is_alive():
            return _background_worker_thread
        if shutdown_event.is_set():
            raise RuntimeError("GPU collector runtime has been shut down")
        _background_worker_thread = threading.Thread(
            target=background_worker,
            name="gpu-background-worker",
            daemon=True,
        )
        _background_worker_thread.start()
        return _background_worker_thread


def wait_for_shutdown(timeout=2):
    thread = _background_worker_thread
    if thread is None or thread is threading.current_thread():
        return True
    thread.join(timeout=max(0, timeout))
    return not thread.is_alive()


def shutdown(timeout=2):
    with _shutdown_lock:
        if not shutdown_event.is_set():
            shutdown_event.set()
            manager = gpu_collector_manager
            if manager is not None:
                manager.stop()
            gpu_executor.shutdown(wait=False, cancel_futures=True)

    return wait_for_shutdown(timeout)
