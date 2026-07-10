import copy
import os
import shlex
import subprocess
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import app


NONCE = "0123456789abcdef0123456789abcdef"


def make_frame(
    *,
    nonce=NONCE,
    seq=1,
    epoch=1_700_000_000,
    status=0,
    gpu=b"",
    apps=b"",
    ps=b"",
    error=b"",
):
    payload = gpu + apps + ps + error
    header = (
        f"\x1eGUM1|{nonce}|DATA|{seq}|{epoch}|{status}|"
        f"{len(gpu)}|{len(apps)}|{len(ps)}|{len(error)}\n"
    ).encode("ascii")
    footer = f"\x1eGUM1|{nonce}|END|{seq}\n".encode("ascii")
    return header + payload + footer


def frame_payload(**overrides):
    result = {
        "seq": 1,
        "epoch": 1_700_000_000,
        "status": 0,
        "gpu": b"",
        "apps": b"",
        "ps": b"",
        "error": b"",
    }
    result.update(overrides)
    return result


def make_server(name, host=None, key_file=None):
    return {
        "name": name,
        "host": host or f"{name}.example.test",
        "port": 22,
        "username": "gpu",
        "key_file": key_file or f"/tmp/{name}-collector-test-key",
        "accept_unknown_host": True,
    }


def monitoring_settings(**overrides):
    settings = {
        "collector_mode": "stream",
        "collector_reconcile_interval": 2,
        "collector_retry_backoff_max": 60,
        "refresh_interval": 5,
        "gpu_command_total_timeout": 30,
        "gpu_operation_timeout": 60,
    }
    settings.update(overrides)
    return settings


def collector_signature(server, settings):
    return (
        server["host"],
        server["port"],
        server["username"],
        server["key_file"],
        settings["collector_mode"],
        settings["refresh_interval"],
    )


class GPUStreamFrameParserTests(unittest.TestCase):
    def test_arbitrary_fragmentation_preserves_length_delimited_payload(self):
        false_data_marker = (
            f"\x1eGUM1|{NONCE}|DATA|999|1|0|0|0|0|0\n"
        ).encode("ascii")
        false_footer = f"\x1eGUM1|{NONCE}|END|999\n".encode("ascii")
        gpu = b"gpu-prefix\n" + false_data_marker + false_footer + b"gpu-suffix"
        apps = b"0000:01:00.0, 123, 512 MiB\n"
        ps = b"123 alice\n"
        first = make_frame(seq=7, gpu=gpu, apps=apps, ps=ps)
        second = make_frame(seq=8, status=9, error=b"nvidia-smi failed")
        wire = b"collector startup noise\n" + first + second

        parser = app.GPUStreamFrameParser(NONCE)
        parsed = []
        chunk_sizes = (1, 2, 3, 5, 8, 13, 21)
        offset = 0
        chunk_index = 0
        while offset < len(wire):
            size = chunk_sizes[chunk_index % len(chunk_sizes)]
            parsed.extend(parser.feed(wire[offset:offset + size]))
            offset += size
            chunk_index += 1

        self.assertEqual(
            parsed,
            [
                frame_payload(seq=7, gpu=gpu, apps=apps, ps=ps),
                frame_payload(seq=8, status=9, error=b"nvidia-smi failed"),
            ],
        )

    def test_multiple_complete_frames_are_returned_by_one_feed(self):
        parser = app.GPUStreamFrameParser(NONCE)

        parsed = parser.feed(
            make_frame(seq=1, gpu=b"first")
            + make_frame(seq=2, gpu=b"second", apps=b"apps")
        )

        self.assertEqual(
            parsed,
            [
                frame_payload(seq=1, gpu=b"first"),
                frame_payload(seq=2, gpu=b"second", apps=b"apps"),
            ],
        )

    def test_partial_footer_waits_and_invalid_footer_is_rejected(self):
        parser = app.GPUStreamFrameParser(NONCE)
        encoded = make_frame(seq=3, gpu=b"payload")

        self.assertEqual(parser.feed(encoded[:-1]), [])
        with self.assertRaisesRegex(ValueError, "Invalid GPU collector frame footer"):
            parser.feed(b"X")

    def test_declared_payload_over_limit_is_rejected_before_buffering_payload(self):
        parser = app.GPUStreamFrameParser(NONCE)
        header = (
            f"\x1eGUM1|{NONCE}|DATA|1|1700000000|0|"
            f"{app.GPU_COLLECTOR_FRAME_MAX_BYTES + 1}|0|0|0\n"
        ).encode("ascii")

        with self.assertRaisesRegex(ValueError, "GPU collector frame is too large"):
            parser.feed(header)


class GPUCollectorCommandTests(unittest.TestCase):
    def run_combined_query_awk(self, topology, query_output):
        completed = subprocess.run(
            [
                "awk",
                "-v",
                f"marker={app.GPU_COMBINED_QUERY_MARKER}",
                app.GPU_COMBINED_QUERY_AWK,
            ],
            input=(
                topology.rstrip("\n")
                + "\n"
                + app.GPU_COMBINED_QUERY_MARKER
                + "\n"
                + query_output
            ),
            text=True,
            capture_output=True,
            check=False,
        )
        return completed

    def test_stream_command_caches_topology_and_has_one_combined_query_per_poll(self):
        command = app.build_gpu_collector_command(NONCE, 30)
        command_parts = shlex.split(command)

        self.assertEqual(command_parts[:2], ["sh", "-c"])
        script = command_parts[2]
        startup_script, poll_loop = script.split("while IFS= read -r request", 1)

        self.assertIn("--query-gpu=", startup_script)
        for field in ("index", "gpu_bus_id", "name"):
            self.assertIn(field, startup_script)
        self.assertNotIn("utilization.gpu", startup_script)
        self.assertNotIn("memory.used", startup_script)
        self.assertNotIn("--query-gpu=", poll_loop)
        self.assertNotIn("--query-compute-apps=", poll_loop)
        self.assertIn("MEMORY,UTILIZATION,PIDS", poll_loop)

    def test_compact_combined_query_output_remains_gum1_compatible(self):
        raw_query_output = """\
==============NVSMI LOG==============

GPU 00000000:01:00.0
    FB Memory Usage
        Total                             : 24576 MiB
        Reserved                          : 0 MiB
        Used                              : 1024 MiB
        Free                              : 23552 MiB
    Utilization
        Gpu                               : 25 %
        Memory                            : 4 %
        Encoder                           : 0 %
        Decoder                           : 0 %
    Processes
        GPU instance ID                  : N/A
        Compute instance ID              : N/A
        Process ID                       : 4242
        Type                             : C
        Name                             : python
        Used GPU Memory                  : 1024 MiB
"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            invocation_log = temp_path / "nvidia-smi.log"
            fake_nvidia_smi = temp_path / "nvidia-smi"
            fake_ps = temp_path / "ps"
            fake_date = temp_path / "date"

            fake_nvidia_smi.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' \"$*\" >> \"$NVIDIA_SMI_LOG\"\n"
                "case \"$*\" in\n"
                "  *--query-gpu=*)\n"
                "    printf '%s\\n' '0, 00000000:01:00.0, Test GPU'\n"
                "    ;;\n"
                "  *'-q'*'-d MEMORY,UTILIZATION,PIDS'*)\n"
                "    printf '%s' \"$NVIDIA_SMI_QUERY_OUTPUT\"\n"
                "    ;;\n"
                "  *)\n"
                "    printf '%s\\n' \"unexpected nvidia-smi arguments: $*\" >&2\n"
                "    exit 64\n"
                "    ;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_ps.write_text(
                "#!/bin/sh\nprintf '%s\\n' ' 4242 alice'\n",
                encoding="utf-8",
            )
            fake_date.write_text(
                "#!/bin/sh\nprintf '%s\\n' '1700000000'\n",
                encoding="utf-8",
            )
            for executable in (fake_nvidia_smi, fake_ps, fake_date):
                executable.chmod(0o755)

            env = os.environ.copy()
            env.update(
                {
                    "PATH": f"{temp_dir}:{env.get('PATH', '')}",
                    "NVIDIA_SMI_LOG": str(invocation_log),
                    "NVIDIA_SMI_QUERY_OUTPUT": raw_query_output,
                }
            )
            completed = subprocess.run(
                app.build_gpu_collector_command(NONCE, 30),
                shell=True,
                input="POLL|1\nPOLL|2\nQUIT\n",
                text=True,
                capture_output=True,
                env=env,
                timeout=5,
                check=False,
            )

            self.assertEqual(completed.returncode, 0, completed.stderr)
            invocations = invocation_log.read_text(encoding="utf-8").splitlines()

        topology_calls = [
            invocation for invocation in invocations if "--query-gpu=" in invocation
        ]
        combined_calls = [
            invocation
            for invocation in invocations
            if "-q" in invocation and "MEMORY,UTILIZATION,PIDS" in invocation
        ]
        self.assertEqual(len(topology_calls), 1, invocations)
        self.assertEqual(len(combined_calls), 2, invocations)
        self.assertFalse(
            any("--query-compute-apps=" in invocation for invocation in invocations),
            invocations,
        )

        frames = app.GPUStreamFrameParser(NONCE).feed(completed.stdout.encode())
        self.assertEqual([frame["seq"] for frame in frames], [1, 2])
        for frame in frames:
            compact_size = sum(
                len(frame[key]) for key in ("gpu", "apps", "ps", "error")
            )
            self.assertLess(compact_size, len(raw_query_output.encode()))
            self.assertNotIn(b"FB Memory Usage", frame["gpu"])
            result = app.build_gpu_result(
                make_server("alpha"),
                frame["status"],
                frame["gpu"].decode(),
                frame["apps"].decode(),
                frame["ps"].decode(),
                frame["error"].decode(),
            )
            self.assertIsNone(result["error"])
            self.assertEqual(
                result["gpus"],
                [
                    {
                        "index": 0,
                        "name": "Test GPU",
                        "gpu_util": 25,
                        "memory_used": 1024,
                        "memory_total": 24576,
                        "processes": [{"user": "alice", "memory": 1024}],
                    }
                ],
            )

    def test_combined_parser_ignores_other_memory_sections_and_empty_processes(self):
        completed = self.run_combined_query_awk(
            "0, 00000000:01:00.0, Test GPU\n",
            """\
GPU 00000000:01:00.0
    FB Memory Usage
        Total                             : 24576 MiB
        Used                              : 1 MiB
    BAR1 Memory Usage
        Total                             : 256 MiB
        Used                              : 7 MiB
    Conf Compute Protected Memory Usage
        Total                             : 0 MiB
        Used                              : 0 MiB
    Utilization
        GPU                               : N/A
    GPU Utilization Samples
        Max                               : 99 %
    Processes                             : None
""",
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            completed.stdout,
            "G|0, 00000000:01:00.0, Test GPU, 0, 1, 24576\n",
        )

    def test_combined_parser_keeps_compute_types_and_skips_graphics_only(self):
        completed = self.run_combined_query_awk(
            "0, 00000000:01:00.0, Test GPU\n",
            """\
GPU 00000000:01:00.0
    FB Memory Usage
        Total                             : 24576 MiB
        Used                              : 1536 MiB
    Utilization
        Gpu                               : 40 %
    Processes
        Process ID                        : 100
            Type                          : G
            Used GPU Memory               : 512 MiB
        Process ID                        : 200
            Type                          : C+G
            Used GPU Memory               : 1024 MiB
""",
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(
            completed.stdout.splitlines(),
            [
                "G|0, 00000000:01:00.0, Test GPU, 40, 1536, 24576",
                "A|00000000:01:00.0, 200, 1024",
            ],
        )

    def test_combined_parser_rejects_incomplete_or_unknown_gpu_records(self):
        for query_output, expected_error in (
            (
                """\
GPU 00000000:01:00.0
    FB Memory Usage
        Total                             : 24576 MiB
        Used                              : 1 MiB
    Processes                             : None
""",
                "incomplete GPU record",
            ),
            (
                """\
GPU 00000000:02:00.0
    FB Memory Usage
        Total                             : 24576 MiB
        Used                              : 1 MiB
    Utilization
        Gpu                               : 0 %
    Processes                             : None
""",
                "unknown GPU bus id",
            ),
        ):
            with self.subTest(expected_error=expected_error):
                completed = self.run_combined_query_awk(
                    "0, 00000000:01:00.0, Test GPU\n",
                    query_output,
                )

                self.assertEqual(completed.returncode, 65)
                self.assertIn(f"E|{expected_error}", completed.stdout)

    def test_stream_exits_after_parse_error_so_topology_is_refreshed(self):
        incomplete_query_output = """\
GPU 00000000:01:00.0
    FB Memory Usage
        Total                             : 24576 MiB
        Used                              : 1 MiB
    Processes                             : None
"""

        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            invocation_log = temp_path / "nvidia-smi.log"
            fake_nvidia_smi = temp_path / "nvidia-smi"
            fake_date = temp_path / "date"

            fake_nvidia_smi.write_text(
                "#!/bin/sh\n"
                "printf '%s\\n' \"$*\" >> \"$NVIDIA_SMI_LOG\"\n"
                "case \"$*\" in\n"
                "  *--query-gpu=*)\n"
                "    printf '%s\\n' '0, 00000000:01:00.0, Test GPU'\n"
                "    ;;\n"
                "  *'-q'*'-d MEMORY,UTILIZATION,PIDS'*)\n"
                "    printf '%s' \"$NVIDIA_SMI_QUERY_OUTPUT\"\n"
                "    ;;\n"
                "  *) exit 64;;\n"
                "esac\n",
                encoding="utf-8",
            )
            fake_date.write_text(
                "#!/bin/sh\nprintf '%s\\n' '1700000000'\n",
                encoding="utf-8",
            )
            for executable in (fake_nvidia_smi, fake_date):
                executable.chmod(0o755)

            env = os.environ.copy()
            env.update(
                {
                    "PATH": f"{temp_dir}:{env.get('PATH', '')}",
                    "NVIDIA_SMI_LOG": str(invocation_log),
                    "NVIDIA_SMI_QUERY_OUTPUT": incomplete_query_output,
                }
            )
            completed = subprocess.run(
                app.build_gpu_collector_command(NONCE, 30),
                shell=True,
                input="POLL|1\nPOLL|2\n",
                text=True,
                capture_output=True,
                env=env,
                timeout=5,
                check=False,
            )
            invocations = invocation_log.read_text(encoding="utf-8").splitlines()

        self.assertEqual(completed.returncode, 65, completed.stderr)
        combined_calls = [
            invocation
            for invocation in invocations
            if "-q" in invocation and "MEMORY,UTILIZATION,PIDS" in invocation
        ]
        self.assertEqual(len(combined_calls), 1, invocations)
        frames = app.GPUStreamFrameParser(NONCE).feed(completed.stdout.encode())
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0]["seq"], 1)
        self.assertNotEqual(frames[0]["status"], 0)
        self.assertIn(b"incomplete GPU record", frames[0]["error"])


class GPUCollectorBackoffTests(unittest.TestCase):
    def test_backoff_is_exponential_and_attempt_zero_starts_at_base(self):
        self.assertEqual(app.compute_collector_backoff(0, 2, 60, 0), 2)
        self.assertEqual(app.compute_collector_backoff(1, 2, 60, 0), 4)
        self.assertEqual(app.compute_collector_backoff(4, 2, 60, 0), 32)
        self.assertEqual(app.compute_collector_backoff(-3, 2, 60, 0), 2)

    def test_backoff_jitter_is_applied_without_exceeding_configured_maximum(self):
        with patch.object(app.random, "uniform", return_value=0.75) as uniform:
            self.assertEqual(app.compute_collector_backoff(0, 2, 6, 1), 2.75)
            self.assertEqual(app.compute_collector_backoff(3, 2, 6, 1), 6)

        self.assertEqual(uniform.call_count, 2)
        uniform.assert_any_call(0, 1)


class FakeCollector:
    instances = []

    def __init__(self, server, settings, publish_callback):
        self.server = copy.deepcopy(server)
        self.settings = dict(settings)
        self.publish_callback = publish_callback
        self.signature = app.get_gpu_collector_signature(server, settings)
        self.started = False
        self.stopped = False
        self.stop_timeouts = []
        self.__class__.instances.append(self)

    def start(self):
        self.started = True

    def stop(self, timeout=2):
        self.stopped = True
        self.stop_timeouts.append(timeout)


class ThreadedFakeCollector(FakeCollector):
    instances = []

    def __init__(self, server, settings, publish_callback):
        super().__init__(server, settings, publish_callback)
        self.started_event = threading.Event()
        self.thread_stop_event = threading.Event()
        self.thread = None
        self.worker_ident = None

    def start(self):
        self.started = True

        def run():
            self.worker_ident = threading.get_ident()
            self.started_event.set()
            self.thread_stop_event.wait()

        self.thread = threading.Thread(
            target=run,
            name=f"fake-gpu-collector-{self.server['name']}",
            daemon=True,
        )
        self.thread.start()

    def stop(self, timeout=2):
        super().stop(timeout=timeout)
        self.thread_stop_event.set()
        if self.thread is not None:
            self.thread.join(timeout=timeout)


class GPUCollectorManagerTests(unittest.TestCase):
    def setUp(self):
        FakeCollector.instances = []
        ThreadedFakeCollector.instances = []

    def test_reconcile_removes_deleted_replaces_identity_and_fences_old_publish(self):
        alpha = make_server("alpha")
        beta = make_server("beta")
        settings = monitoring_settings()
        manager = app.GPUCollectorManager(collector_factory=FakeCollector)

        with (
            patch.object(app, "get_gpu_collector_signature", side_effect=collector_signature),
            patch.object(app, "initialize_gpu_cache"),
            patch.object(app, "publish_gpu_result") as publish,
        ):
            manager.reconcile_once([alpha, beta], settings)
            old_alpha = manager.collectors["alpha"]
            old_beta = manager.collectors["beta"]

            replacement_alpha = {**alpha, "key_file": "/tmp/alpha-new-key"}
            manager.reconcile_once([replacement_alpha], settings)
            new_alpha = manager.collectors["alpha"]

            self.assertIsNot(new_alpha, old_alpha)
            self.assertTrue(old_alpha.stopped)
            self.assertTrue(old_beta.stopped)
            self.assertTrue(new_alpha.started)
            self.assertNotIn("beta", manager.collectors)

            old_result = {"server": "alpha", "gpus": [], "error": None}
            deleted_result = {"server": "beta", "gpus": [], "error": None}
            self.assertFalse(old_alpha.publish_callback(old_alpha, old_result))
            self.assertFalse(old_beta.publish_callback(old_beta, deleted_result))
            publish.assert_not_called()

            new_result = {"server": "alpha", "gpus": [], "error": None}
            self.assertTrue(new_alpha.publish_callback(new_alpha, new_result))
            publish.assert_called_once_with(new_result, ["alpha"])

    def test_each_server_gets_an_independent_thread_without_gpu_executor(self):
        servers = [make_server(f"gpu-{index}") for index in range(9)]
        settings = monitoring_settings()
        manager = app.GPUCollectorManager(collector_factory=ThreadedFakeCollector)
        forbidden_executor = MagicMock()
        forbidden_executor.submit.side_effect = AssertionError(
            "independent collectors must not use gpu_executor"
        )

        try:
            with (
                patch.object(app, "get_gpu_collector_signature", side_effect=collector_signature),
                patch.object(app, "initialize_gpu_cache"),
                patch.object(app, "gpu_executor", forbidden_executor),
            ):
                manager.reconcile_once(servers, settings)

            collectors = list(manager.collectors.values())
            self.assertEqual(len(collectors), len(servers))
            for collector in collectors:
                self.assertTrue(collector.started_event.wait(1))
                self.assertTrue(collector.thread.is_alive())

            self.assertEqual(
                len({collector.worker_ident for collector in collectors}),
                len(servers),
            )
            forbidden_executor.submit.assert_not_called()
        finally:
            manager.stop(timeout=2)

    def test_manager_stop_fences_publish_attempted_by_stopping_collector(self):
        class PublishingOnStopCollector(FakeCollector):
            instances = []

            def stop(self, timeout=2):
                super().stop(timeout=timeout)
                self.stop_publish_accepted = self.publish_callback(
                    self,
                    {"server": self.server["name"], "gpus": [], "error": None},
                )

        manager = app.GPUCollectorManager(
            collector_factory=PublishingOnStopCollector
        )
        settings = monitoring_settings()

        with (
            patch.object(app, "get_gpu_collector_signature", side_effect=collector_signature),
            patch.object(app, "initialize_gpu_cache"),
            patch.object(app, "publish_gpu_result") as publish,
        ):
            manager.reconcile_once([make_server("alpha")], settings)
            collector = manager.collectors["alpha"]
            manager.stop(timeout=1)

        self.assertFalse(collector.stop_publish_accepted)
        publish.assert_not_called()

    def test_collectors_for_same_endpoint_have_isolated_ssh_namespaces(self):
        endpoint = make_server("alpha")
        alias = {**endpoint, "name": "alpha-alias"}
        settings = monitoring_settings()

        with patch.object(
            app,
            "get_gpu_collector_signature",
            side_effect=collector_signature,
        ):
            first = app.GPUCollector(endpoint, settings, lambda *_args: True)
            second = app.GPUCollector(alias, settings, lambda *_args: True)

        self.assertNotEqual(first.ssh_namespace, second.ssh_namespace)
        self.assertIn("alpha", first.ssh_namespace)
        self.assertIn("alpha-alias", second.ssh_namespace)

    def test_reconcile_factory_failure_leaves_current_collectors_managed(self):
        alpha = make_server("alpha")
        beta = make_server("beta")
        settings = monitoring_settings()
        manager = app.GPUCollectorManager(collector_factory=FakeCollector)

        with (
            patch.object(
                app,
                "get_gpu_collector_signature",
                side_effect=collector_signature,
            ),
            patch.object(app, "initialize_gpu_cache"),
        ):
            manager.reconcile_once([alpha], settings)
            current_alpha = manager.collectors["alpha"]

            def failing_factory(server, _settings, _publish_callback):
                raise ValueError(f"invalid collector {server['name']}")

            manager.collector_factory = failing_factory
            with self.assertRaisesRegex(ValueError, "invalid collector beta"):
                manager.reconcile_once([alpha, beta], settings)

        self.assertIs(manager.collectors["alpha"], current_alpha)
        self.assertFalse(current_alpha.stopped)
        self.assertNotIn("beta", manager.collectors)

    def test_reconcile_replaces_a_collector_whose_thread_died(self):
        class HealthAwareCollector(FakeCollector):
            instances = []

            def start(self):
                super().start()
                self.alive = True

            def stop(self, timeout=2):
                super().stop(timeout=timeout)
                self.alive = False

            def is_alive(self):
                return getattr(self, "alive", False)

        server = make_server("alpha")
        settings = monitoring_settings()
        manager = app.GPUCollectorManager(
            collector_factory=HealthAwareCollector
        )

        with (
            patch.object(
                app,
                "get_gpu_collector_signature",
                side_effect=collector_signature,
            ),
            patch.object(app, "initialize_gpu_cache"),
        ):
            manager.reconcile_once([server], settings)
            dead = manager.collectors["alpha"]
            dead.alive = False
            manager.reconcile_once([server], settings)

        replacement = manager.collectors["alpha"]
        self.assertIsNot(replacement, dead)
        self.assertTrue(dead.stopped)
        self.assertTrue(replacement.started)


class GPUCollectorStopTests(unittest.TestCase):
    def test_stream_run_resets_backoff_sends_poll_sequence_and_suppresses_stop_error(self):
        class FakeStreamChannel:
            def __init__(self):
                self.sent = []
                self.timeout = None

            def settimeout(self, timeout):
                self.timeout = timeout

            def sendall(self, data):
                self.sent.append(data)

        published = []
        channel = FakeStreamChannel()
        client = object()
        transport = object()
        ssh_settings = {
            "retry_backoff_base": 2,
            "retry_jitter": 0,
            "channel_open_timeout": 60,
            "reused_channel_open_timeout": 20,
            "command_idle_timeout": 60,
        }

        with patch.object(
            app,
            "get_gpu_collector_signature",
            side_effect=collector_signature,
        ):
            collector = app.GPUCollector(
                make_server("alpha"),
                monitoring_settings(refresh_interval=0),
                lambda _collector, result: published.append(result),
            )
        collector.backoff_attempt = 4
        requested_sequences = []

        def read_frame(_channel, _parser, expected_seq, _deadline=None):
            requested_sequences.append(expected_seq)
            if expected_seq == 1:
                return frame_payload(
                    seq=1,
                    gpu=(
                        b"0, 00000000:01:00.0, Test GPU, "
                        b"25, 1024, 24576"
                    ),
                )
            collector.stop_event.set()
            raise InterruptedError("collector stopped while reading")

        with (
            patch.object(app, "get_ssh_settings", return_value=ssh_settings),
            patch.object(app, "get_ssh_client", return_value=(client, False)),
            patch.object(app, "ensure_ssh_client_active", return_value=transport),
            patch.object(app, "open_ssh_session", return_value=channel),
            patch.object(app, "execute_ssh_channel_command"),
            patch.object(app, "close_ssh_channel") as close_channel,
            patch.object(app, "invalidate_ssh_client") as invalidate_client,
            patch.object(app.secrets, "token_hex", return_value=NONCE),
            patch.object(collector, "_read_frame", side_effect=read_frame),
            patch.object(collector, "_publish_error") as publish_error,
        ):
            collector._run()

        self.assertEqual(requested_sequences, [1, 2])
        self.assertEqual(channel.sent, [b"POLL|1\n", b"POLL|2\n"])
        self.assertEqual(collector.backoff_attempt, 0)
        self.assertEqual(len(published), 1)
        self.assertIsNone(published[0]["error"])
        self.assertEqual(published[0]["server"], "alpha")
        self.assertEqual(published[0]["gpus"][0]["name"], "Test GPU")
        publish_error.assert_not_called()
        self.assertGreater(
            close_channel.call_args.kwargs["cleanup_deadline"],
            app.time.monotonic(),
        )
        self.assertEqual(
            close_channel.call_args.kwargs["cleanup_deadline"],
            invalidate_client.call_args.kwargs["cleanup_deadline"],
        )

    def test_poll_collector_does_not_publish_query_finishing_after_stop(self):
        entered_query = threading.Event()
        release_query = threading.Event()
        published = []

        def blocking_query(server):
            entered_query.set()
            if not release_query.wait(2):
                raise TimeoutError("test did not release fake GPU query")
            return {"server": server["name"], "gpus": [], "error": None}

        with patch.object(
            app,
            "get_gpu_collector_signature",
            side_effect=collector_signature,
        ):
            collector = app.GPUCollector(
                make_server("alpha"),
                monitoring_settings(collector_mode="poll"),
                lambda _collector, result: published.append(result),
            )

        try:
            with patch.object(app, "get_gpu_info_ssh", side_effect=blocking_query):
                collector.start()
                self.assertTrue(entered_query.wait(1))
                collector.stop(timeout=0)
                release_query.set()
                collector.thread.join(timeout=1)
        finally:
            release_query.set()
            if collector.thread is not None:
                collector.thread.join(timeout=1)

        self.assertFalse(collector.thread.is_alive())
        self.assertEqual(published, [])


if __name__ == "__main__":
    unittest.main()
