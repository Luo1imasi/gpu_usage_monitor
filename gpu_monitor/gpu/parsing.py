"""Parsing and normalization for GPU query and stream results."""

import csv
import io
import logging
import re

from ..ssh import sanitize_error


logger = logging.getLogger(__name__)

GPU_COLLECTOR_FRAME_MAX_BYTES = 4 * 1024 * 1024
GPU_COLLECTOR_HEADER_MAX_BYTES = 512


def parse_gpu_query(output):
    gpus = {}
    bus_to_idx = {}
    reader = csv.reader(io.StringIO(output))
    for row in reader:
        if len(row) < 6:
            continue
        try:
            idx = int(row[0].strip())
            bus_id = row[1].strip()
            name = row[2].strip()
            util_str = row[3].strip()
            mem_used_str = row[4].strip()
            mem_total_str = row[5].strip()
            gpu_util = int(float(util_str)) if util_str not in ("[N/A]", "") else 0
            mem_used = (
                int(float(mem_used_str)) if mem_used_str not in ("[N/A]", "") else 0
            )
            mem_total = (
                int(float(mem_total_str))
                if mem_total_str not in ("[N/A]", "")
                else 0
            )
            gpus[idx] = {
                "index": idx,
                "name": name,
                "gpu_util": gpu_util,
                "memory_used": mem_used,
                "memory_total": mem_total,
                "processes": [],
            }
            bus_to_idx[bus_id] = idx
        except (ValueError, IndexError):
            continue
    return gpus, bus_to_idx


def parse_compute_apps(output, bus_to_idx, gpus):
    if not output.strip() or "No running" in output:
        return
    reader = csv.reader(io.StringIO(output))
    for row in reader:
        if len(row) < 3:
            continue
        bus_id = row[0].strip()
        pid_str = row[1].strip()
        mem_str = row[2].strip()
        if bus_id not in bus_to_idx:
            continue
        idx = bus_to_idx[bus_id]
        try:
            pid = int(pid_str)
        except ValueError:
            continue
        mem = 0
        try:
            mem = int(float(mem_str.replace(" MiB", "").replace(",", "").strip()))
        except ValueError:
            pass
        if idx in gpus:
            gpus[idx]["processes"].append(
                {"pid": pid, "memory": mem, "user": "unknown"}
            )


class GPUStreamFrameParser:
    def __init__(self, nonce):
        if not isinstance(nonce, str) or not re.fullmatch(r"[0-9a-f]{32}", nonce):
            raise ValueError("Invalid GPU collector nonce")
        self.nonce = nonce
        self.buffer = bytearray()
        self.data_prefix = f"\x1eGUM1|{nonce}|DATA|".encode("ascii")

    def feed(self, data):
        if data:
            self.buffer.extend(data)
        frames = []

        while True:
            start = self.buffer.find(self.data_prefix)
            if start < 0:
                if len(self.buffer) > GPU_COLLECTOR_FRAME_MAX_BYTES:
                    raise ValueError("GPU collector frame prefix not found")
                keep = max(0, len(self.data_prefix) - 1)
                if len(self.buffer) > keep:
                    del self.buffer[:-keep]
                break
            if start:
                del self.buffer[:start]

            header_end = self.buffer.find(b"\n")
            if header_end < 0:
                if len(self.buffer) > GPU_COLLECTOR_HEADER_MAX_BYTES:
                    raise ValueError("GPU collector frame header is too large")
                break
            if header_end > GPU_COLLECTOR_HEADER_MAX_BYTES:
                raise ValueError("GPU collector frame header is too large")

            fields = bytes(self.buffer[len(self.data_prefix) : header_end]).split(b"|")
            if len(fields) != 7:
                raise ValueError("Invalid GPU collector frame header")
            try:
                seq, epoch, status, gpu_len, apps_len, ps_len, error_len = (
                    int(field) for field in fields
                )
            except ValueError as e:
                raise ValueError("Invalid GPU collector frame number") from e
            if min(seq, epoch, status, gpu_len, apps_len, ps_len, error_len) < 0:
                raise ValueError("Negative GPU collector frame number")

            lengths = (gpu_len, apps_len, ps_len, error_len)
            payload_length = sum(lengths)
            if payload_length > GPU_COLLECTOR_FRAME_MAX_BYTES:
                raise ValueError("GPU collector frame is too large")
            payload_start = header_end + 1
            payload_end = payload_start + payload_length
            footer = f"\x1eGUM1|{self.nonce}|END|{seq}\n".encode("ascii")
            frame_end = payload_end + len(footer)
            if len(self.buffer) < frame_end:
                break
            if bytes(self.buffer[payload_end:frame_end]) != footer:
                raise ValueError("Invalid GPU collector frame footer")

            cursor = payload_start
            segments = []
            for length in lengths:
                segments.append(bytes(self.buffer[cursor : cursor + length]))
                cursor += length
            del self.buffer[:frame_end]
            frames.append(
                {
                    "seq": seq,
                    "epoch": epoch,
                    "status": status,
                    "gpu": segments[0],
                    "apps": segments[1],
                    "ps": segments[2],
                    "error": segments[3],
                }
            )

        return frames


def extract_marked_section(output, start_marker, end_marker):
    start = output.find(start_marker)
    if start == -1:
        return ""
    start += len(start_marker)
    end = output.find(end_marker, start)
    if end == -1:
        return ""
    return output[start:end].strip()


def apply_process_users(ps_output, gpus):
    if not ps_output:
        return

    user_map = {}
    for line in ps_output.strip().split("\n"):
        if line.strip():
            parts = line.strip().split()
            if len(parts) >= 2:
                user_map[parts[0]] = parts[1]

    for gpu in gpus.values():
        for process in gpu["processes"]:
            if str(process["pid"]) in user_map:
                process["user"] = user_map[str(process["pid"])]


def build_gpu_result(
    server,
    status,
    gpu_output,
    apps_output="",
    ps_output="",
    error_output="",
):
    if status != 0 or not gpu_output.strip():
        error_msg = error_output.strip() or "No GPU info returned"
        logger.error("nvidia-smi error on %s: %s", server["name"], error_msg)
        return {"error": sanitize_error(error_msg), "server": server["name"]}

    gpus, bus_to_idx = parse_gpu_query(gpu_output)
    parse_compute_apps(apps_output, bus_to_idx, gpus)
    apply_process_users(ps_output, gpus)

    for gpu in gpus.values():
        user_memory = {}
        for process in gpu["processes"]:
            user = process["user"]
            if user not in user_memory:
                user_memory[user] = 0
            user_memory[user] += process["memory"]

        total_process_memory = sum(user_memory.values())
        if total_process_memory > 0 and gpu["memory_used"] > 0:
            ratio = gpu["memory_used"] / total_process_memory
            if ratio > 1.5:
                if len(user_memory) == 1:
                    user_memory[list(user_memory.keys())[0]] = gpu["memory_used"]
                else:
                    for user in user_memory:
                        proportion = user_memory[user] / total_process_memory
                        user_memory[user] = int(gpu["memory_used"] * proportion)

        gpu["processes"] = [
            {"user": user, "memory": memory}
            for user, memory in user_memory.items()
        ]

    return {
        "server": server["name"],
        "gpus": sorted(gpus.values(), key=lambda item: item["index"]),
        "error": None,
    }
