import csv
import io
import json
import os
import re
import time
import threading
import logging
import atexit
from concurrent.futures import ThreadPoolExecutor, as_completed
from flask import Flask, render_template, jsonify
from pathlib import Path
import paramiko

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

app = Flask(__name__)
CONFIG_PATH = Path(__file__).parent / "config.json"

cached_data = []
last_update = None
data_lock = threading.Lock()
executor = ThreadPoolExecutor(max_workers=10)
ssh_clients = {}
ssh_lock = threading.Lock()

_config_cache = None
_config_mtime = 0.0


def cleanup():
    logger.info("Cleaning up resources...")
    executor.shutdown(wait=False)
    with ssh_lock:
        for client in ssh_clients.values():
            try:
                client.close()
            except Exception as e:
                logger.debug(f"Error closing SSH client: {e}")
        ssh_clients.clear()


atexit.register(cleanup)


def load_config():
    global _config_cache, _config_mtime
    try:
        mtime = CONFIG_PATH.stat().st_mtime
        if _config_cache is not None and mtime == _config_mtime:
            return _config_cache
        with open(CONFIG_PATH) as f:
            _config_cache = json.load(f)
            _config_mtime = mtime
            return _config_cache
    except FileNotFoundError:
        logger.error(f"Config file not found: {CONFIG_PATH}")
        return {"servers": [], "refresh_interval": 5}
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in config file: {e}")
        return {"servers": [], "refresh_interval": 5}


def get_ssh_client(server):
    key = (server["host"], server["port"], server["username"])

    with ssh_lock:
        if key in ssh_clients:
            client = ssh_clients[key]
            if client.get_transport() and client.get_transport().is_active():
                return client
            try:
                client.close()
            except Exception as e:
                logger.debug(f"Error closing stale SSH client: {e}")
            del ssh_clients[key]

    new_client = paramiko.SSHClient()
    new_client.load_system_host_keys()
    if server.get("accept_unknown_host", False):
        new_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    key_file = os.path.expanduser(server["key_file"])
    new_client.connect(
        hostname=server["host"],
        port=server["port"],
        username=server["username"],
        key_filename=key_file,
        timeout=10,
        banner_timeout=10,
    )
    transport = new_client.get_transport()
    if transport:
        transport.set_keepalive(30)

    with ssh_lock:
        if key in ssh_clients:
            old = ssh_clients[key]
            if old.get_transport() and old.get_transport().is_active():
                new_client.close()
                return old
            try:
                old.close()
            except Exception:
                pass
        ssh_clients[key] = new_client
        return new_client


def invalidate_ssh_client(server):
    key = (server["host"], server["port"], server["username"])
    with ssh_lock:
        if key in ssh_clients:
            try:
                ssh_clients[key].close()
            except Exception:
                pass
            del ssh_clients[key]


def run_ssh_command(client, command, timeout=30):
    stdin = stdout = stderr = None
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
        out = stdout.read().decode()
        err = stderr.read().decode()
        return out, err
    finally:
        for ch in (stdin, stdout, stderr):
            if ch is not None:
                try:
                    ch.close()
                except Exception:
                    pass


def sanitize_error(error_msg):
    sanitized = re.sub(r"\d{1,3}(\.\d{1,3}){3}", "***", error_msg)
    sanitized = re.sub(r":\d{4,5}", ":***", sanitized)
    sanitized = re.sub(r"/home/[\w./\-]+", "/***", sanitized)
    sanitized = re.sub(r"/root/[\w./\-]+", "/***", sanitized)
    return sanitized


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
                int(float(mem_total_str)) if mem_total_str not in ("[N/A]", "") else 0
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


def get_gpu_info_ssh(server):
    try:
        client = get_ssh_client(server)

        gpu_fields = "index,gpu_bus_id,name,utilization.gpu,memory.used,memory.total"
        out, err = run_ssh_command(
            client,
            f"nvidia-smi --query-gpu={gpu_fields} --format=csv,noheader,nounits",
        )
        if not out.strip():
            error_msg = err.strip() if err else "No GPU info returned"
            logger.error(f"nvidia-smi error on {server['name']}: {error_msg}")
            return {"error": sanitize_error(error_msg), "server": server["name"]}

        gpus, bus_to_idx = parse_gpu_query(out)

        proc_out, _ = run_ssh_command(
            client,
            "nvidia-smi --query-compute-apps=gpu_bus_id,pid,used_gpu_memory --format=csv,noheader",
        )
        parse_compute_apps(proc_out, bus_to_idx, gpus)

        pids = []
        for gpu in gpus.values():
            for proc in gpu["processes"]:
                pids.append(str(proc["pid"]))

        if pids:
            pid_list = ",".join(pids)
            ps_out, _ = run_ssh_command(
                client,
                f"ps -o pid=,user= -p {pid_list} 2>/dev/null",
            )
            if ps_out:
                user_map = {}
                for line in ps_out.strip().split("\n"):
                    if line.strip():
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            user_map[parts[0]] = parts[1]
                for gpu in gpus.values():
                    for proc in gpu["processes"]:
                        if str(proc["pid"]) in user_map:
                            proc["user"] = user_map[str(proc["pid"])]

        for gpu in gpus.values():
            user_memory = {}
            for proc in gpu["processes"]:
                user = proc["user"]
                if user not in user_memory:
                    user_memory[user] = 0
                user_memory[user] += proc["memory"]

            total_proc_mem = sum(user_memory.values())
            if total_proc_mem > 0 and gpu["memory_used"] > 0:
                ratio = gpu["memory_used"] / total_proc_mem
                if ratio > 1.5:
                    if len(user_memory) == 1:
                        user_memory[list(user_memory.keys())[0]] = gpu["memory_used"]
                    else:
                        for user in user_memory:
                            proportion = user_memory[user] / total_proc_mem
                            user_memory[user] = int(gpu["memory_used"] * proportion)

            gpu["processes"] = [
                {"user": u, "memory": m} for u, m in user_memory.items()
            ]

        return {
            "server": server["name"],
            "gpus": sorted(gpus.values(), key=lambda x: x["index"]),
            "error": None,
        }
    except Exception as e:
        logger.error(f"Error getting GPU info for {server['name']}: {e}")
        invalidate_ssh_client(server)
        return {"error": sanitize_error(str(e)), "server": server["name"]}


def refresh_data():
    global cached_data, last_update

    config = load_config()
    results = []

    futures = {
        executor.submit(get_gpu_info_ssh, server): server
        for server in config["servers"]
    }
    for future in as_completed(futures):
        try:
            results.append(future.result())
        except Exception as e:
            server = futures[future]
            logger.error(f"Unexpected error for {server['name']}: {e}")
            results.append({"error": sanitize_error(str(e)), "server": server["name"]})

    with data_lock:
        cached_data = results
        last_update = time.time()

    logger.info(f"Refreshed data for {len(results)} servers")


def background_worker():
    logger.info("Starting background worker")
    while True:
        try:
            refresh_data()
        except Exception as e:
            logger.error(f"Error in background worker: {e}")
        config = load_config()
        time.sleep(config.get("refresh_interval", 5))


@app.route("/")
def index():
    config = load_config()
    return render_template(
        "index.html", refresh_interval=config.get("refresh_interval", 5)
    )


@app.route("/api/gpu")
def get_gpu():
    with data_lock:
        return jsonify(cached_data)


@app.route("/api/servers")
def get_servers():
    config = load_config()
    servers = [{"name": s["name"]} for s in config.get("servers", [])]
    return jsonify(
        {"servers": servers, "refresh_interval": config.get("refresh_interval", 5)}
    )


if __name__ == "__main__":
    logger.info("Starting GPU usage monitor...")
    refresh_data()

    worker_thread = threading.Thread(target=background_worker, daemon=True)
    worker_thread.start()

    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    logger.info(f"Running Flask app on 0.0.0.0:5000 (debug={debug})")
    app.run(host="0.0.0.0", port=5000, debug=debug)
