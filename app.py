import json
import subprocess
from flask import Flask, render_template, jsonify
from pathlib import Path

app = Flask(__name__)
CONFIG_PATH = Path(__file__).parent / "config.json"


def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def parse_nvidia_smi(output):
    gpus = {}
    lines = output.split("\n")

    current_gpu_idx = None

    for line in lines:
        if not line.strip():
            continue

        parts = [p.strip() for p in line.split("|")]

        if len(parts) >= 3:
            first_col = parts[1].strip()

            if first_col and first_col[0].isdigit() and "Off" in line:
                tokens = first_col.split()
                if len(tokens) >= 2:
                    try:
                        idx = int(tokens[0])
                        name = " ".join(tokens[1:-1])
                        current_gpu_idx = idx

                        if idx not in gpus:
                            gpus[idx] = {
                                "index": idx,
                                "name": name,
                                "gpu_util": 0,
                                "memory_used": 0,
                                "memory_total": 0,
                                "processes": [],
                            }
                    except:
                        pass

            elif first_col.startswith("N/A") and current_gpu_idx is not None:
                for col in parts:
                    if "MiB" in col and "/" in col:
                        try:
                            vals = col.split("/")
                            mem_used = int(vals[0].strip().replace("MiB", ""))
                            mem_total = int(vals[1].strip().replace("MiB", ""))
                            if current_gpu_idx in gpus:
                                gpus[current_gpu_idx]["memory_used"] = mem_used
                                gpus[current_gpu_idx]["memory_total"] = mem_total
                        except:
                            pass

                    if "%" in col:
                        try:
                            util = int(col.strip().replace("%", "").split()[0])
                            if current_gpu_idx in gpus:
                                gpus[current_gpu_idx]["gpu_util"] = util
                        except:
                            pass

        if "Processes:" in line:
            current_gpu_idx = None

    for line in lines:
        if (
            "|" in line
            and "MiB" in line
            and "PID" not in line
            and "GPU" not in line
            and "=" not in line
        ):
            content = line.replace("|", " ").strip()
            if content and content[0].isdigit():
                tokens = content.split()
                try:
                    gpu_idx = int(tokens[0])
                    pid = int(tokens[3])

                    mem = 0
                    for i, t in enumerate(tokens):
                        if "MiB" in t:
                            try:
                                mem = int(t.replace("MiB", "").replace("...", ""))
                            except:
                                pass

                    if gpu_idx in gpus:
                        gpus[gpu_idx]["processes"].append(
                            {"pid": pid, "memory": mem, "user": "unknown"}
                        )
                except:
                    pass

    return list(gpus.values())


def get_gpu_info_ssh(server):
    try:
        ssh_cmd = [
            "ssh",
            "-p",
            str(server["port"]),
            "-i",
            server["key_file"],
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "ConnectTimeout=5",
            f"{server['username']}@{server['host']}",
            "nvidia-smi",
        ]
        result = subprocess.run(ssh_cmd, capture_output=True, text=True, timeout=10)

        if result.returncode != 0:
            return {"error": result.stderr.strip(), "server": server["name"]}

        gpus = parse_nvidia_smi(result.stdout)

        pids = []
        for gpu in gpus:
            for proc in gpu["processes"]:
                pids.append(str(proc["pid"]))

        if pids:
            pid_list = ",".join(pids)
            ssh_cmd2 = [
                "ssh",
                "-p",
                str(server["port"]),
                "-i",
                server["key_file"],
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "ConnectTimeout=5",
                f"{server['username']}@{server['host']}",
                f"ps -o pid=,user= -p {pid_list} 2>/dev/null",
            ]
            result2 = subprocess.run(
                ssh_cmd2, capture_output=True, text=True, timeout=10
            )

            if result2.stdout:
                user_map = {}
                for line in result2.stdout.strip().split("\n"):
                    if line.strip():
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            user_map[parts[0]] = parts[1]

                for gpu in gpus:
                    for proc in gpu["processes"]:
                        if str(proc["pid"]) in user_map:
                            proc["user"] = user_map[str(proc["pid"])]

        for gpu in gpus:
            user_memory = {}
            for proc in gpu["processes"]:
                user = proc["user"]
                if user not in user_memory:
                    user_memory[user] = 0
                user_memory[user] += proc["memory"]
            gpu["processes"] = [
                {"user": u, "memory": m} for u, m in user_memory.items()
            ]

        return {
            "server": server["name"],
            "host": server["host"],
            "gpus": sorted(gpus, key=lambda x: x["index"]),
            "error": None,
        }
    except subprocess.TimeoutExpired:
        return {"error": "Connection timeout", "server": server["name"]}
    except Exception as e:
        return {"error": str(e), "server": server["name"]}


@app.route("/")
def index():
    config = load_config()
    return render_template(
        "index.html", refresh_interval=config.get("refresh_interval", 5)
    )


@app.route("/api/gpu")
def get_gpu():
    config = load_config()
    results = []
    for server in config["servers"]:
        results.append(get_gpu_info_ssh(server))
    return jsonify(results)


@app.route("/api/config")
def get_config():
    config = load_config()
    return jsonify(config)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
