"""Remote commands used to sample NVIDIA GPU state."""

import shlex


GPU_INFO_GPU_START = "__GPU_MONITOR_GPU_START__"
GPU_INFO_GPU_END = "__GPU_MONITOR_GPU_END__"
GPU_INFO_APPS_START = "__GPU_MONITOR_APPS_START__"
GPU_INFO_APPS_END = "__GPU_MONITOR_APPS_END__"
GPU_INFO_PS_START = "__GPU_MONITOR_PS_START__"
GPU_INFO_PS_END = "__GPU_MONITOR_PS_END__"

GPU_COMBINED_QUERY_MARKER = "__GPU_MONITOR_COMBINED_QUERY_START__"
GPU_COMBINED_QUERY_AWK = r"""
function trim(value) {
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
    return value
}

function numeric_value(value, cleaned) {
    cleaned = value
    gsub(/[^0-9.+-]/, "", cleaned)
    if (cleaned == "" || cleaned == "." || cleaned == "+" || cleaned == "-") {
        return 0
    }
    return int(cleaned + 0)
}

function fail(reason) {
    parse_error = 1
    if (error_reason == "") {
        error_reason = reason
    }
}

function reset_process() {
    process_pid = ""
    process_type = ""
    process_memory = 0
    process_memory_seen = 0
}

function flush_process() {
    if (process_pid == "") {
        reset_process()
        return
    }
    if (process_pid !~ /^[0-9]+$/ || process_type == "") {
        fail("invalid process record")
        reset_process()
        return
    }
    if (process_type ~ /C/) {
        if (!process_memory_seen) {
            fail("missing process memory")
            reset_process()
            return
        }
        process_count++
        process_bus[process_count] = current_bus
        process_id[process_count] = process_pid
        process_memory_value[process_count] = process_memory
    }
    reset_process()
}

function parse_topology(line, first_comma, remainder, second_comma, idx, bus, name) {
    first_comma = index(line, ",")
    if (first_comma == 0) {
        return
    }
    idx = trim(substr(line, 1, first_comma - 1))
    remainder = substr(line, first_comma + 1)
    second_comma = index(remainder, ",")
    if (second_comma == 0) {
        return
    }
    bus = toupper(trim(substr(remainder, 1, second_comma - 1)))
    name = trim(substr(remainder, second_comma + 1))
    if (idx !~ /^[0-9]+$/ || bus == "" || name == "") {
        fail("invalid topology record")
        return
    }
    if ((bus in topology_index) || (idx in topology_index_seen)) {
        fail("duplicate topology record")
        return
    }
    topology_count++
    topology_bus[topology_count] = bus
    topology_index[bus] = idx
    topology_index_seen[idx] = 1
    topology_name[bus] = name
}

BEGIN {
    in_query = 0
    section = ""
    current_bus = ""
    parse_error = 0
    error_reason = ""
    reset_process()
}

$0 == marker {
    in_query = 1
    next
}

!in_query {
    if (trim($0) != "") {
        parse_topology($0)
    }
    next
}

{
    stripped = trim($0)

    if (stripped ~ /^GPU[[:space:]]+[[:xdigit:]]+:/) {
        flush_process()
        split(stripped, header_fields, /[[:space:]]+/)
        current_bus = toupper(header_fields[2])
        if (!(current_bus in topology_index)) {
            fail("unknown GPU bus id")
        } else if (seen_gpu[current_bus]) {
            fail("duplicate GPU bus id")
        }
        seen_gpu[current_bus] = 1
        section = ""
        reset_process()
        next
    }

    if ($0 ~ /^    [^[:space:]]/) {
        section = ""
        if (stripped == "FB Memory Usage") {
            section = "fb_memory"
        } else if (stripped == "Utilization") {
            section = "utilization"
        } else if (stripped ~ /^Processes([[:space:]]*:[[:space:]]*None)?$/) {
            section = "processes"
            reset_process()
        }
        next
    }

    separator = index(stripped, ":")
    if (separator == 0 || current_bus == "") {
        next
    }
    key = trim(substr(stripped, 1, separator - 1))
    value = trim(substr(stripped, separator + 1))

    if (section == "fb_memory") {
        if (key == "Total") {
            memory_total[current_bus] = numeric_value(value)
            memory_total_seen[current_bus] = 1
        } else if (key == "Used") {
            memory_used[current_bus] = numeric_value(value)
            memory_used_seen[current_bus] = 1
        }
        next
    }

    if (section == "utilization" && toupper(key) == "GPU") {
        gpu_utilization[current_bus] = numeric_value(value)
        gpu_utilization_seen[current_bus] = 1
        next
    }

    if (section == "processes") {
        if (key == "Process ID") {
            flush_process()
            process_pid = value
        } else if (key == "Type") {
            process_type = value
        } else if (key == "Used GPU Memory") {
            process_memory = numeric_value(value)
            process_memory_seen = 1
        }
    }
}

END {
    flush_process()
    if (!in_query || topology_count == 0) {
        fail("missing topology or query marker")
    }
    for (i = 1; i <= topology_count; i++) {
        bus = topology_bus[i]
        if (!seen_gpu[bus] || !memory_total_seen[bus] || !memory_used_seen[bus] || !gpu_utilization_seen[bus]) {
            fail("incomplete GPU record")
        }
    }
    if (parse_error) {
        printf "E|%s\n", error_reason
        exit 65
    }
    for (i = 1; i <= topology_count; i++) {
        bus = topology_bus[i]
        printf "G|%s, %s, %s, %s, %s, %s\n", topology_index[bus], bus, topology_name[bus], gpu_utilization[bus], memory_used[bus], memory_total[bus]
    }
    for (i = 1; i <= process_count; i++) {
        printf "A|%s, %s, %s\n", process_bus[i], process_id[i], process_memory_value[i]
    }
}
""".strip()


def build_gpu_info_command():
    gpu_fields = "index,gpu_bus_id,name,utilization.gpu,memory.used,memory.total"
    app_fields = "gpu_bus_id,pid,used_gpu_memory"
    return f"""
gpu_status=0
echo {GPU_INFO_GPU_START}
gpu_output="$(nvidia-smi --query-gpu={gpu_fields} --format=csv,noheader,nounits)" || gpu_status=$?
printf '%s\n' "$gpu_output"
echo {GPU_INFO_GPU_END}
echo {GPU_INFO_APPS_START}
has_gpu_memory="$(printf '%s\n' "$gpu_output" | awk -F, '{{gsub(/^[ \\t]+|[ \\t]+$/, "", $5); if (($5 + 0) > 0) {{print "1"; exit}}}}')"
apps=""
if [ "$gpu_status" -eq 0 ] && [ "$has_gpu_memory" = "1" ]; then
    apps="$(nvidia-smi --query-compute-apps={app_fields} --format=csv,noheader 2>/dev/null || true)"
fi
printf '%s\n' "$apps"
echo {GPU_INFO_APPS_END}
echo {GPU_INFO_PS_START}
pids="$(printf '%s\n' "$apps" | awk -F, '{{gsub(/^[ \\t]+|[ \\t]+$/, "", $2); if ($2 ~ /^[0-9]+$/) {{printf "%s%s", sep, $2; sep=","}}}}')"
if [ -n "$pids" ]; then
    ps -o pid=,user= -p "$pids" 2>/dev/null
fi
echo {GPU_INFO_PS_END}
exit "$gpu_status"
""".strip()


def build_gpu_collector_command(nonce, sample_timeout):
    topology_fields = "index,gpu_bus_id,name"
    combined_query_awk = shlex.quote(GPU_COMBINED_QUERY_AWK)
    combined_query_marker = shlex.quote(GPU_COMBINED_QUERY_MARKER)
    sample_timeout = max(1, int(sample_timeout))
    script = f"""
LC_ALL=C
export LC_ALL
nonce={shlex.quote(nonce)}
topology_fields={shlex.quote(topology_fields)}
sample_timeout={sample_timeout}
has_timeout=0
if command -v timeout >/dev/null 2>&1; then
    has_timeout=1
fi
run_limited() {{
    if [ "$has_timeout" = "1" ]; then
        timeout "$sample_timeout" "$@"
    else
        "$@"
    fi
}}
trap 'exit 0' HUP INT TERM PIPE

topology_capture="$(run_limited nvidia-smi "--query-gpu=$topology_fields" --format=csv,noheader,nounits 2>&1)"
topology_status=$?
if [ "$topology_status" -ne 0 ] || [ -z "$topology_capture" ]; then
    printf '%s\n' "$topology_capture" >&2
    if [ "$topology_status" -eq 0 ]; then
        topology_status=1
    fi
    exit "$topology_status"
fi
topology_count="$(printf '%s\n' "$topology_capture" | awk -F, 'NF >= 3 {{ count++ }} END {{ print count + 0 }}')"
if [ "$topology_count" -le 0 ]; then
    printf '%s\n' 'Unable to parse GPU topology' >&2
    exit 1
fi

while IFS= read -r request; do
    case "$request" in
        POLL\\|*)
            seq="${{request#POLL|}}"
            case "$seq" in
                ''|*[!0-9]*) continue ;;
            esac
            ;;
        *)
            continue
            ;;
    esac

    gpu_capture="$(run_limited nvidia-smi -q -d MEMORY,UTILIZATION,PIDS 2>&1)"
    gpu_status=$?
    gpu_output=""
    gpu_error=""
    apps=""
    restart_after_frame=0
    if [ "$gpu_status" -eq 0 ]; then
        parsed_output="$(
            {{
                printf '%s\n' "$topology_capture"
                printf '%s\n' {combined_query_marker}
                printf '%s\n' "$gpu_capture"
            }} | awk -v marker={combined_query_marker} {combined_query_awk}
        )"
        parse_status=$?
        gpu_output="$(printf '%s\n' "$parsed_output" | awk 'substr($0, 1, 2) == "G|" {{ print substr($0, 3) }}')"
        apps="$(printf '%s\n' "$parsed_output" | awk 'substr($0, 1, 2) == "A|" {{ print substr($0, 3) }}')"
        parse_error_message="$(printf '%s\n' "$parsed_output" | awk 'substr($0, 1, 2) == "E|" {{ print substr($0, 3); exit }}')"
        parsed_gpu_count="$(printf '%s\n' "$gpu_output" | awk 'NF {{ count++ }} END {{ print count + 0 }}')"
        if [ "$parse_status" -ne 0 ] || [ "$parsed_gpu_count" -ne "$topology_count" ]; then
            gpu_status=1
            gpu_output=""
            apps=""
            restart_after_frame=1
            if [ -n "$parse_error_message" ]; then
                gpu_error="Unable to parse combined nvidia-smi output: $parse_error_message"
            else
                gpu_error="Unable to parse combined nvidia-smi output (expected $topology_count GPUs, got $parsed_gpu_count)"
            fi
        fi
    else
        gpu_error="$gpu_capture"
    fi

    ps_output=""
    pids="$(printf '%s\\n' "$apps" | awk -F, '{{gsub(/^[ \\t]+|[ \\t]+$/, "", $2); if ($2 ~ /^[0-9]+$/) {{printf "%s%s", sep, $2; sep=","}}}}')"
    if [ -n "$pids" ]; then
        ps_output="$(ps -o pid=,user= -p "$pids" 2>/dev/null || true)"
    fi

    epoch="$(date +%s 2>/dev/null || printf 0)"
    printf '\\036GUM1|%s|DATA|%s|%s|%s|%s|%s|%s|%s\\n' \\
        "$nonce" "$seq" "$epoch" "$gpu_status" \\
        "${{#gpu_output}}" "${{#apps}}" "${{#ps_output}}" "${{#gpu_error}}" || exit 1
    printf '%s%s%s%s' "$gpu_output" "$apps" "$ps_output" "$gpu_error" || exit 1
    printf '\\036GUM1|%s|END|%s\\n' "$nonce" "$seq" || exit 1
    if [ "$restart_after_frame" -eq 1 ]; then
        exit 65
    fi
done
""".strip()
    return "sh -c " + shlex.quote(script)
