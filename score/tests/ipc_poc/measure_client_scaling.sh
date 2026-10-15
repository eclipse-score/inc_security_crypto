#!/bin/sh

# Run the IPC POCs for burst and staggered client-scaling measurements.
#
set -u

readonly SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
readonly WORKSPACE_ROOT=$(CDPATH= cd -- "$SCRIPT_DIR/../../.." && pwd)
readonly DEFAULT_OUTPUT_ROOT="$WORKSPACE_ROOT/measurement-results"
readonly DEFAULT_POC_BIN_DIR="$WORKSPACE_ROOT/bazel-bin/score/tests/ipc_poc"

OUTPUT_ROOT="$DEFAULT_OUTPUT_ROOT"
POC_BIN_DIR="$DEFAULT_POC_BIN_DIR"
CLIENT_COUNT=1
CLIENT_THREADS="1 2 4 8 16 32 64 128"
ITERATIONS=10
CAPTURE_LOGS=true
CALL_COUNT=100
SERVER_THREADS=8
SLEEP_MILLISECONDS=0
INCLUDE_QNX_POC=auto
POC_NAMES="poc_low_level poc_low_level_no_reply poc_engine poc_engine_sync poc_unix_socket poc_grpc poc_qnx_message_passing"

case "$CAPTURE_LOGS" in
    true|false) ;;
    *)
        echo "CAPTURE_LOGS must be true or false" >&2
        exit 2
        ;;
esac

case "$INCLUDE_QNX_POC" in
    true|false) ;;
    auto)
        case "$(uname -s 2>/dev/null || printf unknown)" in
            QNX|QNX*) INCLUDE_QNX_POC=true ;;
            *) INCLUDE_QNX_POC=false ;;
        esac
        ;;
    *)
        echo "INCLUDE_QNX_POC must be true, false, or auto" >&2
        exit 2
        ;;
esac

case " $POC_NAMES " in
    *" poc_qnx_message_passing "*)
        if [ "$INCLUDE_QNX_POC" != true ]; then
            POC_NAMES=$(printf '%s' "$POC_NAMES" | sed 's/[[:space:]][[:space:]]*poc_qnx_message_passing\([[:space:]]*\|$\)//')
        fi
        ;;
esac

mkdir -p "$OUTPUT_ROOT"
MANIFEST="$OUTPUT_ROOT/results.csv"
ITERATION_MANIFEST="$OUTPUT_ROOT/iteration_results.csv"
: > "$ITERATION_MANIFEST"
printf '%s\n' 'iteration,poc,mode,client_count,client_threads,server_threads,call_count,sleep_milliseconds,random_wait,round_trip_mean_ns,server_rss_delta_bytes,server_cpu_total_time_delta_ns,client_cpu_total_time_delta_ns,status,log' > "$ITERATION_MANIFEST"

safe_value()
{
    awk -v value="$1" 'BEGIN {
        gsub(/[^A-Za-z0-9._-]/, "_", value)
        printf "%s", value
    }'
}

read_round_trip_mean_ns()
{
    awk '/\[Timing\] average .*RoundTrip:/{ print $4; exit }' "$1"
}

read_server_rss_delta_bytes()
{
    awk '
        /\[Resources\].*_server_thread_creation:/ {
            for (field = 1; field <= NF; field++) {
                if ($field ~ /^resident_delta_bytes=/) {
                    split($field, value, "=")
                    total += value[2]
                    found = 1
                }
            }
        }
        END {
            if (found) {
                print total
            }
        }
    ' "$1"
}

read_server_cpu_total_time_delta_ns()
{
    awk '
        /\[Resources\].*_server_workload:/ {
            for (field = 1; field <= NF; field++) {
                if ($field ~ /^cpu_total_time_delta_ns=/) {
                    split($field, value, "=")
                    total += value[2]
                    found = 1
                }
            }
        }
        END {
            if (found) {
                print total
            }
        }
    ' "$1"
}

read_client_cpu_total_time_delta_ns()
{
    awk '
        /\[Resources\].*_client_workload:/ {
            for (field = 1; field <= NF; field++) {
                if ($field ~ /^cpu_total_time_delta_ns=/) {
                    split($field, value, "=")
                    total += value[2]
                    found = 1
                }
            }
        }
        END {
            if (found) {
                print total
            }
        }
    ' "$1"
}

run_poc_binary()
{
    target=$1
    shift
    case "$(uname -s 2>/dev/null || printf unknown)" in
        QNX|QNX*)
            env LD_LIBRARY_PATH="${LD_LIBRARY_PATH:-}:$target.runfiles/_main/_solib_aarch64le/" "$target" "$@"
            ;;
        *)
            "$target" "$@"
            ;;
    esac
}

run_poc()
{
    iteration=$1
    mode=$2
    poc=$3
    client_count=$4
    client_threads=$5
    random_wait=$6
    poc_binary="$POC_BIN_DIR/$poc"
    if [ "$CAPTURE_LOGS" = true ]; then
        log_file="$OUTPUT_ROOT/$(safe_value "$poc")_$(safe_value "$mode")_iteration$(printf '%02d' "$iteration")_clients$(safe_value "$client_count")_threads$(safe_value "$client_threads").log"
        log_name=$(basename "$log_file")
    else
        log_file=$(mktemp "${TMPDIR:-/tmp}/ipc_poc_measurement.XXXXXX")
        log_name=
    fi

    printf '\n[%s] %s clients=%s client_threads=%s server_threads=%s calls=%s wait=%s\n' \
        "$mode" "$poc" "$client_count" "$client_threads" "$SERVER_THREADS" "$CALL_COUNT" "$random_wait"
    {
        printf '[measurement] iteration=%s mode=%s poc=%s client_count=%s client_threads=%s server_threads=%s call_count=%s sleep_milliseconds=%s random_wait=%s\n' \
            "$iteration" "$mode" "$poc" "$client_count" "$client_threads" "$SERVER_THREADS" "$CALL_COUNT" "$SLEEP_MILLISECONDS" "$random_wait"
        if [ ! -x "$poc_binary" ]; then
            printf '[measurement] missing executable: %s\n' "$poc_binary"
            exit 127
        else
            run_poc_binary "$poc_binary" \
                "--client_count=$client_count" \
                "--client_threads=$client_threads" \
                "--server_threads=$SERVER_THREADS" \
                "--call_count=$CALL_COUNT" \
                "--sleep_milliseconds=$SLEEP_MILLISECONDS" \
                "--random_wait=$random_wait"
        fi
    } > "$log_file" 2>&1
    status=$?
    round_trip_mean_ns=$(read_round_trip_mean_ns "$log_file")
    server_rss_delta_bytes=$(read_server_rss_delta_bytes "$log_file")
    server_cpu_total_time_delta_ns=$(read_server_cpu_total_time_delta_ns "$log_file")
    client_cpu_total_time_delta_ns=$(read_client_cpu_total_time_delta_ns "$log_file")
    [ -n "$round_trip_mean_ns" ] || round_trip_mean_ns=NA
    [ -n "$server_rss_delta_bytes" ] || server_rss_delta_bytes=NA
    [ -n "$server_cpu_total_time_delta_ns" ] || server_cpu_total_time_delta_ns=NA
    [ -n "$client_cpu_total_time_delta_ns" ] || client_cpu_total_time_delta_ns=NA

    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$iteration" "$poc" "$mode" "$client_count" "$client_threads" "$SERVER_THREADS" "$CALL_COUNT" \
        "$SLEEP_MILLISECONDS" "$random_wait" "$round_trip_mean_ns" "$server_rss_delta_bytes" \
        "$server_cpu_total_time_delta_ns" "$client_cpu_total_time_delta_ns" "$status" \
        "$log_name" >> "$ITERATION_MANIFEST"

    if [ "$CAPTURE_LOGS" = false ]; then
        rm -f "$log_file"
    fi

    if [ "$status" -eq 0 ]; then
        if [ "$CAPTURE_LOGS" = true ]; then
            printf '[done] %s\n' "$log_file"
        else
            printf '[done] %s (log capture disabled)\n' "$poc"
        fi
    else
        if [ "$CAPTURE_LOGS" = true ]; then
            printf '[failed status=%s] %s\n' "$status" "$log_file" >&2
        else
            printf '[failed status=%s] %s (log capture disabled)\n' "$status" "$poc" >&2
        fi
    fi
}

run_skipped_qnx_row()
{
    iteration=$1
    mode=$2
    client_count=$3
    client_threads=$4
    random_wait=$5
    printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
        "$iteration" "poc_qnx_message_passing" "$mode" "$client_count" "$client_threads" "$SERVER_THREADS" "$CALL_COUNT" \
        "$SLEEP_MILLISECONDS" "$random_wait" "NA" "NA" "NA" "NA" "SKIPPED_HOST" "" >> "$ITERATION_MANIFEST"
}

iteration=1
while [ "$iteration" -le "$ITERATIONS" ]; do
    printf '\n=== iteration %s/%s ===\n' "$iteration" "$ITERATIONS"
    for poc in $POC_NAMES; do
        for mode in burst staggered; do
            if [ "$mode" = burst ]; then
                random_wait=false
            else
                random_wait=true
            fi

            for client_threads in $CLIENT_THREADS; do
                if [ "$poc" = poc_qnx_message_passing ] && [ "$INCLUDE_QNX_POC" != true ]; then
                    run_skipped_qnx_row "$iteration" "$mode" "$CLIENT_COUNT" "$client_threads" "$random_wait"
                else
                    run_poc "$iteration" "$mode" "$poc" "$CLIENT_COUNT" "$client_threads" "$random_wait"
                fi
            done
        done
    done
    iteration=$((iteration + 1))
done

awk -F, '
    NR == 1 {
        next
    }
    {
        key = $2 FS $3 FS $4 FS $5 FS $6 FS $7 FS $8 FS $9
        if (!(key in first)) {
            first[key] = $0
            order[++count] = key
        }
        iterations[key]++
        if ($14 == 0) {
            successful[key]++
            if ($10 != "NA") {
                round_trip_total[key] += $10
                round_trip_samples[key]++
            }
            if ($11 != "NA") {
                rss_total[key] += $11
                rss_samples[key]++
            }
            if ($12 != "NA") {
                server_cpu_total[key] += $12
                server_cpu_samples[key]++
            }
            if ($13 != "NA") {
                client_cpu_total[key] += $13
                client_cpu_samples[key]++
            }
        } else if ($14 == "SKIPPED_HOST") {
            skipped[key]++
        }
    }
    END {
        print "poc,mode,client_count,client_threads,server_threads,call_count,sleep_milliseconds,random_wait,round_trip_mean_ns,server_rss_delta_bytes,server_cpu_total_time_delta_ns,client_cpu_total_time_delta_ns,iterations,successful_iterations,status,log"
        for (row_number = 1; row_number <= count; row_number++) {
            key = order[row_number]
            split(first[key], fields, FS)
            round_trip_mean = (round_trip_samples[key] ? sprintf("%.0f", round_trip_total[key] / round_trip_samples[key]) : "NA")
            server_rss_delta = (rss_samples[key] ? sprintf("%.0f", rss_total[key] / rss_samples[key]) : "NA")
            server_cpu_mean = (server_cpu_samples[key] ? sprintf("%.0f", server_cpu_total[key] / server_cpu_samples[key]) : "NA")
            client_cpu_mean = (client_cpu_samples[key] ? sprintf("%.0f", client_cpu_total[key] / client_cpu_samples[key]) : "NA")
            if (successful[key] == iterations[key]) {
                status = "OK"
            } else if (successful[key] > 0) {
                status = "PARTIAL"
            } else if (skipped[key] == iterations[key]) {
                status = "SKIPPED_HOST"
            } else {
                status = "FAILED"
            }
            printf "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n", fields[2], fields[3], fields[4], fields[5], fields[6], fields[7], fields[8], fields[9], round_trip_mean, server_rss_delta, server_cpu_mean, client_cpu_mean, iterations[key], successful[key] + 0, status, "iteration_results.csv"
        }
    }
' "$ITERATION_MANIFEST" > "$MANIFEST"

printf '\nResults manifest: %s\n' "$MANIFEST"
printf 'Logs directory: %s\n' "$OUTPUT_ROOT"
printf 'Per-iteration manifest: %s\n' "$ITERATION_MANIFEST"
if awk -F, 'NR > 1 && $15 != "OK" && $15 != "SKIPPED_HOST" { failed = 1 } END { exit failed }' "$MANIFEST"; then
    exit 0
fi
exit 1
