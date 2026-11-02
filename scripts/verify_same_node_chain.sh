#!/usr/bin/env bash
set -euo pipefail

NS_NAMESPACE="${NS_NAMESPACE:-nse-ovs-dpi}"
NSM_SYSTEM_NAMESPACE="${NSM_SYSTEM_NAMESPACE:-nsm-system}"
CLIENT_POD_PREFIX="${CLIENT_POD_PREFIX:-nsc-ovs-client-}"
DPI_POD_PREFIX="${DPI_POD_PREFIX:-nse-ovs-dpi-}"
SERVER_POD_PREFIX="${SERVER_POD_PREFIX:-nse-ovs-server-}"
CLIENT_IFACE="${CLIENT_IFACE:-nsm-1}"
CLIENT_CONTAINER="${CLIENT_CONTAINER:-client}"
CLIENT_CMD_CONTAINER="${CLIENT_CMD_CONTAINER:-cmd-nsc}"
DPI_CONTAINER="${DPI_CONTAINER:-nse}"
SERVER_CONTAINER="${SERVER_CONTAINER:-server}"
HTTP_PORT="${HTTP_PORT:-8080}"
HTTP_SERVER_ROOT="${HTTP_SERVER_ROOT:-/tmp/nse-dpi-http}"
DPI_TEMP_ROOT="${DPI_TEMP_ROOT:-/tmp/nse-ovs-dpi}"
EVE_WAIT_SECONDS="${EVE_WAIT_SECONDS:-60}"
KUBECTL="${KUBECTL:-kubectl}"
EXPECT_RESULT="alert"
PRINT_EVE="false"

usage() {
  cat <<'EOF'
Usage: ./scripts/verify_same_node_chain.sh [--expect-alert|--expect-clean] [--print-eve]

Verify the same-node NSM OVS DPI chain and print path evidence plus Suricata alert proof.

Options:
  --expect-alert  Expect the default baseline rules to generate alerts. Default.
  --expect-clean  Expect the same HTTP requests to produce no alerts.
  --print-eve     Print the newly appended EVE lines after verification.
  -h, --help      Show this help text.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --expect-alert)
      EXPECT_RESULT="alert"
      shift
      ;;
    --expect-clean)
      EXPECT_RESULT="clean"
      shift
      ;;
    --print-eve)
      PRINT_EVE="true"
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

tmpdir="$(mktemp -d)"
cleanup_http_servers() {
  if [[ -n "${server_pod:-}" ]]; then
    pod_sh "$NS_NAMESPACE" "$server_pod" "$SERVER_CONTAINER" "
      for pidfile in \"$HTTP_SERVER_ROOT\"/*.pid; do
        [ -f \"\$pidfile\" ] || continue
        kill \"\$(cat \"\$pidfile\")\" 2>/dev/null || true
      done
      rm -rf \"$HTTP_SERVER_ROOT\"
    " >/dev/null 2>&1 || true
  fi
}
trap 'cleanup_http_servers; rm -rf "$tmpdir"' EXIT

die() {
  echo "ERROR: $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

run_kubectl() {
  "$KUBECTL" "$@"
}

sanitize_name() {
  local value="$1"
  [[ "$value" =~ ^[A-Za-z0-9._:-]+$ ]] || die "unexpected name: $value"
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

fmt_count() {
  local value="$1"
  local sign=""
  local digits="$value"
  if [[ "$digits" == -* ]]; then
    sign="-"
    digits="${digits#-}"
  fi
  local out=""
  while ((${#digits} > 3)); do
    out=",${digits: -3}${out}"
    digits="${digits:0:${#digits}-3}"
  done
  printf '%s%s%s' "$sign" "$digits" "$out"
}

fmt_bytes_gib() {
  awk -v value="$1" 'BEGIN { printf "%.6f GiB", value / 1024 / 1024 / 1024 }'
}

kv_get() {
  local file="$1"
  local key="$2"
  awk -F'=' -v key="$key" '$1 == key { print $2; exit }' "$file"
}

delta_from_files() {
  local before_file="$1"
  local after_file="$2"
  local key="$3"
  local before_value after_value
  before_value="$(kv_get "$before_file" "$key")"
  after_value="$(kv_get "$after_file" "$key")"
  [[ -n "$before_value" ]] || die "missing before counter $key in $before_file"
  [[ -n "$after_value" ]] || die "missing after counter $key in $after_file"
  echo $((after_value - before_value))
}

get_running_pod_by_prefix() {
  local namespace="$1"
  local prefix="$2"
  run_kubectl get pods -n "$namespace" --no-headers \
    -o custom-columns=NAME:.metadata.name,PHASE:.status.phase \
    | awk -v prefix="$prefix" '$1 ~ ("^" prefix) && $2 == "Running" { print $1; exit }'
}

get_forwarder_pod_on_node() {
  local node_name="$1"
  run_kubectl get pods -n "$NSM_SYSTEM_NAMESPACE" --no-headers \
    -o custom-columns=NAME:.metadata.name,PHASE:.status.phase,NODE:.spec.nodeName \
    | awk -v node_name="$node_name" '$1 ~ /^forwarder-ovs-/ && $2 == "Running" && $3 == node_name { print $1; exit }'
}

require_container() {
  local namespace="$1"
  local pod_name="$2"
  local container_name="$3"
  if ! run_kubectl get pod -n "$namespace" "$pod_name" \
    -o jsonpath='{range .spec.containers[*]}{.name}{"\n"}{end}' | grep -Fxq "$container_name"; then
    die "container $container_name not found in pod $namespace/$pod_name"
  fi
}

pod_sh() {
  local namespace="$1"
  local pod_name="$2"
  local container_name="$3"
  local command="$4"
  run_kubectl exec -n "$namespace" "$pod_name" -c "$container_name" -- sh -eu -c "$command"
}

list_suricata_processes() {
  local namespace="$1"
  local pod_name="$2"
  local container_name="$3"
  pod_sh "$namespace" "$pod_name" "$container_name" "ps -ef | grep '[s]uricata' || true"
}

list_dpi_session_dirs() {
  local namespace="$1"
  local pod_name="$2"
  local container_name="$3"
  pod_sh "$namespace" "$pod_name" "$container_name" \
    "find '$DPI_TEMP_ROOT' -mindepth 1 -maxdepth 1 -type d -name 'session-*' 2>/dev/null | sort"
}

list_named_links() {
  local namespace="$1"
  local pod_name="$2"
  local container_name="$3"
  local pattern="$4"
  pod_sh "$namespace" "$pod_name" "$container_name" "
    ip -o link show | awk -F': ' '
      {
        name = \$2
        sub(/ .*/, \"\", name)
        sub(/@.*/, \"\", name)
        if (name ~ /$pattern/) {
          print \$0
        }
      }'
  "
}

parse_link_name() {
  local line="$1"
  local token
  token="$(printf '%s\n' "$line" | awk -F': ' '{print $2}' | awk '{print $1}')"
  token="${token%:}"
  printf '%s' "${token%%@*}"
}

parse_link_peer_ifindex() {
  local line="$1"
  local token
  token="$(printf '%s\n' "$line" | awk -F': ' '{print $2}' | awk '{print $1}')"
  token="${token%:}"
  printf '%s\n' "$token" | sed -n 's/.*@if\([0-9][0-9]*\)$/\1/p'
}

capture_netdev_stats() {
  local namespace="$1"
  local pod_name="$2"
  local container_name="$3"
  local iface_name="$4"
  sanitize_name "$iface_name"
  pod_sh "$namespace" "$pod_name" "$container_name" \
    "for key in rx_bytes rx_packets tx_bytes tx_packets; do printf '%s=%s\n' \"\$key\" \"\$(cat /sys/class/net/$iface_name/statistics/\$key)\"; done"
}

capture_ofport_stats() {
  local forwarder_pod="$1"
  local ofport="$2"
  sanitize_name "$ofport"
  run_kubectl exec -n "$NSM_SYSTEM_NAMESPACE" "$forwarder_pod" -- \
    ovs-ofctl dump-ports br-nsm "$ofport" \
    | awk '
        /port [0-9]+: rx pkts=/ {
          gsub(/,/, "")
          match($0, /pkts=([0-9]+)/, rx_pkts)
          match($0, /bytes=([0-9]+)/, rx_b)
          rx_packets = rx_pkts[1]
          rx_bytes = rx_b[1]
        }
        /tx pkts=/ {
          gsub(/,/, "")
          match($0, /pkts=([0-9]+)/, tx_pkts)
          match($0, /bytes=([0-9]+)/, tx_b)
          tx_packets = tx_pkts[1]
          tx_bytes = tx_b[1]
        }
        END {
          printf "rx_bytes=%s\nrx_packets=%s\ntx_bytes=%s\ntx_packets=%s\n", rx_bytes, rx_packets, tx_bytes, tx_packets
        }'
}

save_snapshot() {
  local file_path="$1"
  shift
  "$@" >"$file_path"
}

forwarder_port_name_for_ifindex() {
  local links_file="$1"
  local ifindex="$2"
  awk -F': ' -v ifindex="$ifindex" '
    $1 == ifindex {
      split($2, fields, " ")
      name = fields[1]
      sub(/:$/, "", name)
      sub(/@.*/, "", name)
      print name
      exit
    }' "$links_file"
}

port_conn_id() {
  local port_name="$1"
  printf '%s' "$port_name" | sed -E 's/^tap(src|dst)-//'
}

lookup_ofport() {
  local forwarder_pod="$1"
  local port_name="$2"
  sanitize_name "$port_name"
  trim "$(run_kubectl exec -n "$NSM_SYSTEM_NAMESPACE" "$forwarder_pod" -- ovs-vsctl get Interface "$port_name" ofport)"
}

render_leg_line() {
  local label="$1"
  local pod_name="$2"
  local iface_name="$3"
  local detail="$4"
  printf "%-14s %-42s %-24s %s\n" "$label" "$pod_name" "$iface_name" "$detail"
}

prepare_http_server() {
  local namespace="$1"
  local pod_name="$2"
  local container_name="$3"
  pod_sh "$namespace" "$pod_name" "$container_name" "
    rm -rf \"$HTTP_SERVER_ROOT\"
    mkdir -p \"$HTTP_SERVER_ROOT\"
    sh -c '
      while true; do
        printf \"%b\" \"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 15\r\n\r\nnse-ovs-dpi-ok\n\" | nc -l -p \"$HTTP_PORT\" -w 1
      done
    ' >/tmp/nse-dpi-http.log 2>&1 &
    echo \$! >\"$HTTP_SERVER_ROOT/http.pid\"
    sleep 1
  "
}

run_http_request() {
  local namespace="$1"
  local pod_name="$2"
  local container_name="$3"
  local server_ip="$4"
  local request_payload="$5"
  run_kubectl exec -n "$namespace" "$pod_name" -c "$container_name" -- \
    sh -eu -c "printf '%b' '$request_payload' | nc -w 3 '$server_ip' '$HTTP_PORT'"
}

wait_for_suricata() {
  local namespace="$1"
  local pod_name="$2"
  local container_name="$3"
  local timeout_seconds="$4"
  local deadline=$((SECONDS + timeout_seconds))
  local active_processes=""
  local session_dirs=""

  while (( SECONDS < deadline )); do
    active_processes="$(list_suricata_processes "$namespace" "$pod_name" "$container_name")"
    session_dirs="$(list_dpi_session_dirs "$namespace" "$pod_name" "$container_name")"
    if [[ -n "$active_processes" || -n "$session_dirs" ]]; then
      return 0
    fi
    sleep 1
  done

  return 1
}

wait_for_dpi_interfaces() {
  local namespace="$1"
  local pod_name="$2"
  local container_name="$3"
  local timeout_seconds="$4"
  local deadline=$((SECONDS + timeout_seconds))
  local interface_count=0
  local bridge_line=""

  while (( SECONDS < deadline )); do
    interface_count="$(list_named_links "$namespace" "$pod_name" "$container_name" '^nse-ovs-' | awk 'END { print NR + 0 }')"
    bridge_line="$(trim "$(list_named_links "$namespace" "$pod_name" "$container_name" '^nsmbr' | head -n1)")"
    if [[ "$interface_count" == "2" && -n "$bridge_line" ]]; then
      return 0
    fi
    sleep 1
  done

  return 1
}

find_eve_file() {
  local namespace="$1"
  local pod_name="$2"
  local container_name="$3"
  pod_sh "$namespace" "$pod_name" "$container_name" \
    "find '$DPI_TEMP_ROOT' -name eve.json -type f 2>/dev/null | sort | tail -n1"
}

wait_for_eve_file() {
  local namespace="$1"
  local pod_name="$2"
  local container_name="$3"
  local timeout_seconds="$4"
  local deadline=$((SECONDS + timeout_seconds))
  local eve_path=""

  while (( SECONDS < deadline )); do
    eve_path="$(trim "$(find_eve_file "$namespace" "$pod_name" "$container_name" || true)")"
    if [[ -n "$eve_path" ]]; then
      printf '%s' "$eve_path"
      return 0
    fi
    sleep 1
  done

  return 1
}

eve_line_count() {
  local namespace="$1"
  local pod_name="$2"
  local container_name="$3"
  local eve_file="$4"
  pod_sh "$namespace" "$pod_name" "$container_name" "wc -l < '$eve_file' 2>/dev/null || echo 0"
}

copy_new_eve_lines() {
  local namespace="$1"
  local pod_name="$2"
  local container_name="$3"
  local eve_file="$4"
  local before_lines="$5"
  local output_file="$6"

  if (( before_lines > 0 )); then
    pod_sh "$namespace" "$pod_name" "$container_name" "sed -n '$((before_lines + 1)),999999p' '$eve_file'" >"$output_file"
  else
    pod_sh "$namespace" "$pod_name" "$container_name" "cat '$eve_file'" >"$output_file"
  fi
}

count_matches() {
  local file_path="$1"
  local pattern="$2"
  awk -v pattern="$pattern" 'index($0, pattern) { count++ } END { print count + 0 }' "$file_path"
}

need_cmd awk
need_cmd grep
need_cmd kubectl
need_cmd sed

client_pod="$(get_running_pod_by_prefix "$NS_NAMESPACE" "$CLIENT_POD_PREFIX")"
dpi_pod="$(get_running_pod_by_prefix "$NS_NAMESPACE" "$DPI_POD_PREFIX")"
server_pod="$(get_running_pod_by_prefix "$NS_NAMESPACE" "$SERVER_POD_PREFIX")"

[[ -n "$client_pod" ]] || die "running client pod with prefix $CLIENT_POD_PREFIX not found in namespace $NS_NAMESPACE"
[[ -n "$dpi_pod" ]] || die "running dpi pod with prefix $DPI_POD_PREFIX not found in namespace $NS_NAMESPACE"
[[ -n "$server_pod" ]] || die "running server pod with prefix $SERVER_POD_PREFIX not found in namespace $NS_NAMESPACE"

client_node="$(trim "$(run_kubectl get pod -n "$NS_NAMESPACE" "$client_pod" -o jsonpath='{.spec.nodeName}')")"
[[ -n "$client_node" ]] || die "unable to determine node for pod $client_pod"
forwarder_pod="$(get_forwarder_pod_on_node "$client_node")"
[[ -n "$forwarder_pod" ]] || die "running forwarder-ovs pod not found on node $client_node"

require_container "$NS_NAMESPACE" "$client_pod" "$CLIENT_CONTAINER"
require_container "$NS_NAMESPACE" "$client_pod" "$CLIENT_CMD_CONTAINER"
require_container "$NS_NAMESPACE" "$dpi_pod" "$DPI_CONTAINER"
require_container "$NS_NAMESPACE" "$server_pod" "$SERVER_CONTAINER"

if ! wait_for_suricata "$NS_NAMESPACE" "$dpi_pod" "$DPI_CONTAINER" "$EVE_WAIT_SECONDS"; then
  die "suricata did not appear in pod $dpi_pod within ${EVE_WAIT_SECONDS}s"
fi

if ! wait_for_dpi_interfaces "$NS_NAMESPACE" "$dpi_pod" "$DPI_CONTAINER" "$EVE_WAIT_SECONDS"; then
  die "dpi data interfaces did not appear in pod $dpi_pod within ${EVE_WAIT_SECONDS}s"
fi

client_link_line="$(pod_sh "$NS_NAMESPACE" "$client_pod" "$CLIENT_CONTAINER" "ip -o link show dev $CLIENT_IFACE")"
client_iface="$(parse_link_name "$client_link_line")"
client_peer_ifindex="$(parse_link_peer_ifindex "$client_link_line")"
[[ -n "$client_iface" ]] || die "unable to parse client interface from: $client_link_line"
[[ -n "$client_peer_ifindex" ]] || die "unable to parse client peer ifindex from: $client_link_line"

client_ip="$(pod_sh "$NS_NAMESPACE" "$client_pod" "$CLIENT_CONTAINER" "ip -o -4 addr show dev $client_iface | awk '{print \$4}' | cut -d/ -f1")"
[[ -n "$client_ip" ]] || die "unable to determine client IP on $client_iface"

mapfile -t dpi_leg_lines < <(list_named_links "$NS_NAMESPACE" "$dpi_pod" "$DPI_CONTAINER" '^nse-ovs-')
[[ "${#dpi_leg_lines[@]}" -eq 2 ]] || die "expected 2 DPI data interfaces, got ${#dpi_leg_lines[@]}"
dpi_bridge_line="$(list_named_links "$NS_NAMESPACE" "$dpi_pod" "$DPI_CONTAINER" '^nsmbr' | head -n1)"
dpi_bridge="$(parse_link_name "$dpi_bridge_line")"
[[ -n "$dpi_bridge" ]] || die "unable to determine dpi bridge interface"

dpi_leg_a="$(parse_link_name "${dpi_leg_lines[0]}")"
dpi_leg_a_peer_ifindex="$(parse_link_peer_ifindex "${dpi_leg_lines[0]}")"
dpi_leg_b="$(parse_link_name "${dpi_leg_lines[1]}")"
dpi_leg_b_peer_ifindex="$(parse_link_peer_ifindex "${dpi_leg_lines[1]}")"

[[ -n "$dpi_leg_a_peer_ifindex" ]] || die "unable to parse dpi leg A peer ifindex"
[[ -n "$dpi_leg_b_peer_ifindex" ]] || die "unable to parse dpi leg B peer ifindex"

server_link_line="$(list_named_links "$NS_NAMESPACE" "$server_pod" "$SERVER_CONTAINER" '^nse-ovs-' | head -n1)"
server_iface="$(parse_link_name "$server_link_line")"
server_peer_ifindex="$(parse_link_peer_ifindex "$server_link_line")"
[[ -n "$server_iface" ]] || die "unable to parse server interface from: $server_link_line"
[[ -n "$server_peer_ifindex" ]] || die "unable to parse server peer ifindex from: $server_link_line"

server_ip="$(pod_sh "$NS_NAMESPACE" "$server_pod" "$SERVER_CONTAINER" "ip -o -4 addr show dev $server_iface | awk '{print \$4}' | cut -d/ -f1")"
[[ -n "$server_ip" ]] || die "unable to determine server IP on $server_iface"

forwarder_links_file="$tmpdir/forwarder-links.txt"
run_kubectl exec -n "$NSM_SYSTEM_NAMESPACE" "$forwarder_pod" -- ip -o link show >"$forwarder_links_file"

client_forwarder_port="$(forwarder_port_name_for_ifindex "$forwarder_links_file" "$client_peer_ifindex")"
server_forwarder_port="$(forwarder_port_name_for_ifindex "$forwarder_links_file" "$server_peer_ifindex")"
dpi_leg_a_forwarder_port="$(forwarder_port_name_for_ifindex "$forwarder_links_file" "$dpi_leg_a_peer_ifindex")"
dpi_leg_b_forwarder_port="$(forwarder_port_name_for_ifindex "$forwarder_links_file" "$dpi_leg_b_peer_ifindex")"

[[ -n "$client_forwarder_port" ]] || die "unable to map client peer ifindex $client_peer_ifindex to forwarder port"
[[ -n "$server_forwarder_port" ]] || die "unable to map server peer ifindex $server_peer_ifindex to forwarder port"
[[ -n "$dpi_leg_a_forwarder_port" ]] || die "unable to map dpi leg A peer ifindex $dpi_leg_a_peer_ifindex to forwarder port"
[[ -n "$dpi_leg_b_forwarder_port" ]] || die "unable to map dpi leg B peer ifindex $dpi_leg_b_peer_ifindex to forwarder port"

client_conn_id="$(port_conn_id "$client_forwarder_port")"
server_conn_id="$(port_conn_id "$server_forwarder_port")"
leg_a_conn_id="$(port_conn_id "$dpi_leg_a_forwarder_port")"
leg_b_conn_id="$(port_conn_id "$dpi_leg_b_forwarder_port")"

if [[ "$leg_a_conn_id" == "$client_conn_id" ]]; then
  dpi_ingress_leg="$dpi_leg_a"
  dpi_ingress_forwarder_port="$dpi_leg_a_forwarder_port"
  dpi_egress_leg="$dpi_leg_b"
  dpi_egress_forwarder_port="$dpi_leg_b_forwarder_port"
elif [[ "$leg_b_conn_id" == "$client_conn_id" ]]; then
  dpi_ingress_leg="$dpi_leg_b"
  dpi_ingress_forwarder_port="$dpi_leg_b_forwarder_port"
  dpi_egress_leg="$dpi_leg_a"
  dpi_egress_forwarder_port="$dpi_leg_a_forwarder_port"
else
  die "unable to match dpi ingress leg to client connection id $client_conn_id"
fi

if [[ "$(port_conn_id "$dpi_egress_forwarder_port")" != "$server_conn_id" ]]; then
  die "dpi egress leg does not map to server connection id $server_conn_id"
fi

client_ofport="$(lookup_ofport "$forwarder_pod" "$client_forwarder_port")"
dpi_ingress_ofport="$(lookup_ofport "$forwarder_pod" "$dpi_ingress_forwarder_port")"
dpi_egress_ofport="$(lookup_ofport "$forwarder_pod" "$dpi_egress_forwarder_port")"
server_ofport="$(lookup_ofport "$forwarder_pod" "$server_forwarder_port")"

prepare_http_server "$NS_NAMESPACE" "$server_pod" "$SERVER_CONTAINER"

eve_file_before="$(trim "$(find_eve_file "$NS_NAMESPACE" "$dpi_pod" "$DPI_CONTAINER" || true)")"
eve_before_lines=0
if [[ -n "$eve_file_before" ]]; then
  eve_before_lines="$(trim "$(eve_line_count "$NS_NAMESPACE" "$dpi_pod" "$DPI_CONTAINER" "$eve_file_before")")"
fi
[[ "$eve_before_lines" =~ ^[0-9]+$ ]] || eve_before_lines=0

client_before="$tmpdir/client-before.env"
dpi_ingress_before="$tmpdir/dpi-ingress-before.env"
dpi_egress_before="$tmpdir/dpi-egress-before.env"
server_before="$tmpdir/server-before.env"
client_ofport_before="$tmpdir/client-ofport-before.env"
dpi_ingress_ofport_before="$tmpdir/dpi-ingress-ofport-before.env"
dpi_egress_ofport_before="$tmpdir/dpi-egress-ofport-before.env"
server_ofport_before="$tmpdir/server-ofport-before.env"

save_snapshot "$client_before" capture_netdev_stats "$NS_NAMESPACE" "$client_pod" "$CLIENT_CONTAINER" "$client_iface"
save_snapshot "$dpi_ingress_before" capture_netdev_stats "$NS_NAMESPACE" "$dpi_pod" "$DPI_CONTAINER" "$dpi_ingress_leg"
save_snapshot "$dpi_egress_before" capture_netdev_stats "$NS_NAMESPACE" "$dpi_pod" "$DPI_CONTAINER" "$dpi_egress_leg"
save_snapshot "$server_before" capture_netdev_stats "$NS_NAMESPACE" "$server_pod" "$SERVER_CONTAINER" "$server_iface"
save_snapshot "$client_ofport_before" capture_ofport_stats "$forwarder_pod" "$client_ofport"
save_snapshot "$dpi_ingress_ofport_before" capture_ofport_stats "$forwarder_pod" "$dpi_ingress_ofport"
save_snapshot "$dpi_egress_ofport_before" capture_ofport_stats "$forwarder_pod" "$dpi_egress_ofport"
save_snapshot "$server_ofport_before" capture_ofport_stats "$forwarder_pod" "$server_ofport"

run_start_rfc3339="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

request_paths=(
  "GET /admin HTTP/1.1\r\nHost: example.local\r\nConnection: close\r\n\r\n"
  "POST /upload HTTP/1.1\r\nHost: example.local\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
  "GET / HTTP/1.1\r\nHost: blocked.local\r\nConnection: close\r\n\r\n"
  "GET / HTTP/1.1\r\nHost: example.local\r\nX-Debug: 1\r\nConnection: close\r\n\r\n"
  "GET /health HTTP/1.1\r\nHost: example.local\r\nConnection: close\r\n\r\n"
)

request_labels=(
  "GET /admin"
  "POST /upload"
  "Host blocked.local"
  "Header X-Debug: 1"
  "GET /health"
)

for i in "${!request_paths[@]}"; do
  output_file="$tmpdir/request-$i.txt"
  if ! run_http_request "$NS_NAMESPACE" "$client_pod" "$CLIENT_CONTAINER" "$server_ip" "${request_paths[$i]}" >"$output_file" 2>&1; then
    cat "$output_file"
    die "http request failed for ${request_labels[$i]}"
  fi
  if ! grep -q "200 OK" "$output_file"; then
    cat "$output_file"
    die "http response missing 200 OK for ${request_labels[$i]}"
  fi
done

sleep 3

eve_file_after="$(wait_for_eve_file "$NS_NAMESPACE" "$dpi_pod" "$DPI_CONTAINER" "$EVE_WAIT_SECONDS")"
[[ -n "$eve_file_after" ]] || die "eve.json was not created under $DPI_TEMP_ROOT"
if [[ "$eve_file_after" != "$eve_file_before" ]]; then
  eve_before_lines=0
fi

new_eve_file="$tmpdir/eve-new.json"
copy_new_eve_lines "$NS_NAMESPACE" "$dpi_pod" "$DPI_CONTAINER" "$eve_file_after" "$eve_before_lines" "$new_eve_file"

alert_lines_file="$tmpdir/eve-alerts.json"
grep '"event_type":"alert"' "$new_eve_file" >"$alert_lines_file" || true
alert_count="$(wc -l < "$alert_lines_file" | tr -d ' ')"

get_admin_hits="$(count_matches "$alert_lines_file" "nse-ovs-dpi GET /admin")"
post_upload_hits="$(count_matches "$alert_lines_file" "nse-ovs-dpi POST /upload")"
host_hits="$(count_matches "$alert_lines_file" "nse-ovs-dpi Host blocked.local")"
debug_hits="$(count_matches "$alert_lines_file" "nse-ovs-dpi Header X-Debug 1")"

if [[ "$EXPECT_RESULT" == "alert" ]]; then
  (( get_admin_hits > 0 )) || die "missing alert for GET /admin"
  (( post_upload_hits > 0 )) || die "missing alert for POST /upload"
  (( host_hits > 0 )) || die "missing alert for Host blocked.local"
  (( debug_hits > 0 )) || die "missing alert for Header X-Debug 1"
else
  (( alert_count == 0 )) || die "expected no alerts, but found $alert_count"
fi

client_after="$tmpdir/client-after.env"
dpi_ingress_after="$tmpdir/dpi-ingress-after.env"
dpi_egress_after="$tmpdir/dpi-egress-after.env"
server_after="$tmpdir/server-after.env"
client_ofport_after="$tmpdir/client-ofport-after.env"
dpi_ingress_ofport_after="$tmpdir/dpi-ingress-ofport-after.env"
dpi_egress_ofport_after="$tmpdir/dpi-egress-ofport-after.env"
server_ofport_after="$tmpdir/server-ofport-after.env"

save_snapshot "$client_after" capture_netdev_stats "$NS_NAMESPACE" "$client_pod" "$CLIENT_CONTAINER" "$client_iface"
save_snapshot "$dpi_ingress_after" capture_netdev_stats "$NS_NAMESPACE" "$dpi_pod" "$DPI_CONTAINER" "$dpi_ingress_leg"
save_snapshot "$dpi_egress_after" capture_netdev_stats "$NS_NAMESPACE" "$dpi_pod" "$DPI_CONTAINER" "$dpi_egress_leg"
save_snapshot "$server_after" capture_netdev_stats "$NS_NAMESPACE" "$server_pod" "$SERVER_CONTAINER" "$server_iface"
save_snapshot "$client_ofport_after" capture_ofport_stats "$forwarder_pod" "$client_ofport"
save_snapshot "$dpi_ingress_ofport_after" capture_ofport_stats "$forwarder_pod" "$dpi_ingress_ofport"
save_snapshot "$dpi_egress_ofport_after" capture_ofport_stats "$forwarder_pod" "$dpi_egress_ofport"
save_snapshot "$server_ofport_after" capture_ofport_stats "$forwarder_pod" "$server_ofport"

client_tx_bytes_delta="$(delta_from_files "$client_before" "$client_after" "tx_bytes")"
client_tx_packets_delta="$(delta_from_files "$client_before" "$client_after" "tx_packets")"
client_rx_bytes_delta="$(delta_from_files "$client_before" "$client_after" "rx_bytes")"
client_rx_packets_delta="$(delta_from_files "$client_before" "$client_after" "rx_packets")"

dpi_ingress_rx_bytes_delta="$(delta_from_files "$dpi_ingress_before" "$dpi_ingress_after" "rx_bytes")"
dpi_ingress_rx_packets_delta="$(delta_from_files "$dpi_ingress_before" "$dpi_ingress_after" "rx_packets")"
dpi_ingress_tx_bytes_delta="$(delta_from_files "$dpi_ingress_before" "$dpi_ingress_after" "tx_bytes")"
dpi_ingress_tx_packets_delta="$(delta_from_files "$dpi_ingress_before" "$dpi_ingress_after" "tx_packets")"

dpi_egress_rx_bytes_delta="$(delta_from_files "$dpi_egress_before" "$dpi_egress_after" "rx_bytes")"
dpi_egress_rx_packets_delta="$(delta_from_files "$dpi_egress_before" "$dpi_egress_after" "rx_packets")"
dpi_egress_tx_bytes_delta="$(delta_from_files "$dpi_egress_before" "$dpi_egress_after" "tx_bytes")"
dpi_egress_tx_packets_delta="$(delta_from_files "$dpi_egress_before" "$dpi_egress_after" "tx_packets")"

server_rx_bytes_delta="$(delta_from_files "$server_before" "$server_after" "rx_bytes")"
server_rx_packets_delta="$(delta_from_files "$server_before" "$server_after" "rx_packets")"
server_tx_bytes_delta="$(delta_from_files "$server_before" "$server_after" "tx_bytes")"
server_tx_packets_delta="$(delta_from_files "$server_before" "$server_after" "tx_packets")"

client_ofport_rx_bytes_delta="$(delta_from_files "$client_ofport_before" "$client_ofport_after" "rx_bytes")"
client_ofport_rx_packets_delta="$(delta_from_files "$client_ofport_before" "$client_ofport_after" "rx_packets")"
client_ofport_tx_bytes_delta="$(delta_from_files "$client_ofport_before" "$client_ofport_after" "tx_bytes")"
client_ofport_tx_packets_delta="$(delta_from_files "$client_ofport_before" "$client_ofport_after" "tx_packets")"

dpi_ingress_ofport_rx_bytes_delta="$(delta_from_files "$dpi_ingress_ofport_before" "$dpi_ingress_ofport_after" "rx_bytes")"
dpi_ingress_ofport_rx_packets_delta="$(delta_from_files "$dpi_ingress_ofport_before" "$dpi_ingress_ofport_after" "rx_packets")"
dpi_ingress_ofport_tx_bytes_delta="$(delta_from_files "$dpi_ingress_ofport_before" "$dpi_ingress_ofport_after" "tx_bytes")"
dpi_ingress_ofport_tx_packets_delta="$(delta_from_files "$dpi_ingress_ofport_before" "$dpi_ingress_ofport_after" "tx_packets")"

dpi_egress_ofport_rx_bytes_delta="$(delta_from_files "$dpi_egress_ofport_before" "$dpi_egress_ofport_after" "rx_bytes")"
dpi_egress_ofport_rx_packets_delta="$(delta_from_files "$dpi_egress_ofport_before" "$dpi_egress_ofport_after" "rx_packets")"
dpi_egress_ofport_tx_bytes_delta="$(delta_from_files "$dpi_egress_ofport_before" "$dpi_egress_ofport_after" "tx_bytes")"
dpi_egress_ofport_tx_packets_delta="$(delta_from_files "$dpi_egress_ofport_before" "$dpi_egress_ofport_after" "tx_packets")"

server_ofport_rx_bytes_delta="$(delta_from_files "$server_ofport_before" "$server_ofport_after" "rx_bytes")"
server_ofport_rx_packets_delta="$(delta_from_files "$server_ofport_before" "$server_ofport_after" "rx_packets")"
server_ofport_tx_bytes_delta="$(delta_from_files "$server_ofport_before" "$server_ofport_after" "tx_bytes")"
server_ofport_tx_packets_delta="$(delta_from_files "$server_ofport_before" "$server_ofport_after" "tx_packets")"

if (( client_tx_bytes_delta <= 0 )); then
  die "client transmitted no payload during verification"
fi

if (( dpi_ingress_rx_bytes_delta <= 0 || dpi_egress_tx_bytes_delta <= 0 )); then
  die "dpi dataplane counters did not move on both sides"
fi

if (( server_rx_bytes_delta <= 0 )); then
  die "server received no traffic during verification"
fi

client_log_hits="$(run_kubectl logs -n "$NS_NAMESPACE" "$client_pod" -c "$CLIENT_CMD_CONTAINER" --since-time="$run_start_rfc3339" | grep -n 'RESELECT_REQUESTED' || true)"
dpi_log_hits="$(run_kubectl logs -n "$NS_NAMESPACE" "$dpi_pod" -c "$DPI_CONTAINER" --since-time="$run_start_rfc3339" | grep -n 'inline close requested' || true)"

echo "== Context =="
echo "Namespace           : $NS_NAMESPACE"
echo "Expectation         : $EXPECT_RESULT"
echo "Node                : $client_node"
echo "Forwarder pod       : $forwarder_pod"
echo "Client pod          : $client_pod ($client_iface $client_ip)"
echo "DPI pod             : $dpi_pod (bridge $dpi_bridge, ingress $dpi_ingress_leg, egress $dpi_egress_leg)"
echo "Server pod          : $server_pod ($server_iface $server_ip)"
echo "EVE file            : $eve_file_after"
echo

echo "== HTTP Request Summary =="
for i in "${!request_labels[@]}"; do
  echo "${request_labels[$i]}: PASS"
done
echo

echo "== Alert Summary =="
echo "Total alerts        : $alert_count"
echo "GET /admin          : $get_admin_hits"
echo "POST /upload        : $post_upload_hits"
echo "Host blocked.local  : $host_hits"
echo "Header X-Debug 1    : $debug_hits"
echo

echo "== Path Proof =="
echo "Forward data path: client -> forwarder -> dpi ingress -> bridge -> dpi egress -> forwarder -> server"
render_leg_line "Client TX" "$client_pod" "$client_iface" "+$(fmt_bytes_gib "$client_tx_bytes_delta") / +$(fmt_count "$client_tx_packets_delta") pkts"
render_leg_line "FWD RX" "$forwarder_pod" "$client_forwarder_port/$client_ofport" "+$(fmt_bytes_gib "$client_ofport_rx_bytes_delta") / +$(fmt_count "$client_ofport_rx_packets_delta") pkts"
render_leg_line "FWD TX" "$forwarder_pod" "$dpi_ingress_forwarder_port/$dpi_ingress_ofport" "+$(fmt_bytes_gib "$dpi_ingress_ofport_tx_bytes_delta") / +$(fmt_count "$dpi_ingress_ofport_tx_packets_delta") pkts"
render_leg_line "Ingress RX" "$dpi_pod" "$dpi_ingress_leg" "+$(fmt_bytes_gib "$dpi_ingress_rx_bytes_delta") / +$(fmt_count "$dpi_ingress_rx_packets_delta") pkts"
render_leg_line "Bridge" "$dpi_pod" "$dpi_bridge" "local handoff inside inline NSE"
render_leg_line "Egress TX" "$dpi_pod" "$dpi_egress_leg" "+$(fmt_bytes_gib "$dpi_egress_tx_bytes_delta") / +$(fmt_count "$dpi_egress_tx_packets_delta") pkts"
render_leg_line "FWD RX" "$forwarder_pod" "$dpi_egress_forwarder_port/$dpi_egress_ofport" "+$(fmt_bytes_gib "$dpi_egress_ofport_rx_bytes_delta") / +$(fmt_count "$dpi_egress_ofport_rx_packets_delta") pkts"
render_leg_line "FWD TX" "$forwarder_pod" "$server_forwarder_port/$server_ofport" "+$(fmt_bytes_gib "$server_ofport_tx_bytes_delta") / +$(fmt_count "$server_ofport_tx_packets_delta") pkts"
render_leg_line "Server RX" "$server_pod" "$server_iface" "+$(fmt_bytes_gib "$server_rx_bytes_delta") / +$(fmt_count "$server_rx_packets_delta") pkts"
echo

echo "Reverse path: server -> forwarder -> dpi egress -> bridge -> dpi ingress -> forwarder -> client"
render_leg_line "Server TX" "$server_pod" "$server_iface" "+$(fmt_bytes_gib "$server_tx_bytes_delta") / +$(fmt_count "$server_tx_packets_delta") pkts"
render_leg_line "FWD RX" "$forwarder_pod" "$server_forwarder_port/$server_ofport" "+$(fmt_bytes_gib "$server_ofport_rx_bytes_delta") / +$(fmt_count "$server_ofport_rx_packets_delta") pkts"
render_leg_line "FWD TX" "$forwarder_pod" "$dpi_egress_forwarder_port/$dpi_egress_ofport" "+$(fmt_bytes_gib "$dpi_egress_ofport_tx_bytes_delta") / +$(fmt_count "$dpi_egress_ofport_tx_packets_delta") pkts"
render_leg_line "Egress RX" "$dpi_pod" "$dpi_egress_leg" "+$(fmt_bytes_gib "$dpi_egress_rx_bytes_delta") / +$(fmt_count "$dpi_egress_rx_packets_delta") pkts"
render_leg_line "Bridge" "$dpi_pod" "$dpi_bridge" "local handoff inside inline NSE"
render_leg_line "Ingress TX" "$dpi_pod" "$dpi_ingress_leg" "+$(fmt_bytes_gib "$dpi_ingress_tx_bytes_delta") / +$(fmt_count "$dpi_ingress_tx_packets_delta") pkts"
render_leg_line "FWD RX" "$forwarder_pod" "$dpi_ingress_forwarder_port/$dpi_ingress_ofport" "+$(fmt_bytes_gib "$dpi_ingress_ofport_rx_bytes_delta") / +$(fmt_count "$dpi_ingress_ofport_rx_packets_delta") pkts"
render_leg_line "FWD TX" "$forwarder_pod" "$client_forwarder_port/$client_ofport" "+$(fmt_bytes_gib "$client_ofport_tx_bytes_delta") / +$(fmt_count "$client_ofport_tx_packets_delta") pkts"
render_leg_line "Client RX" "$client_pod" "$client_iface" "+$(fmt_bytes_gib "$client_rx_bytes_delta") / +$(fmt_count "$client_rx_packets_delta") pkts"
echo

echo "== ASCII Diagram =="
cat <<EOF
[$client_pod]
  client:$client_iface ($client_ip)
  TX +$(fmt_bytes_gib "$client_tx_bytes_delta") / +$(fmt_count "$client_tx_packets_delta") pkts
        |
        |  $forwarder_pod:$client_forwarder_port (ofport $client_ofport)
        |  RX +$(fmt_bytes_gib "$client_ofport_rx_bytes_delta") / +$(fmt_count "$client_ofport_rx_packets_delta") pkts
        v
[$dpi_pod]
  ingress:$dpi_ingress_leg  RX +$(fmt_bytes_gib "$dpi_ingress_rx_bytes_delta") / +$(fmt_count "$dpi_ingress_rx_packets_delta") pkts
  bridge:$dpi_bridge        local handoff
  egress:$dpi_egress_leg    TX +$(fmt_bytes_gib "$dpi_egress_tx_bytes_delta") / +$(fmt_count "$dpi_egress_tx_packets_delta") pkts
        |
        |  $forwarder_pod:$dpi_egress_forwarder_port (ofport $dpi_egress_ofport)
        |  RX +$(fmt_bytes_gib "$dpi_egress_ofport_rx_bytes_delta") / +$(fmt_count "$dpi_egress_ofport_rx_packets_delta") pkts
        v
[$server_pod]
  nse:$server_iface ($server_ip)
  RX +$(fmt_bytes_gib "$server_rx_bytes_delta") / +$(fmt_count "$server_rx_packets_delta") pkts
EOF
echo

echo "== Control Plane Checks =="
if [[ -n "$client_log_hits" ]]; then
  echo "cmd-nsc reselect detected:"
  echo "$client_log_hits"
  exit 1
fi
echo "cmd-nsc reselect        : clean"

if [[ -n "$dpi_log_hits" ]]; then
  echo "dpi inline close detected:"
  echo "$dpi_log_hits"
  exit 1
fi
echo "dpi inline close        : clean"
echo

if [[ "$PRINT_EVE" == "true" ]]; then
  echo "== New EVE Lines =="
  cat "$new_eve_file"
  echo
fi

echo "Verification result: PASS"
