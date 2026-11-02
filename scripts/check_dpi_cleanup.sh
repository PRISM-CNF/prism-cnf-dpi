#!/usr/bin/env bash
set -euo pipefail

NS_NAMESPACE="${NS_NAMESPACE:-nse-ovs-dpi}"
DPI_POD_PREFIX="${DPI_POD_PREFIX:-nse-ovs-dpi-}"
DPI_CONTAINER="${DPI_CONTAINER:-nse}"
DPI_TEMP_ROOT="${DPI_TEMP_ROOT:-/tmp/nse-ovs-dpi}"
WAIT_TIMEOUT_SECONDS="${WAIT_TIMEOUT_SECONDS:-60}"
POLL_INTERVAL_SECONDS="${POLL_INTERVAL_SECONDS:-2}"
KUBECTL="${KUBECTL:-kubectl}"

usage() {
  cat <<'EOF'
Usage: ./scripts/check_dpi_cleanup.sh [--timeout-seconds <n>] [--poll-seconds <n>]

Wait until the running DPI pod has no active Suricata process and no session artifacts
under /tmp/nse-ovs-dpi.

Options:
  --timeout-seconds <n> Timeout in seconds. Default: 60
  --poll-seconds <n>    Poll interval in seconds. Default: 2
  -h, --help            Show this help text
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --timeout-seconds)
      WAIT_TIMEOUT_SECONDS="${2:-}"
      shift 2
      ;;
    --poll-seconds)
      POLL_INTERVAL_SECONDS="${2:-}"
      shift 2
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

run_kubectl() {
  "${KUBECTL}" "$@"
}

get_dpi_pod() {
  run_kubectl get pods -n "${NS_NAMESPACE}" --no-headers \
    -o custom-columns=NAME:.metadata.name,PHASE:.status.phase \
    | awk -v prefix="${DPI_POD_PREFIX}" '$1 ~ ("^" prefix) && $2 == "Running" { print $1; exit }'
}

list_suricata_processes() {
  local pod_name="$1"
  run_kubectl exec -n "${NS_NAMESPACE}" "${pod_name}" -c "${DPI_CONTAINER}" -- \
    sh -eu -c "ps -ef | grep '[s]uricata' || true"
}

list_dpi_artifacts() {
  local pod_name="$1"
  run_kubectl exec -n "${NS_NAMESPACE}" "${pod_name}" -c "${DPI_CONTAINER}" -- \
    sh -eu -c "find '${DPI_TEMP_ROOT}' -mindepth 1 -print 2>/dev/null || true"
}

dpi_pod="$(get_dpi_pod)"
[[ -n "${dpi_pod}" ]] || { echo "running dpi pod not found in namespace ${NS_NAMESPACE}" >&2; exit 1; }

deadline=$((SECONDS + WAIT_TIMEOUT_SECONDS))
while (( SECONDS < deadline )); do
  active_processes="$(list_suricata_processes "${dpi_pod}")"
  active_artifacts="$(list_dpi_artifacts "${dpi_pod}")"
  if [[ -z "${active_processes}" && -z "${active_artifacts}" ]]; then
    echo "DPI cleanup check: PASS"
    echo "DPI pod: ${dpi_pod}"
    exit 0
  fi
  sleep "${POLL_INTERVAL_SECONDS}"
done

echo "dpi cleanup timed out after ${WAIT_TIMEOUT_SECONDS}s" >&2
echo "== Suricata processes ==" >&2
list_suricata_processes "${dpi_pod}" >&2 || true
echo "== Artifact paths ==" >&2
list_dpi_artifacts "${dpi_pod}" >&2 || true
exit 1
