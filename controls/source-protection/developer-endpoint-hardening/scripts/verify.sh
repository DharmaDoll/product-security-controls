#!/usr/bin/env bash
set -u

mode="${1:-}"
case "$mode" in
  secure|insecure) ;;
  *)
    echo "usage: $0 secure|insecure" >&2
    exit 2
    ;;
esac

root_dir="$(cd "$(dirname "$0")/.." && pwd)"
policy="$root_dir/$mode/endpoint-policy.conf"
failures=0

get_value() {
  awk -F= -v key="$1" '$1 == key {print $2; found=1} END {if (!found) exit 1}' "$policy"
}

check_value() {
  local key="$1" expected="$2" actual
  actual="$(get_value "$key" 2>/dev/null || true)"
  if [[ "$actual" != "$expected" ]]; then
    echo "FAIL $key: expected=$expected actual=${actual:-<missing>}"
    failures=$((failures + 1))
  else
    echo "PASS $key=$actual"
  fi
}

if [[ "$mode" == secure ]]; then
  check_value disk_encryption required
  check_value screen_lock required
  check_value automatic_updates required
  check_value local_admin false
  check_value credential_storage system_keychain
  check_value secrets_in_workspace false
  check_value docker_socket_exposed false
  check_value local_debug_services disabled
  check_value ai_tools_network allowlist
  check_value workspace_mount read-only-by-default
  check_value backup_encryption required
else
  # The insecure fixture must be rejected by the same policy expectations.
  check_value disk_encryption required
  check_value screen_lock required
  check_value automatic_updates required
  check_value local_admin false
  check_value credential_storage system_keychain
  check_value secrets_in_workspace false
  check_value docker_socket_exposed false
  check_value local_debug_services disabled
  check_value ai_tools_network allowlist
  check_value workspace_mount read-only-by-default
  check_value backup_encryption required
fi

if (( failures > 0 )); then
  echo "REJECTED $mode policy: $failures control checks failed"
  exit 1
fi

echo "ACCEPTED $mode policy"
