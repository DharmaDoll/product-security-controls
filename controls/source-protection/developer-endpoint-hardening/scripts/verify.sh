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

# Both fixtures are evaluated against the same expectations. Requirements
# DEH-001 through DEH-010 are traced in docs/operational-baseline.md.
check_value disk_encryption required
check_value screen_lock required
check_value automatic_updates required
check_value local_admin false
check_value credential_lifetime short-lived
check_value credential_storage system-keychain-or-approved-manager
check_value hardware_backed_keys required
check_value secrets_in_workspace false
check_value pre_commit_secret_scan required
check_value repository_secret_scan required
check_value docker_socket_exposed false
check_value package_install_isolation required
check_value dependency_update_guard release-cooldown-and-security-updates
check_value dependency_registry_proxy mdm-enforced-no-direct-fallback
check_value local_debug_services disabled
check_value developer_egress_control allowlist
check_value phishing_resistant_mfa required
check_value sensitive_data_file_guard required
check_value ai_tools_network allowlist
check_value workspace_mount read-only-by-default
check_value backup_encryption required
check_value approved_applications allowlist-enforced
check_value edr_xdr required
check_value commit_signing required
check_value ide_security_feedback sast-and-sca
check_value managed_development_environment required-for-high-risk
check_value sandbox_runtime_monitoring required
check_value endpoint_configuration_management mdm-enforced
check_value physical_device_protection required

if (( failures > 0 )); then
  echo "REJECTED $mode policy: $failures control checks failed"
  exit 1
fi

echo "ACCEPTED $mode policy"
