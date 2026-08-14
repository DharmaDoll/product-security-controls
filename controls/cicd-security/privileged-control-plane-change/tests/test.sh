#!/usr/bin/env bash
set -euo pipefail

control="controls/cicd-security/privileged-control-plane-change"
verify="$control/scripts/verify.py"
evaluation_time="2026-08-12T04:10:00Z"
temporary_directory="$(mktemp -d)"
trap 'rm -rf "$temporary_directory"' EXIT

secure=(
  --policy "$control/secure/policy.json"
  --change-evidence "$control/secure/change-evidence.json"
  --evaluation-time "$evaluation_time"
)

github=(
  --audit-events "$control/secure/github/audit-events.json"
  --identity-sessions "$control/secure/github/identity-sessions.json"
  --change-register "$control/secure/github/change-register.json"
  --runner-groups "$control/secure/github/runner-groups.json"
)

github_scm=(
  --audit-events "$control/secure/github-scm/audit-events.json"
  --identity-sessions "$control/secure/github-scm/identity-sessions.json"
  --change-register "$control/secure/github-scm/change-register.json"
  --ruleset-snapshot "$control/secure/github-scm/ruleset-snapshot.json"
)

github_org_scm=(
  --audit-events "$control/secure/github-org-scm/audit-events.json"
  --identity-sessions "$control/secure/github-org-scm/identity-sessions.json"
  --change-register "$control/secure/github-org-scm/change-register.json"
  --ruleset-snapshot "$control/secure/github-org-scm/ruleset-snapshot.json"
)

github_tag_scm=(
  --audit-events "$control/secure/github-tag-scm/audit-events.json"
  --identity-sessions "$control/secure/github-tag-scm/identity-sessions.json"
  --change-register "$control/secure/github-tag-scm/change-register.json"
  --ruleset-snapshot "$control/secure/github-tag-scm/ruleset-snapshot.json"
)

github_push_scm=(
  --audit-events "$control/secure/github-push-scm/audit-events.json"
  --identity-sessions "$control/secure/github-push-scm/identity-sessions.json"
  --change-register "$control/secure/github-push-scm/change-register.json"
  --ruleset-snapshot "$control/secure/github-push-scm/ruleset-snapshot.json"
  --fork-network-snapshot "$control/secure/github-push-scm/fork-network-snapshot.json"
)

github_legacy_branch_scm=(
  --audit-events "$control/secure/github-legacy-branch-scm/audit-events.json"
  --identity-sessions "$control/secure/github-legacy-branch-scm/identity-sessions.json"
  --change-register "$control/secure/github-legacy-branch-scm/change-register.json"
  --branch-protection-snapshot "$control/secure/github-legacy-branch-scm/branch-protection-snapshot.json"
)

aws=(
  --cloudtrail-events "$control/secure/aws/cloudtrail-events.json"
  --identity-sessions "$control/secure/aws/identity-sessions.json"
  --change-register "$control/secure/aws/change-register.json"
  --iam-roles "$control/secure/aws/iam-roles.json"
)

ecr=(
  --cloudtrail-events "$control/secure/aws-ecr/cloudtrail-events.json"
  --identity-sessions "$control/secure/aws-ecr/identity-sessions.json"
  --change-register "$control/secure/aws-ecr/change-register.json"
  --repositories "$control/secure/aws-ecr/repositories.json"
)

kms=(
  --cloudtrail-events "$control/secure/aws-kms/cloudtrail-events.json"
  --identity-sessions "$control/secure/aws-kms/identity-sessions.json"
  --change-register "$control/secure/aws-kms/change-register.json"
  --keys "$control/secure/aws-kms/keys.json"
)

python3 -m unittest discover \
  -s "$control/tests" \
  -p 'test_*.py'

python3 "$verify" "${secure[@]}" >"$temporary_directory/secure.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/secure.txt"

set +e
python3 "$verify" \
  --policy "$control/insecure/policy.json" \
  --change-evidence "$control/insecure/change-evidence.json" \
  --evaluation-time "$evaluation_time" \
  >"$temporary_directory/insecure.txt"
insecure_status=$?
set -e
test "$insecure_status" -eq 1
diff -u "$control/expected-results/insecure.txt" "$temporary_directory/insecure.txt"

set +e
python3 "$verify" "${secure[@]}" \
  --change-evidence "$control/tests/fixtures/unavailable-evidence.json" \
  >"$temporary_directory/unavailable.txt"
unavailable_status=$?
set -e
test "$unavailable_status" -eq 2
rg -F "ERROR PSB-CICD-008 control-plane change evaluation unavailable: control-plane evidence collector is unavailable" \
  "$temporary_directory/unavailable.txt" >/dev/null

set +e
python3 "$verify" "${secure[@]}" \
  --evaluation-time "2026-08-12T05:00:00Z" \
  >"$temporary_directory/stale.txt"
stale_status=$?
set -e
test "$stale_status" -eq 2
rg -F "change evidence is stale" "$temporary_directory/stale.txt" >/dev/null

printf '{not-json}\n' >"$temporary_directory/malformed.json"
set +e
python3 "$verify" "${secure[@]}" \
  --change-evidence "$temporary_directory/malformed.json" \
  >"$temporary_directory/malformed.txt"
malformed_status=$?
set -e
test "$malformed_status" -eq 2
rg -F "invalid change evidence JSON" "$temporary_directory/malformed.txt" >/dev/null

set +e
python3 "$verify" "${secure[@]}" \
  --change-evidence "$control/tests/fixtures/secret-bearing-evidence.json" \
  >"$temporary_directory/secret.txt"
secret_status=$?
set -e
test "$secret_status" -eq 2
rg -F "change evidence contains forbidden credential field access_token" \
  "$temporary_directory/secret.txt" >/dev/null
if rg -F "SYNTHETIC_TEST_VALUE_DO_NOT_USE" "$temporary_directory/secret.txt" >/dev/null; then
  echo "secret-bearing evidence leaked to verifier output" >&2
  exit 1
fi

python3 - "$control/secure/change-evidence.json" "$temporary_directory/substituted.json" <<'PY'
import json
import sys
source = json.load(open(sys.argv[1], encoding="utf-8"))
source["changes"][0]["execution"]["request_id"] = "request:substituted"
json.dump(source, open(sys.argv[2], "w", encoding="utf-8"), indent=2)
PY
set +e
python3 "$verify" "${secure[@]}" \
  --change-evidence "$temporary_directory/substituted.json" \
  >"$temporary_directory/substituted.txt"
substituted_status=$?
set -e
test "$substituted_status" -eq 1
rg -F "FAIL CPC-005 change 1 execution identity does not match its request and session" \
  "$temporary_directory/substituted.txt" >/dev/null

python3 - "$control/secure/change-evidence.json" "$temporary_directory/emergency.json" <<'PY'
import json
import sys
source = json.load(open(sys.argv[1], encoding="utf-8"))
source["changes"][1]["emergency"].pop("post_review")
json.dump(source, open(sys.argv[2], "w", encoding="utf-8"), indent=2)
PY
set +e
python3 "$verify" "${secure[@]}" \
  --change-evidence "$temporary_directory/emergency.json" \
  >"$temporary_directory/emergency.txt"
emergency_status=$?
set -e
test "$emergency_status" -eq 1
rg -F "FAIL CPC-006 change 2 emergency path lacks post-change review" \
  "$temporary_directory/emergency.txt" >/dev/null

python3 "$control/scripts/normalize_github.py" "${github[@]}" \
  --output "$temporary_directory/github-evidence.json" \
  >"$temporary_directory/github-normalize.txt"
rg -F "NORMALIZED 2 GitHub privileged change event(s)" \
  "$temporary_directory/github-normalize.txt" >/dev/null
if rg 'hashed_token|actor_ip|token_scopes|SYNTHETIC_TEST_VALUE_DO_NOT_USE' \
  "$temporary_directory/github-evidence.json" >/dev/null; then
  echo "GitHub normalized evidence retained a sensitive provider field" >&2
  exit 1
fi

# A single provider fragment must not claim that the five-service inventory is complete.
set +e
python3 "$verify" \
  --policy "$control/secure/policy.json" \
  --change-evidence "$temporary_directory/github-evidence.json" \
  --evaluation-time "$evaluation_time" \
  >"$temporary_directory/github-partial.txt"
github_partial_status=$?
set -e
test "$github_partial_status" -eq 1
rg -F "FAIL CPC-007 collector does not cover every required service" \
  "$temporary_directory/github-partial.txt" >/dev/null

python3 - \
  "$control/secure/change-evidence.json" \
  "$temporary_directory/github-evidence.json" \
  "$temporary_directory/github-composed.json" <<'PY'
import json
import sys
complete = json.load(open(sys.argv[1], encoding="utf-8"))
github = json.load(open(sys.argv[2], encoding="utf-8"))
complete["changes"][0] = github["changes"][0]
complete["changes"].append(github["changes"][1])
json.dump(complete, open(sys.argv[3], "w", encoding="utf-8"), indent=2)
PY
python3 "$verify" \
  --policy "$control/secure/policy.json" \
  --change-evidence "$temporary_directory/github-composed.json" \
  --evaluation-time "$evaluation_time" \
  >"$temporary_directory/github-composed.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/github-composed.txt"

python3 - \
  "$control/secure/github/identity-sessions.json" \
  "$temporary_directory/missing-session.json" <<'PY'
import json
import sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
value["sessions"] = []
json.dump(value, open(sys.argv[2], "w", encoding="utf-8"), indent=2)
PY
set +e
python3 "$control/scripts/normalize_github.py" \
  --audit-events "$control/secure/github/audit-events.json" \
  --identity-sessions "$temporary_directory/missing-session.json" \
  --change-register "$control/secure/github/change-register.json" \
  --runner-groups "$control/secure/github/runner-groups.json" \
  --output "$temporary_directory/should-not-exist.json" \
  >"$temporary_directory/missing-session-out.txt" \
  2>"$temporary_directory/missing-session-error.txt"
missing_session_status=$?
set -e
test "$missing_session_status" -eq 2
rg -F "privileged GitHub event lacks an exact session or change-register join" \
  "$temporary_directory/missing-session-error.txt" >/dev/null
test ! -e "$temporary_directory/should-not-exist.json"

python3 - \
  "$control/secure/github/audit-events.json" \
  "$temporary_directory/tampered-audit.json" <<'PY'
import json
import sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
value["events"][0]["new_value"]["required_reviewers"] = 1
json.dump(value, open(sys.argv[2], "w", encoding="utf-8"), indent=2)
PY
set +e
python3 "$control/scripts/normalize_github.py" \
  --audit-events "$temporary_directory/tampered-audit.json" \
  --identity-sessions "$control/secure/github/identity-sessions.json" \
  --change-register "$control/secure/github/change-register.json" \
  --runner-groups "$control/secure/github/runner-groups.json" \
  --output "$temporary_directory/tampered-output.json" \
  >"$temporary_directory/tampered-github-out.txt" \
  2>"$temporary_directory/tampered-github-error.txt"
tampered_github_status=$?
set -e
test "$tampered_github_status" -eq 2
rg -F "change register does not match GitHub before and after values" \
  "$temporary_directory/tampered-github-error.txt" >/dev/null
test ! -e "$temporary_directory/tampered-output.json"

set +e
python3 "$control/scripts/normalize_github.py" \
  --audit-events "$control/secure/github/audit-events.json" \
  --identity-sessions "$control/secure/github/identity-sessions.json" \
  --change-register "$control/secure/github/change-register.json" \
  --output "$temporary_directory/missing-runner-output.json" \
  >"$temporary_directory/missing-runner-out.txt" \
  2>"$temporary_directory/missing-runner-error.txt"
missing_runner_status=$?
set -e
test "$missing_runner_status" -eq 2
rg -F "runner-group event lacks an exact current-state snapshot join" \
  "$temporary_directory/missing-runner-error.txt" >/dev/null
test ! -e "$temporary_directory/missing-runner-output.json"

python3 - \
  "$control/secure/github/runner-groups.json" \
  "$temporary_directory/tampered-runner.json" <<'PY'
import json
import sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
value["runner_groups"][0]["configuration"]["allows_public_repositories"] = True
json.dump(value, open(sys.argv[2], "w", encoding="utf-8"), indent=2)
PY
set +e
python3 "$control/scripts/normalize_github.py" \
  --audit-events "$control/secure/github/audit-events.json" \
  --identity-sessions "$control/secure/github/identity-sessions.json" \
  --change-register "$control/secure/github/change-register.json" \
  --runner-groups "$temporary_directory/tampered-runner.json" \
  --output "$temporary_directory/tampered-runner-output.json" \
  >"$temporary_directory/tampered-runner-out.txt" \
  2>"$temporary_directory/tampered-runner-error.txt"
tampered_runner_status=$?
set -e
test "$tampered_runner_status" -eq 2
rg -F "runner-group audit register and current state do not name one configuration" \
  "$temporary_directory/tampered-runner-error.txt" >/dev/null
test ! -e "$temporary_directory/tampered-runner-output.json"

python3 - \
  "$control/secure/github/runner-groups.json" \
  "$temporary_directory/stale-runner.json" <<'PY'
import json
import sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
value["collected_at"] = "2026-08-12T03:30:00Z"
json.dump(value, open(sys.argv[2], "w", encoding="utf-8"), indent=2)
PY
set +e
python3 "$control/scripts/normalize_github.py" \
  --audit-events "$control/secure/github/audit-events.json" \
  --identity-sessions "$control/secure/github/identity-sessions.json" \
  --change-register "$control/secure/github/change-register.json" \
  --runner-groups "$temporary_directory/stale-runner.json" \
  --output "$temporary_directory/stale-runner-output.json" \
  >"$temporary_directory/stale-runner-out.txt" \
  2>"$temporary_directory/stale-runner-error.txt"
stale_runner_status=$?
set -e
test "$stale_runner_status" -eq 2
rg -F "runner-group snapshot is not covered by a complete later audit window" \
  "$temporary_directory/stale-runner-error.txt" >/dev/null
test ! -e "$temporary_directory/stale-runner-output.json"

python3 - \
  "$control/secure/github/audit-events.json" \
  "$temporary_directory/later-runner-event.json" <<'PY'
import copy
import json
import sys
value = json.load(open(sys.argv[1], encoding="utf-8"))
later = copy.deepcopy(value["events"][1])
later["_document_id"] = "audit-doc-553"
later["request_id"] = "github-request-553"
later["@timestamp"] = "2026-08-12T03:20:30Z"
value["events"].append(later)
value["collection"]["raw_events"] = 3
value["collection"]["selected_events"] = 3
json.dump(value, open(sys.argv[2], "w", encoding="utf-8"), indent=2)
PY
set +e
python3 "$control/scripts/normalize_github.py" \
  --audit-events "$temporary_directory/later-runner-event.json" \
  --identity-sessions "$control/secure/github/identity-sessions.json" \
  --change-register "$control/secure/github/change-register.json" \
  --runner-groups "$control/secure/github/runner-groups.json" \
  --output "$temporary_directory/ambiguous-runner-output.json" \
  >"$temporary_directory/ambiguous-runner-out.txt" \
  2>"$temporary_directory/ambiguous-runner-error.txt"
ambiguous_runner_status=$?
set -e
test "$ambiguous_runner_status" -eq 2
rg -F "runner-group snapshot is ambiguous because a later update exists" \
  "$temporary_directory/ambiguous-runner-error.txt" >/dev/null
test ! -e "$temporary_directory/ambiguous-runner-output.json"

python3 "$control/scripts/normalize_aws.py" "${aws[@]}" \
  --output "$temporary_directory/aws-evidence.json" \
  >"$temporary_directory/aws-normalize.txt"
rg -F "NORMALIZED 1 AWS IAM trust-policy change event(s)" \
  "$temporary_directory/aws-normalize.txt" >/dev/null
if rg 'accessKeyId|sourceIPAddress|userAgent|REDACTED-SYNTHETIC-NOT-A-CREDENTIAL' \
  "$temporary_directory/aws-evidence.json" >/dev/null; then
  echo "AWS normalized evidence retained a sensitive provider field" >&2
  exit 1
fi

set +e
python3 "$verify" \
  --policy "$control/secure/policy.json" \
  --change-evidence "$temporary_directory/aws-evidence.json" \
  --evaluation-time "$evaluation_time" \
  >"$temporary_directory/aws-partial.txt"
aws_partial_status=$?
set -e
test "$aws_partial_status" -eq 1
rg -F "FAIL CPC-007 collector does not cover every required service" \
  "$temporary_directory/aws-partial.txt" >/dev/null

python3 - \
  "$control/secure/change-evidence.json" \
  "$temporary_directory/github-evidence.json" \
  "$temporary_directory/aws-evidence.json" \
  "$temporary_directory/provider-composed.json" <<'PY'
import json
import sys
complete = json.load(open(sys.argv[1], encoding="utf-8"))
github = json.load(open(sys.argv[2], encoding="utf-8"))
aws = json.load(open(sys.argv[3], encoding="utf-8"))
complete["changes"][0] = github["changes"][0]
complete["changes"].append(github["changes"][1])
complete["changes"][1] = aws["changes"][0]
json.dump(complete, open(sys.argv[4], "w", encoding="utf-8"), indent=2)
PY
python3 "$verify" \
  --policy "$control/secure/policy.json" \
  --change-evidence "$temporary_directory/provider-composed.json" \
  --evaluation-time "$evaluation_time" \
  >"$temporary_directory/provider-composed.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/provider-composed.txt"

python3 "$control/scripts/normalize_aws_ecr.py" "${ecr[@]}" \
  --output "$temporary_directory/ecr-evidence.json" \
  >"$temporary_directory/ecr-normalize.txt"
rg -F "NORMALIZED 1 ECR repository-policy change event(s)" \
  "$temporary_directory/ecr-normalize.txt" >/dev/null
if rg 'accessKeyId|sourceIPAddress|userAgent|REDACTED-SYNTHETIC-NOT-A-CREDENTIAL' \
  "$temporary_directory/ecr-evidence.json" >/dev/null; then
  echo "ECR normalized evidence retained a sensitive provider field" >&2
  exit 1
fi

set +e
python3 "$verify" \
  --policy "$control/secure/policy.json" \
  --change-evidence "$temporary_directory/ecr-evidence.json" \
  --evaluation-time "$evaluation_time" \
  >"$temporary_directory/ecr-partial.txt"
ecr_partial_status=$?
set -e
test "$ecr_partial_status" -eq 1
rg -F "FAIL CPC-007 collector does not cover every required service" \
  "$temporary_directory/ecr-partial.txt" >/dev/null

python3 "$control/scripts/normalize_aws_kms.py" "${kms[@]}" \
  --output "$temporary_directory/kms-evidence.json" \
  >"$temporary_directory/kms-normalize.txt"
rg -F "NORMALIZED 1 KMS signing-key policy change event(s)" \
  "$temporary_directory/kms-normalize.txt" >/dev/null
if rg 'accessKeyId|sourceIPAddress|userAgent|REDACTED-SYNTHETIC-NOT-A-CREDENTIAL|"Statement"|"Principal"' \
  "$temporary_directory/kms-evidence.json" >/dev/null; then
  echo "KMS normalized evidence retained a sensitive provider field or policy body" >&2
  exit 1
fi

set +e
python3 "$verify" \
  --policy "$control/secure/policy.json" \
  --change-evidence "$temporary_directory/kms-evidence.json" \
  --evaluation-time "$evaluation_time" \
  >"$temporary_directory/kms-partial.txt"
kms_partial_status=$?
set -e
test "$kms_partial_status" -eq 1
rg -F "FAIL CPC-007 collector does not cover every required service" \
  "$temporary_directory/kms-partial.txt" >/dev/null

python3 "$control/scripts/normalize_github_ruleset.py" "${github_scm[@]}" \
  --output "$temporary_directory/github-scm-evidence.json" \
  >"$temporary_directory/github-scm-normalize.txt"
rg -F "NORMALIZED 1 GitHub repository-ruleset change event" \
  "$temporary_directory/github-scm-normalize.txt" >/dev/null
if rg 'hashed_token|user_agent|token_scopes|redacted-provider-token-identifier|"bypass_actors"|"conditions"|"rules"' \
  "$temporary_directory/github-scm-evidence.json" >/dev/null; then
  echo "GitHub SCM normalized evidence retained a sensitive provider field or ruleset body" >&2
  exit 1
fi

set +e
python3 "$verify" \
  --policy "$control/secure/policy.json" \
  --change-evidence "$temporary_directory/github-scm-evidence.json" \
  --evaluation-time "$evaluation_time" \
  >"$temporary_directory/github-scm-partial.txt"
github_scm_partial_status=$?
set -e
test "$github_scm_partial_status" -eq 1
rg -F "FAIL CPC-007 collector does not cover every required service" \
  "$temporary_directory/github-scm-partial.txt" >/dev/null

python3 "$control/scripts/normalize_github_ruleset.py" "${github_org_scm[@]}" \
  --output "$temporary_directory/github-org-scm-evidence.json" \
  >"$temporary_directory/github-org-scm-normalize.txt"
rg -F "NORMALIZED 1 GitHub organization-ruleset change event" \
  "$temporary_directory/github-org-scm-normalize.txt" >/dev/null
if rg 'hashed_token|user_agent|token_scopes|redacted-provider-token-identifier|"bypass_actors"|"conditions"|"rules"' \
  "$temporary_directory/github-org-scm-evidence.json" >/dev/null; then
  echo "GitHub organization SCM normalized evidence retained a sensitive provider field or ruleset body" >&2
  exit 1
fi

set +e
python3 "$verify" \
  --policy "$control/secure/policy.json" \
  --change-evidence "$temporary_directory/github-org-scm-evidence.json" \
  --evaluation-time "$evaluation_time" \
  >"$temporary_directory/github-org-scm-partial.txt"
github_org_scm_partial_status=$?
set -e
test "$github_org_scm_partial_status" -eq 1
rg -F "FAIL CPC-007 collector does not cover every required service" \
  "$temporary_directory/github-org-scm-partial.txt" >/dev/null

python3 "$control/scripts/normalize_github_ruleset.py" "${github_tag_scm[@]}" \
  --output "$temporary_directory/github-tag-scm-evidence.json" \
  >"$temporary_directory/github-tag-scm-normalize.txt"
rg -F "NORMALIZED 1 GitHub repository-ruleset change event" \
  "$temporary_directory/github-tag-scm-normalize.txt" >/dev/null
rg -F '"change_type": "tag-protection"' \
  "$temporary_directory/github-tag-scm-evidence.json" >/dev/null
if rg 'hashed_token|user_agent|token_scopes|redacted-provider-token-identifier|"bypass_actors"|"conditions"|"rules"' \
  "$temporary_directory/github-tag-scm-evidence.json" >/dev/null; then
  echo "GitHub tag SCM normalized evidence retained a sensitive provider field or ruleset body" >&2
  exit 1
fi

set +e
python3 "$verify" \
  --policy "$control/secure/policy.json" \
  --change-evidence "$temporary_directory/github-tag-scm-evidence.json" \
  --evaluation-time "$evaluation_time" \
  >"$temporary_directory/github-tag-scm-partial.txt"
github_tag_scm_partial_status=$?
set -e
test "$github_tag_scm_partial_status" -eq 1
rg -F "FAIL CPC-007 collector does not cover every required service" \
  "$temporary_directory/github-tag-scm-partial.txt" >/dev/null

python3 "$control/scripts/normalize_github_ruleset.py" "${github_push_scm[@]}" \
  --output "$temporary_directory/github-push-scm-evidence.json" \
  >"$temporary_directory/github-push-scm-normalize.txt"
rg -F '"change_type": "push-protection"' \
  "$temporary_directory/github-push-scm-evidence.json" >/dev/null
rg -F ':network@sha256:' "$temporary_directory/github-push-scm-evidence.json" >/dev/null
if rg 'partner-org|product-api-integration|"forks"|"rules"|"conditions"' \
  "$temporary_directory/github-push-scm-evidence.json" >/dev/null; then
  echo "GitHub push SCM normalized evidence retained network members or ruleset body" >&2
  exit 1
fi

set +e
python3 "$verify" \
  --policy "$control/secure/policy.json" \
  --change-evidence "$temporary_directory/github-push-scm-evidence.json" \
  --evaluation-time "$evaluation_time" \
  >"$temporary_directory/github-push-scm-partial.txt"
github_push_scm_partial_status=$?
set -e
test "$github_push_scm_partial_status" -eq 1
rg -F "FAIL CPC-007 collector does not cover every required service" \
  "$temporary_directory/github-push-scm-partial.txt" >/dev/null

python3 "$control/scripts/normalize_github_branch_protection.py" "${github_legacy_branch_scm[@]}" \
  --output "$temporary_directory/github-legacy-branch-scm-evidence.json" \
  >"$temporary_directory/github-legacy-branch-scm-normalize.txt"
rg -F "NORMALIZED 1 GitHub legacy branch-protection change event" \
  "$temporary_directory/github-legacy-branch-scm-normalize.txt" >/dev/null
rg -F '"type": "github-legacy-branch-protection"' \
  "$temporary_directory/github-legacy-branch-scm-evidence.json" >/dev/null
if rg 'allow_force_pushes|hashed_token|user_agent|token_scopes|github-request-557' \
  "$temporary_directory/github-legacy-branch-scm-evidence.json" >/dev/null; then
  echo "GitHub legacy branch normalized evidence retained provider state or sensitive fields" >&2
  exit 1
fi

set +e
python3 "$verify" \
  --policy "$control/secure/policy.json" \
  --change-evidence "$temporary_directory/github-legacy-branch-scm-evidence.json" \
  --evaluation-time "$evaluation_time" \
  >"$temporary_directory/github-legacy-branch-scm-partial.txt"
github_legacy_branch_scm_partial_status=$?
set -e
test "$github_legacy_branch_scm_partial_status" -eq 1
rg -F "FAIL CPC-007 collector does not cover every required service" \
  "$temporary_directory/github-legacy-branch-scm-partial.txt" >/dev/null

python3 - \
  "$control/secure/change-evidence.json" \
  "$temporary_directory/github-evidence.json" \
  "$temporary_directory/aws-evidence.json" \
  "$temporary_directory/ecr-evidence.json" \
  "$temporary_directory/kms-evidence.json" \
  "$temporary_directory/github-scm-evidence.json" \
  "$temporary_directory/github-org-scm-evidence.json" \
  "$temporary_directory/github-tag-scm-evidence.json" \
  "$temporary_directory/github-push-scm-evidence.json" \
  "$temporary_directory/github-legacy-branch-scm-evidence.json" \
  "$temporary_directory/all-provider-composed.json" <<'PY'
import json
import sys
complete = json.load(open(sys.argv[1], encoding="utf-8"))
github = json.load(open(sys.argv[2], encoding="utf-8"))
aws = json.load(open(sys.argv[3], encoding="utf-8"))
ecr = json.load(open(sys.argv[4], encoding="utf-8"))
kms = json.load(open(sys.argv[5], encoding="utf-8"))
scm = json.load(open(sys.argv[6], encoding="utf-8"))
org_scm = json.load(open(sys.argv[7], encoding="utf-8"))
tag_scm = json.load(open(sys.argv[8], encoding="utf-8"))
push_scm = json.load(open(sys.argv[9], encoding="utf-8"))
legacy_branch_scm = json.load(open(sys.argv[10], encoding="utf-8"))
complete["changes"][0] = scm["changes"][0]
complete["changes"].append(github["changes"][1])
complete["changes"][1] = aws["changes"][0]
complete["changes"].append(ecr["changes"][0])
complete["changes"].append(kms["changes"][0])
complete["changes"].append(org_scm["changes"][0])
complete["changes"].append(tag_scm["changes"][0])
complete["changes"].append(push_scm["changes"][0])
complete["changes"].append(legacy_branch_scm["changes"][0])
json.dump(complete, open(sys.argv[11], "w", encoding="utf-8"), indent=2)
PY
python3 "$verify" \
  --policy "$control/secure/policy.json" \
  --change-evidence "$temporary_directory/all-provider-composed.json" \
  --evaluation-time "$evaluation_time" \
  >"$temporary_directory/all-provider-composed.txt"
diff -u "$control/expected-results/secure.txt" "$temporary_directory/all-provider-composed.txt"

echo "PASS ordinary and emergency privileged changes remain distinct"
echo "PASS actor session request approval execution and audit identities remain bound"
echo "PASS substitution wildcard broad session and missing review are rejected"
echo "PASS stale malformed unavailable and credential-bearing evidence fail closed"
echo "PASS GitHub audit normalization joins stable actor session request and exact policy values"
echo "PASS runner-group audit current state and reviewed digest are joined by stable group ID"
echo "PASS GitHub repository ruleset audit and exact before-after history bind stable repository and ruleset IDs"
echo "PASS GitHub organization ruleset audit and exact history bind stable organization and ruleset IDs"
echo "PASS GitHub tag ruleset update is distinct from branch protection and binds exact history"
echo "PASS GitHub push ruleset binds exact root and complete fork-network identity"
echo "PASS GitHub legacy branch force-push update binds exact repository branch and current state"
echo "PASS AWS CloudTrail current IAM role and reviewed trust digest are joined by stable role ID"
echo "PASS AWS CloudTrail current ECR policy and reviewed digest bind one repository generation"
echo "PASS AWS CloudTrail current KMS signing-key policy and reviewed digest bind one key ARN"
echo "PASS partial missing stale tampered and sensitive GitHub evidence cannot become a clean result"
echo "PASS partial failed substituted ambiguous and sensitive AWS evidence cannot become a clean result"
echo "PASS forced partial failed recreated tampered and ambiguous ECR evidence cannot become a clean result"
echo "PASS bypassed partial failed substituted tampered and ambiguous KMS evidence cannot become a clean result"
echo "PASS partial substituted stale tampered and later-version GitHub SCM evidence cannot become a clean result"
echo "PASS partial substituted contaminated and later-version GitHub organization SCM evidence cannot become a clean result"
echo "PASS missing partial stale substituted and organization-wide push scope fail closed"
echo "PASS missing partial stale substituted and later legacy branch state fails closed"
