.PHONY: bootstrap lint verify verify-control verify-sitf-coverage assess-control import-application-checklist collect-github-control-plane-audit collect-github-runner-group-state collect-github-ruleset-state collect-github-organization-ruleset-state collect-github-fork-network-state collect-github-branch-protection-state normalize-github-control-plane-evidence normalize-github-ruleset-control-plane-evidence normalize-github-branch-protection-evidence normalize-aws-control-plane-evidence normalize-aws-ecr-control-plane-evidence normalize-aws-kms-control-plane-evidence collect-github-action-advisories verify-github-action-advisories collect-github-actions-build-platform collect-github-releases-evidence collect-slsa-consumer-evidence collect-slsa-security-review-evidence build-slsa-build-l2-evidence assess-slsa-build-l2 assess-slsa-build-l2-bundles test generate generate-index generate-mappings generate-checklists validate-controls clean

bootstrap:
	@echo "No external bootstrap required."

lint: validate-controls
	@python3 scripts/generate-index.py --check
	@python3 scripts/generate-mappings.py --check-only
	@python3 scripts/generate-checklists.py --check
	@python3 scripts/sitf_coverage.py --check-only

verify: test

test:
	@python3 -m unittest discover -s tests -p 'test_*.py'
	@python3 scripts/run-controls.py

verify-control:
	@test -n "$(CONTROL)" || (echo "CONTROL is required" >&2; exit 2)
	@python3 scripts/run-controls.py --control "$(CONTROL)"

verify-sitf-coverage:
	@python3 scripts/sitf_coverage.py

assess-control:
	@test -n "$(CONTROL)" || (echo "CONTROL is required" >&2; exit 2)
	@python3 scripts/run-assessments.py --control "$(CONTROL)"

import-application-checklist:
	@test -n "$(APPLICATION_CHECKLIST_MANIFEST)" || (echo "APPLICATION_CHECKLIST_MANIFEST is required" >&2; exit 2)
	@test -n "$(APPLICATION_CHECKLIST_OUTPUT)" || (echo "APPLICATION_CHECKLIST_OUTPUT is required" >&2; exit 2)
	@python3 scripts/import-application-checklist.py \
		--manifest "$(APPLICATION_CHECKLIST_MANIFEST)" \
		--output "$(APPLICATION_CHECKLIST_OUTPUT)"

normalize-github-control-plane-evidence:
	@test -n "$(GITHUB_AUDIT_EVENTS)" || (echo "GITHUB_AUDIT_EVENTS is required" >&2; exit 2)
	@test -n "$(GITHUB_ADMIN_SESSIONS)" || (echo "GITHUB_ADMIN_SESSIONS is required" >&2; exit 2)
	@test -n "$(GITHUB_CHANGE_REGISTER)" || (echo "GITHUB_CHANGE_REGISTER is required" >&2; exit 2)
	@test -n "$(GITHUB_RUNNER_GROUPS)" || (echo "GITHUB_RUNNER_GROUPS is required" >&2; exit 2)
	@test -n "$(CONTROL_PLANE_EVIDENCE_OUTPUT)" || (echo "CONTROL_PLANE_EVIDENCE_OUTPUT is required" >&2; exit 2)
	@python3 controls/cicd-security/privileged-control-plane-change/scripts/normalize_github.py \
		--audit-events "$(GITHUB_AUDIT_EVENTS)" \
		--identity-sessions "$(GITHUB_ADMIN_SESSIONS)" \
		--change-register "$(GITHUB_CHANGE_REGISTER)" \
		--runner-groups "$(GITHUB_RUNNER_GROUPS)" \
		--output "$(CONTROL_PLANE_EVIDENCE_OUTPUT)"

collect-github-control-plane-audit:
	@test -n "$(GITHUB_ORGANIZATION)" || (echo "GITHUB_ORGANIZATION is required" >&2; exit 2)
	@test -n "$(AUDIT_WINDOW_START)" || (echo "AUDIT_WINDOW_START is required" >&2; exit 2)
	@test -n "$(AUDIT_WINDOW_END)" || (echo "AUDIT_WINDOW_END is required" >&2; exit 2)
	@test -n "$(GITHUB_AUDIT_OUTPUT)" || (echo "GITHUB_AUDIT_OUTPUT is required" >&2; exit 2)
	@python3 controls/cicd-security/privileged-control-plane-change/scripts/collect_github_audit.py \
		--organization "$(GITHUB_ORGANIZATION)" \
		--since "$(AUDIT_WINDOW_START)" \
		--until "$(AUDIT_WINDOW_END)" \
		--output "$(GITHUB_AUDIT_OUTPUT)"

collect-github-runner-group-state:
	@test -n "$(GITHUB_ORGANIZATION)" || (echo "GITHUB_ORGANIZATION is required" >&2; exit 2)
	@test -n "$(GITHUB_RUNNER_GROUP_ID)" || (echo "GITHUB_RUNNER_GROUP_ID is required" >&2; exit 2)
	@test -n "$(GITHUB_RUNNER_GROUP_OUTPUT)" || (echo "GITHUB_RUNNER_GROUP_OUTPUT is required" >&2; exit 2)
	@python3 controls/cicd-security/privileged-control-plane-change/scripts/collect_github_runner_group.py \
		--organization "$(GITHUB_ORGANIZATION)" \
		--runner-group-id "$(GITHUB_RUNNER_GROUP_ID)" \
		--output "$(GITHUB_RUNNER_GROUP_OUTPUT)"

collect-github-ruleset-state:
	@test -n "$(GITHUB_ORGANIZATION)" || (echo "GITHUB_ORGANIZATION is required" >&2; exit 2)
	@test -n "$(GITHUB_REPOSITORY)" || (echo "GITHUB_REPOSITORY is required" >&2; exit 2)
	@test -n "$(GITHUB_RULESET_ID)" || (echo "GITHUB_RULESET_ID is required" >&2; exit 2)
	@test -n "$(GITHUB_RULESET_BEFORE_VERSION_ID)" || (echo "GITHUB_RULESET_BEFORE_VERSION_ID is required" >&2; exit 2)
	@test -n "$(GITHUB_RULESET_AFTER_VERSION_ID)" || (echo "GITHUB_RULESET_AFTER_VERSION_ID is required" >&2; exit 2)
	@test -n "$(GITHUB_RULESET_OUTPUT)" || (echo "GITHUB_RULESET_OUTPUT is required" >&2; exit 2)
	@python3 controls/cicd-security/privileged-control-plane-change/scripts/collect_github_ruleset.py \
		--organization "$(GITHUB_ORGANIZATION)" \
		--repository "$(GITHUB_REPOSITORY)" \
		--ruleset-id "$(GITHUB_RULESET_ID)" \
		--before-version-id "$(GITHUB_RULESET_BEFORE_VERSION_ID)" \
		--after-version-id "$(GITHUB_RULESET_AFTER_VERSION_ID)" \
		--output "$(GITHUB_RULESET_OUTPUT)"

collect-github-organization-ruleset-state:
	@test -n "$(GITHUB_ORGANIZATION)" || (echo "GITHUB_ORGANIZATION is required" >&2; exit 2)
	@test -n "$(GITHUB_RULESET_ID)" || (echo "GITHUB_RULESET_ID is required" >&2; exit 2)
	@test -n "$(GITHUB_RULESET_BEFORE_VERSION_ID)" || (echo "GITHUB_RULESET_BEFORE_VERSION_ID is required" >&2; exit 2)
	@test -n "$(GITHUB_RULESET_AFTER_VERSION_ID)" || (echo "GITHUB_RULESET_AFTER_VERSION_ID is required" >&2; exit 2)
	@test -n "$(GITHUB_RULESET_OUTPUT)" || (echo "GITHUB_RULESET_OUTPUT is required" >&2; exit 2)
	@python3 controls/cicd-security/privileged-control-plane-change/scripts/collect_github_ruleset.py \
		--organization "$(GITHUB_ORGANIZATION)" \
		--ruleset-id "$(GITHUB_RULESET_ID)" \
		--before-version-id "$(GITHUB_RULESET_BEFORE_VERSION_ID)" \
		--after-version-id "$(GITHUB_RULESET_AFTER_VERSION_ID)" \
		--output "$(GITHUB_RULESET_OUTPUT)"

collect-github-fork-network-state:
	@test -n "$(GITHUB_ORGANIZATION)" || (echo "GITHUB_ORGANIZATION is required" >&2; exit 2)
	@test -n "$(GITHUB_REPOSITORY)" || (echo "GITHUB_REPOSITORY is required" >&2; exit 2)
	@test -n "$(GITHUB_FORK_NETWORK_OUTPUT)" || (echo "GITHUB_FORK_NETWORK_OUTPUT is required" >&2; exit 2)
	@python3 controls/cicd-security/privileged-control-plane-change/scripts/collect_github_fork_network.py \
		--organization "$(GITHUB_ORGANIZATION)" \
		--repository "$(GITHUB_REPOSITORY)" \
		--output "$(GITHUB_FORK_NETWORK_OUTPUT)"

collect-github-branch-protection-state:
	@test -n "$(GITHUB_ORGANIZATION)" || (echo "GITHUB_ORGANIZATION is required" >&2; exit 2)
	@test -n "$(GITHUB_REPOSITORY)" || (echo "GITHUB_REPOSITORY is required" >&2; exit 2)
	@test -n "$(GITHUB_BRANCH)" || (echo "GITHUB_BRANCH is required" >&2; exit 2)
	@test -n "$(GITHUB_BRANCH_PROTECTION_OUTPUT)" || (echo "GITHUB_BRANCH_PROTECTION_OUTPUT is required" >&2; exit 2)
	@python3 controls/cicd-security/privileged-control-plane-change/scripts/collect_github_branch_protection.py \
		--organization "$(GITHUB_ORGANIZATION)" \
		--repository "$(GITHUB_REPOSITORY)" \
		--branch "$(GITHUB_BRANCH)" \
		--output "$(GITHUB_BRANCH_PROTECTION_OUTPUT)"

normalize-github-ruleset-control-plane-evidence:
	@test -n "$(GITHUB_AUDIT_EVENTS)" || (echo "GITHUB_AUDIT_EVENTS is required" >&2; exit 2)
	@test -n "$(GITHUB_ADMIN_SESSIONS)" || (echo "GITHUB_ADMIN_SESSIONS is required" >&2; exit 2)
	@test -n "$(GITHUB_CHANGE_REGISTER)" || (echo "GITHUB_CHANGE_REGISTER is required" >&2; exit 2)
	@test -n "$(GITHUB_RULESET_SNAPSHOT)" || (echo "GITHUB_RULESET_SNAPSHOT is required" >&2; exit 2)
	@test -n "$(CONTROL_PLANE_EVIDENCE_OUTPUT)" || (echo "CONTROL_PLANE_EVIDENCE_OUTPUT is required" >&2; exit 2)
	@python3 controls/cicd-security/privileged-control-plane-change/scripts/normalize_github_ruleset.py \
		--audit-events "$(GITHUB_AUDIT_EVENTS)" \
		--identity-sessions "$(GITHUB_ADMIN_SESSIONS)" \
		--change-register "$(GITHUB_CHANGE_REGISTER)" \
		--ruleset-snapshot "$(GITHUB_RULESET_SNAPSHOT)" \
		$(if $(GITHUB_FORK_NETWORK_SNAPSHOT),--fork-network-snapshot "$(GITHUB_FORK_NETWORK_SNAPSHOT)") \
		--output "$(CONTROL_PLANE_EVIDENCE_OUTPUT)"

normalize-github-branch-protection-evidence:
	@test -n "$(GITHUB_AUDIT_EVENTS)" || (echo "GITHUB_AUDIT_EVENTS is required" >&2; exit 2)
	@test -n "$(GITHUB_ADMIN_SESSIONS)" || (echo "GITHUB_ADMIN_SESSIONS is required" >&2; exit 2)
	@test -n "$(GITHUB_CHANGE_REGISTER)" || (echo "GITHUB_CHANGE_REGISTER is required" >&2; exit 2)
	@test -n "$(GITHUB_BRANCH_PROTECTION_SNAPSHOT)" || (echo "GITHUB_BRANCH_PROTECTION_SNAPSHOT is required" >&2; exit 2)
	@test -n "$(CONTROL_PLANE_EVIDENCE_OUTPUT)" || (echo "CONTROL_PLANE_EVIDENCE_OUTPUT is required" >&2; exit 2)
	@python3 controls/cicd-security/privileged-control-plane-change/scripts/normalize_github_branch_protection.py \
		--audit-events "$(GITHUB_AUDIT_EVENTS)" \
		--identity-sessions "$(GITHUB_ADMIN_SESSIONS)" \
		--change-register "$(GITHUB_CHANGE_REGISTER)" \
		--branch-protection-snapshot "$(GITHUB_BRANCH_PROTECTION_SNAPSHOT)" \
		--output "$(CONTROL_PLANE_EVIDENCE_OUTPUT)"

normalize-aws-control-plane-evidence:
	@test -n "$(AWS_CLOUDTRAIL_EVENTS)" || (echo "AWS_CLOUDTRAIL_EVENTS is required" >&2; exit 2)
	@test -n "$(AWS_ADMIN_SESSIONS)" || (echo "AWS_ADMIN_SESSIONS is required" >&2; exit 2)
	@test -n "$(AWS_CHANGE_REGISTER)" || (echo "AWS_CHANGE_REGISTER is required" >&2; exit 2)
	@test -n "$(AWS_IAM_ROLES)" || (echo "AWS_IAM_ROLES is required" >&2; exit 2)
	@test -n "$(CONTROL_PLANE_EVIDENCE_OUTPUT)" || (echo "CONTROL_PLANE_EVIDENCE_OUTPUT is required" >&2; exit 2)
	@python3 controls/cicd-security/privileged-control-plane-change/scripts/normalize_aws.py \
		--cloudtrail-events "$(AWS_CLOUDTRAIL_EVENTS)" \
		--identity-sessions "$(AWS_ADMIN_SESSIONS)" \
		--change-register "$(AWS_CHANGE_REGISTER)" \
		--iam-roles "$(AWS_IAM_ROLES)" \
		--output "$(CONTROL_PLANE_EVIDENCE_OUTPUT)"

normalize-aws-ecr-control-plane-evidence:
	@test -n "$(AWS_ECR_CLOUDTRAIL_EVENTS)" || (echo "AWS_ECR_CLOUDTRAIL_EVENTS is required" >&2; exit 2)
	@test -n "$(AWS_ECR_ADMIN_SESSIONS)" || (echo "AWS_ECR_ADMIN_SESSIONS is required" >&2; exit 2)
	@test -n "$(AWS_ECR_CHANGE_REGISTER)" || (echo "AWS_ECR_CHANGE_REGISTER is required" >&2; exit 2)
	@test -n "$(AWS_ECR_REPOSITORIES)" || (echo "AWS_ECR_REPOSITORIES is required" >&2; exit 2)
	@test -n "$(CONTROL_PLANE_EVIDENCE_OUTPUT)" || (echo "CONTROL_PLANE_EVIDENCE_OUTPUT is required" >&2; exit 2)
	@python3 controls/cicd-security/privileged-control-plane-change/scripts/normalize_aws_ecr.py \
		--cloudtrail-events "$(AWS_ECR_CLOUDTRAIL_EVENTS)" \
		--identity-sessions "$(AWS_ECR_ADMIN_SESSIONS)" \
		--change-register "$(AWS_ECR_CHANGE_REGISTER)" \
		--repositories "$(AWS_ECR_REPOSITORIES)" \
		--output "$(CONTROL_PLANE_EVIDENCE_OUTPUT)"

normalize-aws-kms-control-plane-evidence:
	@test -n "$(AWS_KMS_CLOUDTRAIL_EVENTS)" || (echo "AWS_KMS_CLOUDTRAIL_EVENTS is required" >&2; exit 2)
	@test -n "$(AWS_KMS_ADMIN_SESSIONS)" || (echo "AWS_KMS_ADMIN_SESSIONS is required" >&2; exit 2)
	@test -n "$(AWS_KMS_CHANGE_REGISTER)" || (echo "AWS_KMS_CHANGE_REGISTER is required" >&2; exit 2)
	@test -n "$(AWS_KMS_KEYS)" || (echo "AWS_KMS_KEYS is required" >&2; exit 2)
	@test -n "$(CONTROL_PLANE_EVIDENCE_OUTPUT)" || (echo "CONTROL_PLANE_EVIDENCE_OUTPUT is required" >&2; exit 2)
	@python3 controls/cicd-security/privileged-control-plane-change/scripts/normalize_aws_kms.py \
		--cloudtrail-events "$(AWS_KMS_CLOUDTRAIL_EVENTS)" \
		--identity-sessions "$(AWS_KMS_ADMIN_SESSIONS)" \
		--change-register "$(AWS_KMS_CHANGE_REGISTER)" \
		--keys "$(AWS_KMS_KEYS)" \
		--output "$(CONTROL_PLANE_EVIDENCE_OUTPUT)"

collect-github-action-advisories:
	@python3 controls/cicd-security/action-sha-pinning/scripts/collect-advisories.py \
		--output "$(or $(ADVISORY_SNAPSHOT),generated/advisories/github-actions.json)"

verify-github-action-advisories:
	@test -n "$(ACTION_INVENTORY)" || (echo "ACTION_INVENTORY is required" >&2; exit 2)
	@test -n "$(ADVISORY_SNAPSHOT)" || (echo "ADVISORY_SNAPSHOT is required" >&2; exit 2)
	@test -n "$(AS_OF)" || (echo "AS_OF is required" >&2; exit 2)
	@python3 controls/cicd-security/action-sha-pinning/scripts/verify-advisories.py \
		--inventory "$(ACTION_INVENTORY)" \
		--snapshot "$(ADVISORY_SNAPSHOT)" \
		--as-of "$(AS_OF)"

collect-github-actions-build-platform:
	@test -n "$(COLLECTOR_POLICY)" || (echo "COLLECTOR_POLICY is required" >&2; exit 2)
	@test -n "$(BUNDLE_OUTPUT)" || (echo "BUNDLE_OUTPUT is required" >&2; exit 2)
	@test -n "$(RECEIPT_OUTPUT)" || (echo "RECEIPT_OUTPUT is required" >&2; exit 2)
	@python3 scripts/collect-github-actions-build-platform.py \
		--policy "$(COLLECTOR_POLICY)" \
		--output "$(BUNDLE_OUTPUT)" \
		--receipt-output "$(RECEIPT_OUTPUT)" \
		$(if $(GH_CLI),--gh "$(GH_CLI)")

collect-github-releases-evidence:
	@test -n "$(COLLECTOR_POLICY)" || (echo "COLLECTOR_POLICY is required" >&2; exit 2)
	@test -n "$(BUNDLE_OUTPUT)" || (echo "BUNDLE_OUTPUT is required" >&2; exit 2)
	@test -n "$(RECEIPT_OUTPUT)" || (echo "RECEIPT_OUTPUT is required" >&2; exit 2)
	@python3 scripts/collect-github-releases-evidence.py \
		--policy "$(COLLECTOR_POLICY)" \
		--output "$(BUNDLE_OUTPUT)" \
		--receipt-output "$(RECEIPT_OUTPUT)" \
		$(if $(GH_CLI),--gh "$(GH_CLI)")

collect-slsa-consumer-evidence:
	@test -n "$(COLLECTOR_POLICY)" || (echo "COLLECTOR_POLICY is required" >&2; exit 2)
	@test -n "$(BUNDLE_OUTPUT)" || (echo "BUNDLE_OUTPUT is required" >&2; exit 2)
	@test -n "$(RECEIPT_OUTPUT)" || (echo "RECEIPT_OUTPUT is required" >&2; exit 2)
	@python3 scripts/collect-slsa-consumer-evidence.py \
		--policy "$(COLLECTOR_POLICY)" \
		--output "$(BUNDLE_OUTPUT)" \
		--receipt-output "$(RECEIPT_OUTPUT)" \
		$(if $(OPENSSL),--openssl "$(OPENSSL)")

collect-slsa-security-review-evidence:
	@test -n "$(COLLECTOR_POLICY)" || (echo "COLLECTOR_POLICY is required" >&2; exit 2)
	@test -n "$(BUNDLE_OUTPUT)" || (echo "BUNDLE_OUTPUT is required" >&2; exit 2)
	@test -n "$(RECEIPT_OUTPUT)" || (echo "RECEIPT_OUTPUT is required" >&2; exit 2)
	@python3 scripts/collect-slsa-security-review-evidence.py \
		--policy "$(COLLECTOR_POLICY)" \
		--output "$(BUNDLE_OUTPUT)" \
		--receipt-output "$(RECEIPT_OUTPUT)" \
		$(if $(OPENSSL),--openssl "$(OPENSSL)")

build-slsa-build-l2-evidence:
	@test -n "$(ADAPTER_POLICY)" || (echo "ADAPTER_POLICY is required" >&2; exit 2)
	@python3 scripts/build-slsa-build-l2-evidence.py \
		--assessment-policy policies/framework-assessments/slsa-build-l2.json \
		--adapter-policy "$(ADAPTER_POLICY)" \
		--output generated/assessments/slsa-build-l2-evidence.json

assess-slsa-build-l2:
	@test -n "$(EVIDENCE)" || (echo "EVIDENCE is required" >&2; exit 2)
	@python3 scripts/assess-slsa-build-l2.py \
		--policy policies/framework-assessments/slsa-build-l2.json \
		--coverage generated/checklists/profiles/slsa-build-l2-coverage.csv \
		--evidence "$(EVIDENCE)" \
		--json-output generated/assessments/slsa-build-l2.json \
		--csv-output generated/assessments/slsa-build-l2.csv

assess-slsa-build-l2-bundles: build-slsa-build-l2-evidence
	@python3 scripts/assess-slsa-build-l2.py \
		--policy policies/framework-assessments/slsa-build-l2.json \
		--coverage generated/checklists/profiles/slsa-build-l2-coverage.csv \
		--evidence generated/assessments/slsa-build-l2-evidence.json \
		--json-output generated/assessments/slsa-build-l2.json \
		--csv-output generated/assessments/slsa-build-l2.csv

generate: generate-index generate-mappings generate-checklists

generate-index:
	@bash scripts/generate-index.sh

generate-mappings:
	@bash scripts/generate-mappings.sh

generate-checklists:
	@bash scripts/generate-checklists.sh

validate-controls:
	@bash scripts/validate-controls.sh

clean:
	@rm -f generated/CONTROL_INDEX.md
	@rm -rf generated/mappings
	@rm -rf generated/checklists
	@rm -rf generated/assessments
	@rm -rf generated/advisories
