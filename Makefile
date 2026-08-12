.PHONY: bootstrap lint verify verify-control assess-control import-application-checklist collect-github-action-advisories verify-github-action-advisories collect-github-actions-build-platform collect-github-releases-evidence collect-slsa-consumer-evidence collect-slsa-security-review-evidence build-slsa-build-l2-evidence assess-slsa-build-l2 assess-slsa-build-l2-bundles test generate generate-index generate-mappings generate-checklists validate-controls clean

bootstrap:
	@echo "No external bootstrap required."

lint: validate-controls
	@python3 scripts/generate-index.py --check
	@python3 scripts/generate-mappings.py --check-only
	@python3 scripts/generate-checklists.py --check

verify: test

test:
	@python3 -m unittest discover -s tests -p 'test_*.py'
	@python3 scripts/run-controls.py

verify-control:
	@test -n "$(CONTROL)" || (echo "CONTROL is required" >&2; exit 2)
	@python3 scripts/run-controls.py --control "$(CONTROL)"

assess-control:
	@test -n "$(CONTROL)" || (echo "CONTROL is required" >&2; exit 2)
	@python3 scripts/run-assessments.py --control "$(CONTROL)"

import-application-checklist:
	@test -n "$(APPLICATION_CHECKLIST_MANIFEST)" || (echo "APPLICATION_CHECKLIST_MANIFEST is required" >&2; exit 2)
	@test -n "$(APPLICATION_CHECKLIST_OUTPUT)" || (echo "APPLICATION_CHECKLIST_OUTPUT is required" >&2; exit 2)
	@python3 scripts/import-application-checklist.py \
		--manifest "$(APPLICATION_CHECKLIST_MANIFEST)" \
		--output "$(APPLICATION_CHECKLIST_OUTPUT)"

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
