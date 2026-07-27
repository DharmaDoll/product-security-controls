.PHONY: bootstrap lint verify verify-control test generate generate-index generate-mappings generate-checklists validate-controls clean

bootstrap:
	@echo "No external bootstrap required."

lint: validate-controls
	@python3 scripts/generate-mappings.py --check-only
	@python3 scripts/generate-checklists.py --check

verify: test

test:
	@python3 -m unittest discover -s tests -p 'test_*.py'
	@python3 scripts/run-controls.py

verify-control:
	@test -n "$(CONTROL)" || (echo "CONTROL is required" >&2; exit 2)
	@python3 scripts/run-controls.py --control "$(CONTROL)"

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
