.PHONY: bootstrap lint verify verify-control test generate-index generate-mappings validate-controls clean

bootstrap:
	@echo "No external bootstrap required."

lint: validate-controls
	@python3 scripts/generate-mappings.py --check-only

verify: test

test:
	@python3 -m unittest discover -s tests -p 'test_*.py'
	@python3 scripts/run-controls.py

verify-control:
	@test -n "$(CONTROL)" || (echo "CONTROL is required" >&2; exit 2)
	@python3 scripts/run-controls.py --control "$(CONTROL)"

generate-index:
	@bash scripts/generate-index.sh

generate-mappings:
	@bash scripts/generate-mappings.sh

validate-controls:
	@bash scripts/validate-controls.sh

clean:
	@rm -f generated/CONTROL_INDEX.md
	@rm -rf generated/mappings
