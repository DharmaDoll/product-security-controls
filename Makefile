.PHONY: bootstrap lint verify verify-control test generate-index generate-mappings validate-controls clean

bootstrap:
	@echo "No external bootstrap required."

lint: validate-controls
	@ruby -e 'require "yaml"; Dir["controls/*/*/control.yaml"].each { |path| YAML.load_file(path) }; puts "control metadata parsed"'

verify: test

test:
	@bash controls/source-protection/developer-endpoint-hardening/tests/test.sh

verify-control:
	@test -n "$(CONTROL)" || (echo "CONTROL is required" >&2; exit 2)
	@test "$(CONTROL)" = "PSB-SOURCE-001" || (echo "unknown control: $(CONTROL)" >&2; exit 2)
	@bash controls/source-protection/developer-endpoint-hardening/tests/test.sh

generate-index:
	@bash scripts/generate-index.sh

generate-mappings:
	@bash scripts/generate-mappings.sh

validate-controls:
	@bash scripts/validate-controls.sh

clean:
	@rm -f generated/CONTROL_INDEX.md
	@rm -rf generated/mappings
