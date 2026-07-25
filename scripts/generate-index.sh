#!/usr/bin/env bash
set -euo pipefail

mkdir -p generated
cat > generated/CONTROL_INDEX.md <<'EOF'
# Control Index

Generated control catalog.

| ID | Domain | Title | Status | Evidence |
|---|---|---|---|---|
| PSB-SOURCE-001 | source-protection | Harden developer endpoints and local trust boundaries | prototype | E3 |
EOF
echo "generated/CONTROL_INDEX.md"
