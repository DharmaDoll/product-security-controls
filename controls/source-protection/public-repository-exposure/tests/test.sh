#!/bin/sh
set -eu

CONTROL_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

python3 -m unittest discover \
  -s "$CONTROL_DIR/tests" \
  -p 'test_*.py' \
  -v
