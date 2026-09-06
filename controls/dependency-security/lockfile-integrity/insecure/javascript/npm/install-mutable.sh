#!/usr/bin/env bash
# INSECURE EXAMPLE: npm install may update package-lock.json during a normal CI install.
set -euo pipefail

cd "${1:-.}"
npm install
