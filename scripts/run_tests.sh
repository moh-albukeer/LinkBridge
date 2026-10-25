#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "=== Running LinkBridge Automated & Integration Test Suite ==="
python3 -u "$PROJECT_ROOT/tests/test_linkbridge_suite.py"
echo "=== Running LinkBridge Windows Self-Check ==="
python3 -u "$PROJECT_ROOT/windows/app.py" --self-check --data-dir /tmp/lb_self_check_cli
