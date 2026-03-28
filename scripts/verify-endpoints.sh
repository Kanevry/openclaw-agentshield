#!/usr/bin/env bash
# verify-endpoints.sh — Verify all public AgentShield endpoints are reachable
#
# Usage: ./scripts/verify-endpoints.sh
#
# Checks:
#   - Landing page (agentshield.gotzendorfer.at)
#   - Dashboard (openclaw.gotzendorfer.at/agentshield)
#   - Stats API (openclaw.gotzendorfer.at/agentshield/api/stats)
#
# GitLab: #29

set -euo pipefail

PASS=0
FAIL=0

check_endpoint() {
  local name="$1"
  local url="$2"
  local expected="$3"

  local status
  status=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$url" 2>/dev/null || echo "000")

  if [ "$status" = "$expected" ]; then
    echo "  OK   ${name} -> HTTP ${status}"
    PASS=$((PASS + 1))
  else
    echo "  FAIL ${name} -> HTTP ${status} (expected ${expected})"
    FAIL=$((FAIL + 1))
  fi
}

echo "=== AgentShield Endpoint Verification ==="
echo ""

check_endpoint "Landing page " "https://agentshield.gotzendorfer.at"                    "200"
check_endpoint "Dashboard    " "https://openclaw.gotzendorfer.at/agentshield"            "200"
check_endpoint "Stats API    " "https://openclaw.gotzendorfer.at/agentshield/api/stats"  "200"

echo ""
echo "Results: ${PASS} passed, ${FAIL} failed"

if [ "$FAIL" -gt 0 ]; then
  echo ""
  echo "Troubleshooting:"
  echo "  - Check Caddy: ssh root@188.245.81.195 'systemctl status caddy'"
  echo "  - Check gateway: ssh root@188.245.81.195 'pgrep -la openclaw'"
  echo "  - Check logs: ssh root@188.245.81.195 'journalctl -u openclaw --no-pager -n 20'"
  exit 1
fi
