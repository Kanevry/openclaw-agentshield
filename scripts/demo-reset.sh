#!/usr/bin/env bash
# demo-reset.sh — Prepare the server for a clean AgentShield demo
#
# Usage: ./scripts/demo-reset.sh
#
# What it does:
#   1. Kills the OpenClaw gateway process (systemd/process manager respawns it)
#   2. Verifies the gateway came back up
#   3. Verifies the dashboard endpoint returns 200
#   4. Prints a summary of what's ready
#
# GitLab: #29

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCRIPT_DIR}/../.env.local"

if [ ! -f "$ENV_FILE" ]; then
  echo "ERROR: .env.local not found. Create it with GATEWAY_TOKEN=<token>"
  exit 1
fi

# shellcheck source=/dev/null
source "$ENV_FILE"

SERVER="${SERVER:-188.245.81.195}"
REMOTE_USER="${REMOTE_USER:-root}"
GATEWAY_PORT="${GATEWAY_PORT:-18789}"

if [ -z "${GATEWAY_TOKEN:-}" ]; then
  echo "ERROR: GATEWAY_TOKEN not set in .env.local"
  exit 1
fi

echo "=== AgentShield Demo Reset ==="
echo "Server: ${REMOTE_USER}@${SERVER}"
echo ""

# Step 1: Kill the gateway process and let it respawn
echo "→ [1/4] Restarting OpenClaw gateway..."
ssh "${REMOTE_USER}@${SERVER}" "kill \$(pgrep -f openclaw-gateway) 2>/dev/null && echo 'Gateway process killed' || echo 'WARN: No gateway process found'"
echo "  Waiting 3s for respawn..."
sleep 3

# Step 2: Verify the gateway is running
echo "→ [2/4] Verifying gateway process..."
GATEWAY_STATUS=$(ssh "${REMOTE_USER}@${SERVER}" "pgrep -la openclaw 2>/dev/null || true")
if [ -z "$GATEWAY_STATUS" ]; then
  echo "  FAIL: Gateway process not found after restart!"
  echo "  Debug: ssh ${REMOTE_USER}@${SERVER} 'journalctl -u openclaw --no-pager -n 20'"
  exit 1
fi
echo "  OK: ${GATEWAY_STATUS}"

# Step 3: Verify the dashboard endpoint returns 200
echo "→ [3/4] Verifying dashboard endpoint..."
DASH_STATUS=$(ssh "${REMOTE_USER}@${SERVER}" "curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer ${GATEWAY_TOKEN}' --max-time 10 http://localhost:${GATEWAY_PORT}/agentshield")
if [ "$DASH_STATUS" = "200" ]; then
  echo "  OK: Dashboard returned HTTP ${DASH_STATUS}"
else
  echo "  WARN: Dashboard returned HTTP ${DASH_STATUS} (expected 200)"
  echo "  The gateway may still be initializing — try again in a few seconds"
fi

# Step 4: Summary
echo ""
echo "=== Demo Ready ==="
echo ""
echo "  Gateway process : running"
echo "  Dashboard (local): http://localhost:${GATEWAY_PORT}/agentshield -> HTTP ${DASH_STATUS}"
echo "  Dashboard (public): https://openclaw.gotzendorfer.at/agentshield"
echo "  Landing page     : https://agentshield.gotzendorfer.at"
echo ""
echo "  Demo agent: Atlas (Discord, claude-opus-4-6)"
echo ""

if [ "$DASH_STATUS" = "200" ]; then
  echo "All systems go. Ready for demo."
else
  echo "WARNING: Dashboard not returning 200 yet. Check server logs before demo."
  echo "  ssh ${REMOTE_USER}@${SERVER} 'journalctl -u openclaw --no-pager -n 30'"
fi
