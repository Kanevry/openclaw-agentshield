#!/usr/bin/env bash
# deploy.sh — Deploy AgentShield to the Hackathon demo server
#
# Usage: ./scripts/deploy.sh
#
# Prerequisites:
#   - SSH access to 188.245.81.195
#   - OpenClaw running on the server
#   - Git repo cloned at /opt/openclaw-agentshield

set -euo pipefail

SERVER="188.245.81.195"
REMOTE_USER="root"
REMOTE_DIR="/opt/openclaw-agentshield"
DASHBOARD_URL="https://openclaw.gotzendorfer.at/agentshield"
GATEWAY_PORT=18789

echo "=== AgentShield Deploy ==="
echo "Target: ${REMOTE_USER}@${SERVER}:${REMOTE_DIR}"

# Typecheck before deploy
echo "→ Running typecheck..."
pnpm run typecheck

# Pull latest changes on server
echo "→ Pulling latest changes on server..."
ssh "${REMOTE_USER}@${SERVER}" "cd ${REMOTE_DIR} && git pull origin main"

# Install deps on server (in case they changed)
echo "→ Installing dependencies on server..."
ssh "${REMOTE_USER}@${SERVER}" "cd ${REMOTE_DIR} && pnpm install --prod 2>/dev/null || npm install --omit=dev 2>/dev/null || true"

# Reload gateway
echo "→ Reloading OpenClaw gateway..."
ssh "${REMOTE_USER}@${SERVER}" "kill -HUP \$(pgrep -f openclaw-gateway) 2>/dev/null || echo 'WARN: Could not send HUP — gateway process not found, manual restart needed'"

# Post-deploy verification
echo "→ Verifying deployment..."
sleep 2
HTTP_STATUS=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://${SERVER}:${GATEWAY_PORT}/agentshield" 2>/dev/null || echo "000")
if [ "$HTTP_STATUS" = "200" ] || [ "$HTTP_STATUS" = "401" ] || [ "$HTTP_STATUS" = "302" ]; then
  echo "✓ Dashboard endpoint responded with HTTP ${HTTP_STATUS}"
else
  echo "⚠ Dashboard endpoint returned HTTP ${HTTP_STATUS} — check server logs"
  echo "  Debug: ssh ${SERVER} 'ps aux | grep openclaw'"
fi

echo ""
echo "=== Deploy complete ==="
echo "Dashboard: ${DASHBOARD_URL}"
echo "Check logs: ssh ${SERVER} 'tail -f /opt/openclaw-agentshield/*.log 2>/dev/null || journalctl -f 2>/dev/null || echo \"Check process output manually\"'"
