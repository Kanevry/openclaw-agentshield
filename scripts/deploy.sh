#!/usr/bin/env bash
# deploy.sh — Deploy AgentShield to the Clank Gateway server
#
# Usage: ./scripts/deploy.sh
#
# Prerequisites:
#   - SSH access to 46.224.162.185
#   - OpenClaw running on the server
#   - Plugin directory configured in openclaw config

set -euo pipefail

SERVER="46.224.162.185"
REMOTE_USER="root"
REMOTE_DIR="/root/.openclaw/plugins/agentshield"

echo "=== AgentShield Deploy ==="
echo "Target: ${REMOTE_USER}@${SERVER}:${REMOTE_DIR}"

# Typecheck before deploy
echo "→ Running typecheck..."
pnpm run typecheck

# Sync source files to server
echo "→ Syncing files..."
rsync -avz --delete \
  --exclude node_modules \
  --exclude .git \
  --exclude dist \
  --exclude research \
  --exclude options \
  --exclude snippets \
  --exclude tests \
  --exclude ssot \
  --exclude docs \
  --exclude .claude \
  ./ "${REMOTE_USER}@${SERVER}:${REMOTE_DIR}/"

# Install deps on server
echo "→ Installing dependencies on server..."
ssh "${REMOTE_USER}@${SERVER}" "cd ${REMOTE_DIR} && pnpm install --prod 2>/dev/null || npm install --omit=dev 2>/dev/null || true"

# Restart gateway
echo "→ Restarting OpenClaw gateway..."
ssh "${REMOTE_USER}@${SERVER}" "systemctl restart openclaw-gateway 2>/dev/null || supervisorctl restart openclaw 2>/dev/null || echo 'Manual restart needed'"

echo ""
echo "=== Deploy complete ==="
echo "Dashboard: https://agentshield.gotzendorfer.at"
echo "Check logs: ssh ${SERVER} 'journalctl -u openclaw-gateway -f'"
