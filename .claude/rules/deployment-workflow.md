---
description: Deployment workflow for AgentShield on Hetzner server — pre-deployment checks, deploy steps, verification
globs: ["scripts/deploy*", "openclaw.plugin.json", "package.json"]
---

# Deployment Workflow

## Server
- Host: 188.245.81.195 (openclaw-hackathron, Hetzner CX43)
- Deploy Path: /opt/openclaw-agentshield/
- Gateway Port: 18789 (localhost only, Caddy reverse proxy on :443)
- Dashboard: openclaw.gotzendorfer.at/agentshield (public via Caddy auth injection)

## Pre-Deployment Checklist
1. `pnpm run typecheck` — 0 Errors
2. `pnpm test` — All tests green
3. `pnpm run test:scanner` — Corpus validation passed
4. Git clean, all committed and pushed to origin

## Deploy Steps
1. Push to GitLab: `git push origin main`
2. SSH pull: `ssh root@188.245.81.195 'cd /opt/openclaw-agentshield && git pull origin main'`
3. Install deps: `ssh root@188.245.81.195 'cd /opt/openclaw-agentshield && pnpm install --frozen-lockfile'`
4. Reload gateway: `ssh root@188.245.81.195 'kill -HUP $(pgrep -f openclaw-gateway)'`
5. Verify: `curl -s -o /dev/null -w "%{http_code}" https://openclaw.gotzendorfer.at/agentshield`

## Post-Deploy Verification
- Dashboard loads: https://openclaw.gotzendorfer.at/agentshield
- SSE stream connects: /agentshield/events returns text/event-stream
- API responds: /agentshield/api/stats returns JSON
- Atlas responds on Discord after sending a test message

## Rollback
- `ssh root@188.245.81.195 'cd /opt/openclaw-agentshield && git checkout <previous-commit>'`
- `ssh root@188.245.81.195 'kill -HUP $(pgrep -f openclaw-gateway)'`

## Notes
- Gateway reload is graceful (SIGHUP) — no downtime
- Plugin runs in-process via jiti — errors crash gateway, always use safeHandler()
- Caddy handles TLS auto-renewal via Let's Encrypt
