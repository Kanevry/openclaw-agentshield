# Unser Server — Verifizierte Infrastruktur

Stand: 27. März 2026. Verifiziert via SSH.

## Server-Hardware

| Parameter | Wert | Verifiziert via |
|-----------|------|-----------------|
| IP | 46.224.162.185 | ssh clank@46.224.162.185 |
| Provider | Hetzner | Bekannt |
| OS | Ubuntu 24.04.4 LTS | `cat /etc/os-release` |
| RAM | 15.613 MB (6.393 MB frei) | `free -m` |
| Disk | 150 GB (119 GB frei, 18% belegt) | `df -h /` |
| Node.js | v22.22.1 | `node --version` |

## OpenClaw Installation

| Parameter | Wert | Verifiziert via |
|-----------|------|-----------------|
| Version | **2026.3.13** (61d171a) | `openclaw --version` |
| Binary | /usr/bin/openclaw | `which openclaw` |
| Gateway Port | 18789 (WebSocket, Loopback) | config/openclaw.json |
| Agents | 4 (clank, kalender, feedfoundry-designer, mentor) | config/openclaw.json |
| Messaging | Discord (8 Guilds), Telegram (Allowlist) | config/openclaw.json |
| Skills | 16+ aktiv | config/openclaw.json |
| Plugins | discord, telegram, llm-task | config/openclaw.json |

## Laufende Services (auf dem Server)

| Service | Port | Caddy Domain |
|---------|------|-------------|
| OpenClaw Gateway | 18789 | (loopback only) |
| Clank Event Bus | 18790 | events.gotzendorfer.at |
| FeedFoundry | 18793 | feedfoundry.gotzendorfer.at |
| GitLab CE | 10.0.0.3:80 | gitlab.gotzendorfer.at |
| Launchpad | 10.0.0.4:3100 | launchpad.gotzendorfer.at |
| n8n | 10.0.0.4:5678 | n8n.gotzendorfer.at |

## DNS Records (via Vercel)

| Subdomain | Typ | Ziel | Angelegt |
|-----------|-----|------|----------|
| agentshield.gotzendorfer.at | A | 46.224.162.185 | 27.03.2026 |
| events.gotzendorfer.at | A | 46.224.162.185 | bestehend |
| feedfoundry.gotzendorfer.at | A | 46.224.162.185 | bestehend |
| gitlab.gotzendorfer.at | A | 46.224.162.185 | bestehend |

## Wichtige Konfigurationsdateien

| Datei | Pfad (Server) | Pfad (Lokal/Git) |
|-------|---------------|-------------------|
| OpenClaw Config | /home/clank/clank/config/openclaw.json | clank/config/openclaw.json |
| Caddyfile | /etc/caddy/Caddyfile (oder Docker) | clank/config/Caddyfile |
| Clank SOUL.md | /home/clank/clank/workspace/SOUL.md | clank/workspace/SOUL.md |
| Kalender SOUL.md | /home/clank/clank/workspace/kalender/SOUL.md | clank/workspace/kalender/SOUL.md |
