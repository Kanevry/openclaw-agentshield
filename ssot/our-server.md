# Unser Server — Verifizierte Infrastruktur

Stand: 28. März 2026. Verifiziert via SSH.

## Server-Hardware

| Parameter | Wert | Verifiziert via |
|-----------|------|-----------------|
| IP | 188.245.81.195 | ssh root@188.245.81.195 |
| Hostname | openclaw-hackathron | Hetzner CX43 |
| Provider | Hetzner | Bekannt |
| OS | Ubuntu 24.04.4 LTS | `cat /etc/os-release` |
| RAM | 15.613 MB (6.393 MB frei) | `free -m` |
| Disk | 150 GB (119 GB frei, 18% belegt) | `df -h /` |
| Node.js | v24.13.0 | `node --version` |

## OpenClaw Installation

| Parameter | Wert | Verifiziert via |
|-----------|------|-----------------|
| Version | **2026.3.24** | `openclaw --version` |
| Binary | /usr/bin/openclaw | `which openclaw` |
| Gateway Port | 18789 (WebSocket, Loopback) | config/openclaw.json |
| Agents | Atlas (Discord, claude-opus-4-6) | config/openclaw.json |
| Messaging | Discord | config/openclaw.json |
| Plugin Path | /opt/openclaw-agentshield | git clone + git pull |
| Plugins | discord, agentshield | config/openclaw.json |
| Gateway | Laeuft als Prozess (nicht systemd) | — |

## Laufende Services (auf dem Hackathon-Server 188.245.81.195)

| Service | Port | Caddy Domain |
|---------|------|-------------|
| OpenClaw Gateway | 18789 | (loopback only) |
| AgentShield Dashboard | (via Gateway) | openclaw.gotzendorfer.at/agentshield |
| Caddy Reverse Proxy | 443 | TLS automatisch |

## Alter Server (46.224.162.185) — Clank Gateway

> **NICHT der Hackathon-Demo-Server.** Das ist der bestehende Clank Gateway Server
> mit den produktiven Agents (clank, kalender, feedfoundry-designer, mentor).

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
| agentshield.gotzendorfer.at | A | 188.245.81.195 | 28.03.2026 |
| openclaw.gotzendorfer.at | A | 188.245.81.195 | 28.03.2026 |
| events.gotzendorfer.at | A | 46.224.162.185 | bestehend (alter Server) |
| feedfoundry.gotzendorfer.at | A | 46.224.162.185 | bestehend (alter Server) |
| gitlab.gotzendorfer.at | A | 46.224.162.185 | bestehend (alter Server) |

## Wichtige Konfigurationsdateien (Hackathon-Server)

| Datei | Pfad (Server) |
|-------|---------------|
| AgentShield Plugin | /opt/openclaw-agentshield |
| OpenClaw Config | (TBD) |
| Caddyfile | /etc/caddy/Caddyfile |
| Atlas SOUL.md | (im OpenClaw workspace) |

## Deployment

| Parameter | Wert |
|-----------|------|
| Methode | `git clone` + `git pull` (NICHT rsync) |
| Plugin Pfad | /opt/openclaw-agentshield |
| GitHub Mirror | github.com/Kanevry/openclaw-agentshield |
| GitLab | root/openclaw-agentshield (auf 46.224.162.185) |
