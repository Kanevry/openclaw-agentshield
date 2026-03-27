# Projekt — Entscheidungen und Architektur

Stand: 27. März 2026.

## Getroffene Entscheidungen

| # | Entscheidung | Ergebnis | Entschieden am | Von |
|---|-------------|----------|---------------|-----|
| D1 | Welches Projekt? | AgentShield (Option A) mit bedingter MedGuard-Erweiterung bei H12 | 27.03.2026 | User |
| D2 | Solo oder Team? | Solo, aber mit parallelen Subagents für Dashboard etc. | 27.03.2026 | User |
| D3 | Mono-Package oder Monorepo? | Single Package | 27.03.2026 | Plan |
| D4 | Demo-Channel? | Discord | 27.03.2026 | User |
| D5 | Breadth oder Depth? | Breadth (alle 3 Hooks + Dashboard) | 27.03.2026 | Plan |
| D6 | Hosting? | Hackathon Server (188.245.81.195) | 27.03.2026 | User |
| D7 | Dashboard-Ansatz? | registerHttpRoute() innerhalb OpenClaw (NICHT Control UI Extension) | 27.03.2026 | Recherche |
| D8 | Agent-Architektur? | Single Agent (Atlas) + Plugin schützt alle | 27.03.2026 | User |
| D9 | Landing Page? | Next.js App auf Clank Server, Design-first via Pencil | 27.03.2026 | User |

## Naming

| Element | Name |
|---------|------|
| Plugin | AgentShield |
| Demo-Agent | Atlas |
| Dashboard | AgentShield Dashboard |
| Landing Page | agentshield.gotzendorfer.at |
| GitLab Repo | root/openclaw-agentshield |
| Plugin ID | agentshield |

## Repos

| Repo | Zweck | Sichtbarkeit |
|------|-------|-------------|
| `root/openclaw-agentshield` (GitLab) | Alles: Research + Code + Docs | Privat |
| GitHub (TBD) | Nur Plugin-Code nach Hackathon | Public (MIT) |

## Architektur-Entscheidungen

| Entscheidung | Grund |
|-------------|-------|
| Plugin statt Skill | Hooks (before_tool_call) nur in Plugins verfügbar, nicht in Skills |
| In-Memory Audit statt SQLite | Hackathon = 24h Laufzeit, Einfachheit > Persistenz |
| SSE statt WebSocket | registerHttpRoute unterstützt HTTP/SSE, kein direkter WS-Zugang |
| Tailwind CDN statt Build | Kein Build-Step, Single HTML File, maximale Einfachheit |
| Fail-Open bei Fehlern | Gateway-Crash vermeiden, lieber einen Angriff durchlassen als alles kaputt machen |
| try-catch in jedem Hook | Plugin-Exceptions crashen das Gateway (verifiziert via GitHub Issues) |

## Offene Entscheidungen

| # | Entscheidung | Wann | Default |
|---|-------------|------|---------|
| D10 | MedGuard ja/nein | H12 (ca. 04:30 Uhr) | Entscheidung nach Core-Status |
| D11 | CLI Interface | H16+ | Nur wenn Zeit |
| D12 | Live-Demo vs Pre-Recorded | H18 | Aim for Live, Record Backup |
| D13 | Welche Tracks submitten | Submission | Cybersecurity + AI Agent + OC Special |
| D14 | Landing Page Content/Design | Vor Implementation | Pencil Design-First |
