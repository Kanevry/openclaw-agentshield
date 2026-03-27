---
description: Hackathon context, verified facts, and strategic constraints for OpenClaw Hack_001
globs: ["**/*"]
---

# Hackathon Context

## Event
- OpenClaw Hack_001, Wien, 27-28 Maerz 2026, 24h
- 3 Tracks: AI Agents, Cybersecurity, Bio & Healthcare
- Prize Pool: EUR 4.150+, Grand Prize: SF Residency

## Verified Facts (Stand: 27. Maerz 2026)
- OpenClaw: 337K+ GitHub Stars (NICHT 247K — das war Anfang Maerz)
- Creator: Peter Steinberger (PSPDFKit) — jetzt bei OpenAI (seit Feb 2026)
- Prompt Injection: offiziell "out of scope" per OpenClaw Security Policy
- Plugin System: verifiziert, in-process via jiti, Hook-basiert

## Existierende Konkurrenz (MUSS beruecksichtigt werden!)
- ClawSec (prompt-security): SOUL.md Drift Detection, Skill Integrity
- OpenClaw Shield (knostic): Secret Leak Prevention, PII
- SecureClaw (adversa-ai): 56 Audit Checks, OWASP-aligned
- openclaw-security-monitor (adibirzu): ClawHavoc, Memory Poisoning

## Unsere Differenzierung
- Real-time Dashboard mit SSE Live Events (keiner hat das)
- Hook-basiert: aktives Blocking (before_tool_call), nicht nur Logging
- Base64 + Unicode Obfuscation Detection
- Battle-tested Scanner aus BitGN (20/20 Score)

## Naming
- Plugin: AgentShield
- Demo-Agent: Atlas
- Dashboard: AgentShield Dashboard

## Server
- Demo Host: 188.245.81.195 (openclaw-hackathron, Hetzner CX43)
- OpenClaw 2026.3.24, Node 24.13.0, pnpm 10.33.0
- Agent: Atlas (Discord, claude-opus-4-6)
- Caddy Reverse Proxy, TLS automatisch
- Dashboard: openclaw.gotzendorfer.at/agentshield (public via Caddy auth injection)
- Landing Page: agentshield.gotzendorfer.at (static HTML, /var/www/agentshield/)
- GitHub Mirror: github.com/Kanevry/openclaw-agentshield (public)
- Alter Server (46.224.162.185): Clank Gateway, NICHT fuer Hackathon-Demo

## NICHT behaupten
- "Erstes Security-Tool fuer OpenClaw" (FALSCH — es gibt 4+)
- "247K Stars" (veraltet — aktuell 337K+)
- "OpenClaw hat keine Security" (teilweise — hat Infra-Security, kein Agent-Level)
