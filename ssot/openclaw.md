# OpenClaw — Verifizierte Plattform-Fakten

Stand: 27. März 2026.

## Identität

| Fakt | Wert | Quelle |
|------|------|--------|
| Name | OpenClaw | github.com/openclaw/openclaw |
| Typ | Self-hosted AI Agent Gateway | docs.openclaw.ai |
| Lizenz | MIT | github.com/openclaw/openclaw/blob/main/LICENSE |
| GitHub Stars | **337K+** (27. März 2026) | github.com/openclaw/openclaw, star-history.com |
| Stars am 2. März 2026 | 247.000 | medium.com/@aftab001x (Artikel vom 2.3.) |
| Stars am 3. März 2026 | 250.829 (React überholt) | openclaws.io/blog/openclaw-250k-stars-milestone |
| Stars am 24. März 2026 | 331.000+ | startupnews.fyi/2026/03/24 |
| Commits | 22.537+ | github.com/openclaw/openclaw |

## Creator

| Fakt | Wert | Quelle |
|------|------|--------|
| Name | Peter Steinberger | fortune.com/2026/02/19 |
| Herkunft | Österreich | fortune.com/2026/02/19 |
| Vorheriges Unternehmen | PSPDFKit (gegründet 2011, neunstelliger Exit 2024) | fortune.com/2026/02/19 |
| Entstehung | "was annoyed that it didn't exist, so I just prompted it into existence" | fortune.com/2026/02/19 |
| Namenshistorie | Clawdbot (Nov 2025) → Moltbot (27. Jan 2026) → OpenClaw (30. Jan 2026) | fortune.com/2026/02/19 |
| Aktueller Status | Bei OpenAI seit Feb 2026 | techcrunch.com/2026/02/15 |
| Sam Altman Zitat | "He is a genius with a lot of amazing ideas about the future of very smart agents" | x.com/sama/status/2023150230905159801 |

## Architektur

| Fakt | Wert | Quelle |
|------|------|--------|
| Gateway Protokoll | WebSocket auf 127.0.0.1:18789 | docs.openclaw.ai/gateway |
| Auth | Token-basiert (OPENCLAW_GATEWAY_TOKEN) | docs.openclaw.ai/gateway/security |
| Messaging Channels | 22+ (WhatsApp, Telegram, Discord, Slack, Signal, iMessage, ...) | docs.openclaw.ai |
| Plugin System | In-process via jiti, TypeScript/JavaScript, npm packages | docs.openclaw.ai/tools/plugin |
| Skills | SKILL.md Files, installierbar via ClawHub | docs.openclaw.ai/skills |
| Built-in Tools | 18+ (exec, bash, read, write, edit, web_search, web_fetch, browser, ...) | docs.openclaw.ai/tools |

## Security Policy

| Fakt | Wert | Quelle |
|------|------|--------|
| Prompt Injection | **Offiziell "out of scope"** | github.com/openclaw/openclaw/security |
| Zitat | "frequently reported but typically closed with no code change" | github.com/openclaw/openclaw/security |
| Trust Model | Single-operator, nicht adversarial multi-tenant | github.com/openclaw/openclaw/security |
| Infrastructure Security | Exec Approval, Tool Allow/Deny, Docker Sandbox, SSRF Protection | docs.openclaw.ai/gateway/security |
| DM Pairing | Challenge-Nonce für unbekannte Absender (Telegram/WhatsApp) | docs.openclaw.ai/gateway/security |

## Bekannte Sicherheitslücken

| Issue | Beschreibung | Status | Quelle |
|-------|-------------|--------|--------|
| #30111 | Fake [System Message] Blocks in WhatsApp | Offen | github.com/openclaw/openclaw/issues/30111 |
| #30448 | Circulating Prompt Injection Payloads (Reddit/Discord) | Aktiv | github.com/openclaw/openclaw/issues/30448 |
| #22060 | Indirect Injection via URL Previews | Ungelöst | github.com/openclaw/openclaw/issues/22060 |
| N/A | SSH Key Exfiltration via crafted email/webpage | Dokumentiert | giskard.ai/knowledge/openclaw-security-vulnerabilities |
| N/A | SOUL.md Persistence Attacks (durable behavioral changes) | Dokumentiert | penligent.ai/hackinglabs/the-openclaw-prompt-injection-problem |

## Plugin System (technisch)

| Fakt | Wert | Quelle |
|------|------|--------|
| Ausführung | In-process, NICHT sandboxed | docs.openclaw.ai/tools/plugin |
| Laufzeit | jiti (TypeScript/JavaScript JIT compilation) | github.com/openclaw/openclaw source |
| Hooks | api.on("before_tool_call"), api.on("tool_result_persist"), api.on("message_received"), api.on("message_sending") | docs.openclaw.ai/tools/plugin, CLAUDE.md (verifiziert) |
| Tools | api.registerTool() | docs.openclaw.ai/tools/plugin |
| HTTP Routes | api.registerHttpRoute() | docs.openclaw.ai/tools/plugin |
| Control UI erweiterbar? | **NEIN** — Plugins können keine Tabs/Panels hinzufügen | Recherche 27.03. (kein offizieller Endpoint) |
| Exception Handling | Keine Isolation — Unhandled Exception crasht Gateway | github.com/openclaw/openclaw/issues/54790, #53247, #54931 |
| Hook Blocking | Synchron im Request-Path, kein Timeout | github.com/openclaw/openclaw/issues/36412 |
| Version Pinning | Plugins für spezifische OpenClaw-Versionen | docs.openclaw.ai/tools/plugin |
