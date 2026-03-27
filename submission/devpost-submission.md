# DevPost Submission — AgentShield

## Project Name
AgentShield

## Tagline
Real-time AI agent security: prompt injection defense, tool call guardrails, and live audit dashboard for OpenClaw.

## Tracks
- AI Agents
- Cybersecurity
- OpenClaw Special

## Inspiration

OpenClaw (337K+ stars) protects infrastructure — Docker sandbox, tool allow/deny, SSRF protection. But prompt injection at the agent level is officially "out of scope." Existing tools like ClawSec, SecureClaw, and OpenClaw Shield audit and report. None of them actively block dangerous tool calls in real-time. None scan tool results for indirect injection. None provide a live dashboard.

We built AgentShield to fill exactly these gaps.

## What it does

AgentShield is a native OpenClaw plugin that intercepts and analyzes all agent activity across three hooks:

1. **Inbound message scanning** — Detects prompt injection, identity manipulation, credential extraction, and obfuscated payloads (base64, unicode) in user messages
2. **Tool call guardrails** — Analyzes exec, write, and browser commands for data exfiltration, destructive operations, and environment leaks. Blocks in strict mode.
3. **Indirect injection defense** — Scans tool results (file reads, web fetches, API responses) for embedded injection payloads

Plus a **real-time dashboard** with SSE streaming that shows every scan result live, and two **agent-callable tools** (shield_scan, shield_audit) so the agent can self-assess threats.

## How we built it

- **TypeScript** (ESM, strict mode) on **Node 24+**
- **OpenClaw Plugin SDK** — hooks (api.on), tools (api.registerTool), HTTP routes (api.registerHttpRoute)
- **Security scanner** with 20+ patterns, forked from our battle-tested BitGN agent (20/20 security benchmark)
- **Dashboard** built with Tailwind CSS (CDN), Server-Sent Events for live streaming
- **Fail-open error handling** — plugin errors never crash the gateway
- **Ring buffer audit log** (1000 entries) with severity filtering
- Deployed on Hetzner CX43 with Caddy reverse proxy and automatic TLS

## Challenges we ran into

- **Multi-bot Telegram conflict**: OpenClaw doesn't support multiple Telegram bots on one gateway. Attempting to add a second bot destroyed the polling offset. Pivoted to Discord.
- **Plugin auth for HTTP routes**: OpenClaw's gateway auth protects all routes including the dashboard. Solved with Caddy-level auth header injection for public dashboard access.
- **False positives**: Legitimate commands like `git push` match exfiltration patterns. Added glob-based allowlist (allowedExecPatterns) for safe commands.

## Accomplishments that we're proud of

- **33/33 security tests passing** — comprehensive attack corpus covering injection, exec, write, indirect, stealth, and benign scenarios
- **Real-time SSE dashboard** — no existing OpenClaw security tool has this
- **Active blocking via before_tool_call** — context-aware, not just pattern matching on tool names
- **Base64 + Unicode obfuscation detection** — decodes and scans hidden payloads
- **Zero-config deployment** — install the plugin, it protects all agents on the gateway

## What we learned

- OpenClaw's plugin system is powerful but sparsely documented. We verified every API call against the source code.
- Fail-open is the right default for security plugins — crashing the gateway is worse than missing one attack.
- Real-time visualization (SSE dashboard) dramatically improves the demo experience and makes security tangible.

## What's next for AgentShield

- **Configurable severity thresholds** per agent
- **Webhook notifications** (Slack, Discord) on critical threats
- **Persistent audit storage** with SQLite
- **MedGuard profile** — healthcare-specific compliance scanning (HIPAA, PHI detection)
- **Community pattern contributions** — open pattern library

## Built With
- TypeScript
- Node.js
- OpenClaw
- Tailwind CSS
- Server-Sent Events
- Caddy
- Hetzner Cloud

## Links

- **Live Dashboard**: https://openclaw.gotzendorfer.at/agentshield
- **Landing Page**: https://agentshield.gotzendorfer.at
- **GitHub**: https://github.com/Kanevry/openclaw-agentshield
- **Demo Video**: [TODO — YouTube/Loom link]
