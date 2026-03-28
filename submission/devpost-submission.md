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

AgentShield is a native OpenClaw plugin that intercepts and analyzes all agent activity across four hooks:

1. **Inbound message scanning** — Detects prompt injection, identity manipulation, credential extraction, and obfuscated payloads (base64, hex, unicode, ROT13, typoglycemia) in user messages
2. **Tool call guardrails** — Analyzes exec, write, and browser commands for data exfiltration, destructive operations, SSRF/internal-network access, path traversal, and environment leaks. Blocks in strict mode. Includes rate anomaly detection.
3. **Indirect injection defense** — Scans tool results (file reads, web fetches, API responses) for embedded injection payloads and markdown exfiltration attempts
4. **Output monitoring** — Scans outbound agent responses for HTML/markdown exfiltration, system prompt extraction, sensitive data leaks, and 22 API key/secret patterns (OpenAI, Anthropic, GCP, Stripe, and more). Last line of defense.

Plus a **real-time dashboard** with SSE streaming that shows every scan result live, and two **agent-callable tools** (shield_scan, shield_audit) so the agent can self-assess threats.

## How we built it

- **TypeScript** (ESM, strict mode) on **Node 24+**
- **OpenClaw Plugin SDK** — hooks (api.on), tools (api.registerTool), HTTP routes (api.registerHttpRoute)
- **Security scanner** with 130+ patterns across 14 categories (injection, exec abuse, write abuse, sensitive data, base64 decoding, typoglycemia, hex decoding, ROT13 obfuscation, HTML exfiltration, markdown exfiltration, system prompt extraction, SSRF/internal-network detection, path traversal, 22 API key/secret formats), forked from our battle-tested BitGN agent (20/20 security benchmark)
- **Dashboard** built with Tailwind CSS (CDN), Server-Sent Events for live streaming, CSP with frame-ancestors/base-uri/object-src restrictions, and 4 security headers (CSP, X-Content-Type-Options, X-Frame-Options, Referrer-Policy)
- **Fail-open error handling** — plugin errors never crash the gateway
- **Ring buffer audit log** (1000 entries) with severity filtering
- Deployed on Hetzner CX43 with Caddy reverse proxy and automatic TLS

## Challenges we ran into

- **Multi-bot Telegram conflict**: OpenClaw doesn't support multiple Telegram bots on one gateway. Attempting to add a second bot destroyed the polling offset. Pivoted to Discord.
- **Plugin auth for HTTP routes**: OpenClaw's gateway auth protects all routes including the dashboard. Solved with Caddy-level auth header injection for public dashboard access.
- **False positives**: Legitimate commands like `git push` match exfiltration patterns. Added glob-based allowlist (allowedExecPatterns) for safe commands.

## Accomplishments that we're proud of

- **340 tests passing** — comprehensive coverage across injection, exec, write, indirect, stealth, obfuscation, ROT13, markdown exfiltration, SSRF, path traversal, API key detection, and benign scenarios
- **Real-time SSE dashboard** — no existing OpenClaw security tool has this
- **Active blocking via before_tool_call** — context-aware, not just pattern matching on tool names
- **Multi-layer obfuscation detection** — base64, hex, unicode, ROT13, and typoglycemia decoding
- **Security audit hardened** — fixed XSS, CORS, ReDoS, regex injection; added CSP and 4 security headers
- **60 attack corpus cases** — real-world prompt injection payloads from OWASP and research papers
- **Full integration test coverage** with type-safe parameter validation
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
- OpenClaw Plugin SDK
- Zod
- Tailwind CSS
- Server-Sent Events
- Caddy
- Hetzner Cloud

## Links

- **Live Dashboard**: https://openclaw.gotzendorfer.at/agentshield
- **Landing Page**: https://agentshield.gotzendorfer.at
- **GitHub**: https://github.com/Kanevry/openclaw-agentshield
- **Demo Video**: [TODO — YouTube/Loom link]
