# AgentShield — DevPost Submission

> Real-time security plugin for OpenClaw. Detects prompt injection, blocks dangerous tool calls, and streams everything to a live dashboard.

**Tracks:** AI Agents, Cybersecurity, OpenClaw Special Prize

**Links:**
- GitHub: https://github.com/Kanevry/openclaw-agentshield
- Live Dashboard: https://openclaw.gotzendorfer.at/agentshield
- Landing Page: https://agentshield.gotzendorfer.at

---

## What it does

OpenClaw has 337,000+ stars on GitHub. Its creator, Peter Steinberger, is now at OpenAI. Thousands of AI agents run on OpenClaw every day — coding assistants, DevOps bots, research agents. OpenClaw protects the infrastructure with Docker sandboxing, tool permissions, and SSRF protection. But its security policy states one thing explicitly: **prompt injection is out of scope**. There are four existing security tools in the ecosystem (ClawSec, SecureClaw, OpenClaw Shield, openclaw-security-monitor) — they audit, they report, they log. None of them block an attack in real-time.

AgentShield fills that gap. It is a native OpenClaw plugin that hooks into the full agent lifecycle through four hook points: `message_received` scans every inbound user message for injection patterns. `before_tool_call` analyzes commands before execution and actively blocks dangerous ones — data exfiltration, destructive commands, environment leaks. `tool_result_persist` scans file reads, web fetches, and API responses for indirect injection payloads hidden in content. `message_sending` monitors the agent's own responses for accidental system prompt leakage and sensitive data exposure. Install the plugin, and it protects every agent on the gateway — zero config.

Under the hood, AgentShield runs 108+ detection patterns across six categories: instruction overrides, identity manipulation, credential extraction, markup injection, jailbreaks, and data exfiltration. It decodes base64 and hex-encoded payloads, normalizes unicode, strips zero-width characters, and detects typoglycemia (scrambled-letter) evasion attacks — aligned with the OWASP LLM Prompt Injection Prevention Cheat Sheet. Every scan result streams in real-time to a live HTML dashboard via Server-Sent Events. The agent itself can call `shield_scan` and `shield_audit` as registered tools to proactively assess threats and query the audit log.

---

## How we built it

**Stack:** TypeScript (ESM, strict mode), Node.js 24, pnpm, OpenClaw Plugin SDK, Vitest, Tailwind CSS, Server-Sent Events.

We started with a battle-tested security scanner from a previous project (BitGN PAC Agent, which scored 20/20 on a security benchmark) and adapted it for the OpenClaw plugin architecture. The core approach was hook-based: rather than running as a passive skill that the user has to invoke, AgentShield registers lifecycle hooks that fire automatically on every message, every tool call, every result.

The plugin entry point is a plain object export with a `register(api)` method. We use `api.on()` for hooks and `api.registerHttpRoute()` for the dashboard. The scanner module is a pure function library — no side effects, no state, fully testable. The audit log uses an in-memory ring buffer (max 1000 entries) with an EventEmitter for SSE streaming.

The dashboard is a single HTML file with inline Tailwind CSS and vanilla JavaScript. No build step, no framework, no dependencies. It connects to the SSE endpoint and renders events in real-time with color-coded severity badges.

The demo runs on a Hetzner CX43 server with Caddy as reverse proxy (automatic TLS). Our demo agent "Atlas" runs on Discord, powered by Claude Opus 4.6.

---

## Challenges we ran into

**Telegram to Discord pivot.** We originally planned the demo agent on Telegram. Mid-hackathon, we discovered that the Discord integration was more reliable for live demos with screen sharing. We pivoted the entire demo infrastructure — new bot setup, new channel configuration, updated demo script. Stressful, but the right call.

**ReDoS in our own scanner.** During a self-audit, we found two regex patterns in the security scanner that were vulnerable to Regular Expression Denial of Service. A security tool with its own ReDoS vulnerabilities — not a great look. We rewrote the patterns to avoid catastrophic backtracking and added test cases to verify scan time stays under 10ms for adversarial inputs.

**XSS in our own dashboard.** The live dashboard renders scan results including matched patterns and tool parameters. During the security audit, we discovered we were injecting unsanitized content into the DOM. We fixed the XSS and added HTML entity escaping for all dynamic content. A security dashboard that is itself vulnerable to injection — the irony was not lost on us.

**CORS misconfiguration.** The SSE endpoint initially allowed `*` origins. Fine for a hackathon demo, but we tightened it to only allow the gateway origin because we practice what we preach.

**Plugin crashes crash the gateway.** We learned the hard way that OpenClaw plugins run in-process. An unhandled exception in a hook takes down the entire gateway. We built `safeHandler()` — a fail-open wrapper that catches errors, logs them, and lets the agent continue. A security tool that breaks your agent is worse than no security tool.

**The OpenClaw plugin API has no TypeScript types.** We wrote our own `openclaw.d.ts` type declarations from scratch by reading the source code. Every hook signature, every return type, verified against actual behavior.

---

## Accomplishments we're proud of

- **176 tests passing** — scanner corpus validation, audit log tests, hook integration tests, typoglycemia detection, hex encoding, HTML exfiltration, rate anomaly detection. TypeScript strict mode, zero `any` types.

- **OWASP LLM Prompt Injection Prevention alignment** — we implemented defenses from the OWASP cheat sheet that no other OpenClaw security tool covers: typoglycemia detection (scrambled-letter evasion), hex-encoded payload decoding, HTML exfiltration defense (detecting data theft via `<img>`, `<iframe>`, and HTML event handlers pointing to external domains).

- **108+ detection patterns** across six categories, with base64 and hex decoding as pre-processing layers. The scanner catches attacks that bypass simple string matching.

- **Fail-open design** — every hook is wrapped in `safeHandler()`. If the plugin encounters an error, the agent keeps working. Security should be a safety net, not a single point of failure.

- **Self-audited and fixed our own vulnerabilities** — XSS, CORS, ReDoS. We held ourselves to the same standard we apply to the agents we protect.

- **Real-time active blocking** — not just logging or auditing after the fact. The `before_tool_call` hook returns `{ block: true }` and the dangerous command never executes. This is what differentiates AgentShield from every other tool in the ecosystem.

- **41 attack corpus test cases** covering injection, exec abuse, write abuse, indirect injection, stealth attacks, and benign content (to verify we don't over-block).

---

## What we learned

- **OpenClaw's plugin system is powerful but underdocumented.** The hook-based architecture is elegant — `api.on("before_tool_call")` with a return value that can block execution is a great primitive. But there are no official TypeScript types, the error handling behavior (crash the gateway) is surprising, and the distinction between `api.on()` and `api.registerHook()` (the latter doesn't exist) cost us debugging time.

- **Hook-based security is fundamentally better than skill-based security.** A skill requires the user (or agent) to invoke it. A hook fires automatically on every lifecycle event. For security, the difference is everything — you cannot rely on an attacker to trigger the security check.

- **Base64 evasion is real and common.** Encoding `ignore all previous instructions` as base64 bypasses every tool that only does surface-level pattern matching. We decode and scan recursively.

- **Typoglycemia attacks are surprisingly effective.** "Ignroe prevoius instrctions" — scrambled middle letters — is readable to an LLM but invisible to exact-match scanners. Implementing fuzzy matching for known injection keywords was one of our best decisions.

- **Indirect injection is the hardest problem.** Scanning inbound messages is straightforward. Scanning tool results — file contents, web pages, API responses — for embedded instructions is where the real challenge lies. The attacker controls the content, and the agent is designed to follow instructions.

- **A security tool must secure itself.** Finding XSS in our own dashboard was a humbling reminder that security is a mindset, not a checklist.

---

## What's next

- **SQLite persistence** for the audit log — the in-memory ring buffer works for demos, but production deployments need durable storage and historical analysis.

- **LLM-based detection layer** — pattern matching is fast (sub-millisecond) but has limits. A lightweight LLM classifier running asynchronously on flagged content could catch novel attack patterns. The challenge is latency: the blocking hook needs to be fast, so the LLM layer would be advisory, not blocking.

- **OpenClaw core integration** — AgentShield's hook-based approach could be a model for native agent-level security in OpenClaw itself. We would love to contribute the architecture upstream.

- **Configurable policy engine** — let operators define custom rules: "block all exec calls between 2am and 6am", "require human approval for write operations on production files", "rate-limit tool calls per agent".

- **Community pattern library** — open-source the detection patterns as a shared resource. New attack techniques emerge constantly; a community-maintained pattern database would benefit the entire ecosystem.

---

## Built with

- TypeScript (ESM, strict mode)
- Node.js 24
- pnpm
- OpenClaw Plugin SDK
- Vitest (176 tests)
- Tailwind CSS (inline, no build step)
- Server-Sent Events (real-time dashboard)
- Caddy (reverse proxy, automatic TLS)
- Hetzner Cloud (CX43)
- Discord (demo agent channel)
- Claude Opus 4.6 (demo agent LLM)
