# OpenClaw Hack_001 — Claude Code Rules

## Context

24h Hackathon Projekt (27-28 Maerz 2026). Geschwindigkeit zaehlt, aber Code muss funktionieren.
Projekt: **AgentShield** — Real-time Security Monitoring Plugin fuer OpenClaw.
Demo-Agent: **Atlas** (Discord).
Server: 188.245.81.195 (openclaw-hackathron, Hetzner CX43).
Alter Server: 46.224.162.185 (Clank Gateway, NICHT fuer Hackathon-Demo).
GitLab: root/openclaw-agentshield

## Stack

- TypeScript (ESM, strict mode)
- Node 24+
- pnpm
- OpenClaw Plugin SDK (`openclaw/plugin-sdk`)

## Regeln

### Coding
- ESM: Alle Imports mit `.js` Extension
- Zod fuer Schema Validation
- Kein `any` — `unknown` + Type Guards
- Kein Code ohne Verifizierung (typecheck vor commit)

### OpenClaw Plugin API (VERIFIZIERT aus Source Code)

```typescript
// Plugin Entry — plain object export (NICHT definePluginEntry!)
export default {
  id: "plugin-id",
  register(api) {
    // Hooks via api.on() (NICHT api.registerHook!)
    api.on("before_tool_call", (event, ctx) => {
      // event: { toolName: string, params: Record<string, unknown> }
      // return: { block?: boolean, blockReason?: string, params?: Record }
    });

    api.on("tool_result_persist", (event, ctx) => {
      // event: { toolName?, toolCallId?, message: AgentMessage, isSynthetic? }
      // return: { message?: AgentMessage } | void
    });

    api.on("message_received", (event) => {
      // event: { from, content, timestamp, metadata }
      // NOT { messages: AgentMessage[] } — verified from gateway source
    });

    api.on("message_sending", (event, ctx) => {
      // event: { message: AgentMessage }
      // return: { cancel?: boolean } | void
    });

    // Tools registrieren
    api.registerTool(toolDefinition, { optional: true });

    // HTTP Routes fuer Dashboard
    api.registerHttpRoute({ path: "/my-route", handler: (req, res) => {} });
  }
};
```

### Hackathon-Spezifisch
- Schnell iterieren: bauen -> testen -> fixen -> weiter
- Kein Over-Engineering — MVP das funktioniert und beeindruckt
- Demo-Faehigkeit > Code-Schoenheit
- README frueh schreiben (klaert das Denken)

## Verifizierte Fakten (IMMER aktuell halten!)

- OpenClaw: **337K+ Stars** (Maerz 2026), Creator: Peter Steinberger (jetzt bei OpenAI)
- Prompt Injection: offiziell **out of scope** per OpenClaw Security Policy
- Konkurrenz existiert: ClawSec, OpenClaw Shield, SecureClaw, openclaw-security-monitor
- Unser Framing: "OWASP-aligned Real-time Blocking + Live Dashboard" (NICHT "erstes Security-Tool")
- 4 Hooks, 2 Tools, 4 Routes, 165+ Patterns, 391 Tests, 70 Corpus Cases, 16 Detection Techniques (9 ScanCategory values), 7 PII Patterns, Multilingual (EN+DE), OWASP LLM Prompt Injection Prevention + LLM05 Tool Risk Classification aligned

## Referenz-Dateien

- `research/` — Alle Hintergrund-Recherche (PRIVAT, nicht public)
- `research/competition-and-facts.md` — Verifizierte Fakten + Konkurrenz
- `options/` — PRDs pro Option (PRIVAT)
- `snippets/` — Copy-paste-ready Code
- `snippets/openclaw-plugin-template/` — Minimales Plugin Scaffold
- `docs/ARCHITECTURE.md` — End-to-End Architektur
- `docs/SOUL-atlas.md` — Demo-Agent Persona
- `.claude/rules/` — Token-effiziente Kontextrules

## Reusable Code (aus anderen Projekten)

| Snippet | Herkunft | Zweck |
|---------|----------|-------|
| `snippets/security-scanner.ts` | BitGN-Hackathron | Original Scanner (evolved to 165+ patterns in src/lib/scanner.ts) |
| `snippets/retry.ts` | BitGN-Hackathron | Exponential Backoff mit Jitter |
| `snippets/circuit-breaker.ts` | Clank Event Bus | Circuit Breaker (stripped) |
