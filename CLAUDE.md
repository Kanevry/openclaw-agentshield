# OpenClaw Hack_001 — Claude Code Rules

## Context

24h Hackathon Projekt. Geschwindigkeit zaehlt, aber Code muss funktionieren.

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
      // Eingehende Nachrichten scannen
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

## Referenz-Dateien

- `research/` — Alle Hintergrund-Recherche
- `options/` — PRDs pro Option
- `snippets/` — Copy-paste-ready Code
- `snippets/openclaw-plugin-template/` — Minimales Plugin Scaffold

## Reusable Code (aus anderen Projekten)

| Snippet | Herkunft | Zweck |
|---------|----------|-------|
| `snippets/security-scanner.ts` | BitGN-Hackathron | 16+ Injection Patterns, base64 Decoding |
| `snippets/retry.ts` | BitGN-Hackathron | Exponential Backoff mit Jitter |
| `snippets/circuit-breaker.ts` | Clank Event Bus | Circuit Breaker (stripped) |
