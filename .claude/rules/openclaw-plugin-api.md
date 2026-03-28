---
description: OpenClaw Plugin SDK API reference — verified from source code (March 2026)
globs: ["src/**/*.ts", "snippets/**/*.ts"]
---

# OpenClaw Plugin API (VERIFIZIERT)

## Plugin Entry Point

Plain object export, NICHT `definePluginEntry`:

```typescript
export default {
  id: "agentshield",
  register(api: OpenClawPluginApi) {
    // Registration logic
  }
};
```

## Hooks (via api.on)

NICHT `api.registerHook` — verwende `api.on()`:

```typescript
// Eingehende Nachrichten scannen
api.on("message_received", (event, ctx) => {
  // event.messages: AgentMessage[]
  // return: void (modify event.messages in place)
});

// Tool-Calls abfangen/blocken
api.on("before_tool_call", (event, ctx) => {
  // event: { toolName: string, params: Record<string, unknown> }
  // return: { block?: boolean, blockReason?: string, params?: Record }
});

// Tool-Results scannen/modifizieren
api.on("tool_result_persist", (event, ctx) => {
  // event: { toolName?, toolCallId?, message: AgentMessage, isSynthetic? }
  // return: { message?: AgentMessage } | void
});

// Ausgehende Nachrichten scannen (Output Monitoring)
api.on("message_sending", (event, ctx) => {
  // event: { message: AgentMessage }
  // return: { cancel?: boolean } | void
});
```

## Tools (via api.registerTool)

```typescript
api.registerTool({
  name: "shield_scan",
  description: "Scan text for security threats",
  parameters: {
    text: { type: "string", description: "Text to scan" },
    context: { type: "string", enum: ["exec", "write", "read", "message", "general"] }
  }
}, { optional: true });
```

## HTTP Routes (via api.registerHttpRoute)

```typescript
api.registerHttpRoute({
  path: "/agentshield",
  auth: "gateway",       // REQUIRED: "gateway" | "plugin"
  match: "prefix",       // "exact" | "prefix" — prefix fuer catch-all
  handler: (req: IncomingMessage, res: ServerResponse) => {
    res.setHeader("Content-Type", "text/html");
    res.end(dashboardHtml);
  }
});
```

Note: Dashboard public machen via Caddy `request_header Authorization` injection,
da `auth: "gateway"` den Gateway-Token erfordert.

## Config

Plugin config aus `openclaw.plugin.json` configSchema wird automatisch geladen.
Zugriff via `ctx.config` im Hook-Callback.

```typescript
interface AgentShieldConfig {
  strictMode: boolean;
  allowedExecPatterns: string[];
  blockedDomains: string[];
  dashboard: boolean;
  rateLimit: number;       // Max tool calls per minute (default: 30)
  blockOutbound: boolean;  // Block outbound messages with detected threats (default: false)
}
```

## Constraints

- ESM: alle imports mit `.js` Extension
- TypeScript strict mode
- Kein `any` — `unknown` + Type Guards
- Plugin laeuft in-process (nicht sandboxed)
- Fehler im Plugin CRASHEN das Gateway (verifiziert!) — IMMER safeHandler() wrappen
- Pattern: `safeHandler(hookName, handler)` — fail-open, loggt Fehler, crasht nicht

## Best Practices (verifiziert 28.03.2026)

### Type Guards fuer Hook-Parameter
```typescript
function asString(val: unknown, fallback = ""): string
function asNumber(val: unknown, fallback: number): number
function asSeverity(val: unknown): FilterSeverity | undefined
function asScanContext(val: unknown): ScanContext | undefined
```
IMMER statt `as string` verwenden — Hook-Events liefern `Record<string, unknown>`.

### Outcome-Logik zentralisieren
```typescript
function getOutcome(detected, hook, strictMode?, blockOutbound?): "blocked" | "warned" | "allowed"
```
Blocking: before_tool_call + strictMode ODER message_sending + blockOutbound. Alle anderen warnen nur.

### Severity-Berechnung zentralisieren
```typescript
export function calcSeverity(matchCount: number, hasHighSeverity: boolean, baseLevel: "high" | "medium"): Severity
```
Einheitliche Severity ueber alle 5 Scan-Funktionen. baseLevel "high" fuer exec/sensitive, "medium" fuer injection/write/html-exfil.

### SSE Heartbeat fuer Dashboard
```typescript
const heartbeat = setInterval(() => res.write(`: heartbeat\n\n`), 15_000);
req.on("close", () => { clearInterval(heartbeat); unsubscribe(); });
```
Verhindert Proxy-Timeouts bei Caddy/Nginx.

### Rate Anomaly Detection
```typescript
// Sliding window counter for tool call frequency
const toolCallTimestamps: number[] = [];
function checkRateAnomaly(timestamps: number[], threshold: number, windowMs = 60_000)
```
Integriert am Anfang von before_tool_call — cheapest check first.

### New Scanner Functions (verifiziert)
```typescript
// Typoglycemia: scrambled middle letters
export function checkTypoglycemia(text: string): string[]

// Hex encoding: decode and scan
export function checkHexInjections(text: string): string[]

// HTML exfiltration: img/iframe/event handlers
export function scanForHtmlExfiltration(text: string): ScanResult
```

### DoS-Schutz in Scannern
`MAX_SCAN_LENGTH = 1_000_000` — Early-Return in allen Scan-Funktionen.
