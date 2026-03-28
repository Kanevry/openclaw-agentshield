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
  // event: { from: string, content: string, timestamp: string, metadata: Record<string, unknown> }
  // NOT { messages: AgentMessage[] } — verified from gateway source
  // return: void
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
Einheitliche Severity ueber alle 9 Scan-Funktionen. baseLevel "high" fuer exec/sensitive/ssrf/path-traversal, "medium" fuer injection/write/html-exfil/markdown-exfil/rot13.

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

### New Scanner Functions (verifiziert Session E)
```typescript
// Typoglycemia: scrambled middle letters
export function checkTypoglycemia(text: string): string[]

// Hex encoding: decode and scan
export function checkHexInjections(text: string): string[]

// HTML exfiltration: img/iframe/event handlers
export function scanForHtmlExfiltration(text: string): ScanResult

// ROT13: decode and scan against obfuscation keywords
export function checkRot13Injections(text: string): string[]

// Markdown exfiltration: image/link data exfil in Markdown
export function scanForMarkdownExfiltration(text: string): ScanResult

// SSRF: internal IPs, cloud metadata, dangerous URL schemes
export function checkSsrfPatterns(url: string): ScanResult

// Path traversal: directory traversal, sensitive files, null bytes
export function scanForPathTraversal(path: string): ScanResult
```

### SSRF Integration in before_tool_call
`checkSsrfPatterns()` is integrated in the `before_tool_call` hook to scan URL parameters
in tool calls (e.g., web_fetch, curl). Blocks requests to internal IPs, cloud metadata
endpoints, and dangerous URL schemes. Works alongside `isBlockedUrl()` domain blocklist.

### Path Traversal Integration in before_tool_call
`scanForPathTraversal()` is integrated in the `before_tool_call` hook to scan file path
parameters (path, file_path, filename) for directory traversal, sensitive file access,
and null byte injection.

### Dashboard Error Isolation
All HTTP route handlers are wrapped in a top-level try/catch that:
- Logs errors to console
- Returns 500 "Internal Server Error" if headers not yet sent
- Prevents plugin crashes from taking down the gateway

### DoS-Schutz in Scannern
`MAX_SCAN_LENGTH = 1_000_000` — Early-Return in allen Scan-Funktionen.
