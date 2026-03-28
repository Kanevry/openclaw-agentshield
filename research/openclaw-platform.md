# OpenClaw Platform — Recherche

> Stand: 27.03.2026, verifiziert gegen Source Code + offizielle Docs

## Was ist OpenClaw?

Self-hosted AI Agent Gateway. Verbindet Messaging-Apps (WhatsApp, Telegram, Discord, Slack, Signal, iMessage, etc.) mit AI Coding Agents (Pi Agent). MIT-lizenziert, 337K+ GitHub Stars.

- **Erstellt von:** Peter Steinberger (PSPDFKit Gruender)
- **Core:** WebSocket Gateway Daemon (`openclaw gateway`)
- **Interface:** Messaging-Apps als UI (kein Terminal/IDE noetig)
- **Lokal:** Laeuft auf deinem Geraet, keine Cloud-Abhaengigkeit
- **Version:** 2026.3.x (aktiv entwickelt)

## Architektur

```
Messaging Channels (WhatsApp/Telegram/Discord/...)
           |
           v
+-------------------------------------------+
|         Gateway (ws://127.0.0.1:18789)    |
|                                           |
|  - WebSocket Control Plane                |
|  - Session Manager                        |
|  - Channel Routers                        |
|  - Memory System (local + vector DB)      |
|  - Hook System (event-driven)             |
|  - Skill/Plugin Loader                    |
+-------------------------------------------+
           |
   +-------+-------+--------+----------+
   |       |       |        |          |
   v       v       v        v          v
Pi Agent  CLI   macOS App  iOS Node  Android
(RPC)                      (Canvas)
```

## Plugin SDK (VERIFIZIERT)

### Entry Point

```typescript
// Korrekt: Plain object export
export default {
  id: "my-plugin",
  register(api: OpenClawPluginApi) {
    // registrations here
  }
};

// FALSCH: definePluginEntry existiert NICHT
```

### Registration Methods

| Method | Zweck |
|--------|-------|
| `api.registerTool(tool, opts?)` | Agent-callable Functions |
| `api.registerHttpRoute({ path, handler })` | HTTP Endpoints auf Gateway |
| `api.registerProvider(...)` | LLM Model Provider |
| `api.registerChannel(...)` | Messaging Platform |
| `api.registerSpeechProvider(...)` | TTS/STT |
| `api.registerCommand(...)` | CLI Commands |
| `api.registerService(...)` | Background Services |
| `api.on(event, handler)` | Lifecycle Hooks |

### Hook System (via `api.on()`)

**WICHTIG:** `api.registerHook()` ist veraltet. Nutze `api.on()`.

| Hook | Event-Daten | Return | Semantik |
|------|-------------|--------|----------|
| `before_tool_call` | `{ toolName, params }` | `{ block?, blockReason?, params? }` | `block: true` = Tool Call verhindern |
| `tool_result_persist` | `{ toolName?, toolCallId?, message, isSynthetic? }` | `{ message? }` | Tool-Ergebnis vor Persistierung modifizieren |
| `message_received` | `{ from?, content?, ... }` | void | Eingehende Nachricht verarbeiten |
| `message_sending` | `{ ... }` | `{ cancel?: true }` | `cancel: true` = Nachricht nicht senden |
| `message_sent` | `{ success? }` | void | Bestaetigung |

### Tool Registration

```typescript
api.registerTool({
  name: "my_tool",
  description: "Does a thing",
  parameters: Type.Object({ input: Type.String() }),
  async execute(_id, params) {
    return { content: [{ type: "text", text: params.input }] };
  },
}, { optional: true });  // optional = User muss explizit erlauben
```

### HTTP Routes

```typescript
api.registerHttpRoute({
  path: "/my-endpoint",
  handler: async (req: IncomingMessage, res: ServerResponse) => {
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ status: "ok" }));
  }
});
```

### Plugin Manifest (`openclaw.plugin.json`)

```json
{
  "id": "my-plugin",
  "name": "My Plugin",
  "description": "What it does",
  "configSchema": {
    "type": "object",
    "properties": {
      "myOption": { "type": "boolean", "default": true }
    }
  }
}
```

### `package.json` Felder

```json
{
  "name": "@myorg/openclaw-my-plugin",
  "type": "module",
  "openclaw": {
    "extensions": ["./src/index.ts"],
    "hooks": ["./hooks/my-hook"]
  }
}
```

## Built-in Tools

| Tool | Zweck |
|------|-------|
| `exec` / `process` | Shell Commands, Background Processes |
| `browser` | Chromium Control (navigate, click, screenshot) |
| `read` / `write` / `edit` | Dateisystem |
| `web_search` / `web_fetch` | Web-Recherche |
| `message` | Cross-Channel Messaging |
| `canvas` | Visual UI (A2UI) |
| `nodes` | Camera, Screen Record, Location |
| `cron` / `gateway` | Scheduling, Gateway Control |
| `sessions_*` / `agents_list` | Multi-Agent Management |
| `memory_search` / `memory_get` | Agent Memory |

## Tool Groups

- `group:runtime` -> exec, bash, process
- `group:fs` -> read, write, edit, apply_patch
- `group:web` -> web_search, web_fetch
- `group:ui` -> browser, canvas
- `group:sessions` -> Session Tools
- `group:memory` -> Memory Tools
- `group:openclaw` -> Alle Built-in Tools

## Skills (SKILL.md Format)

```yaml
---
name: my_skill
description: "One-line description"
metadata:
  openclaw:
    requires:
      bins: ["node"]
      env: ["API_KEY"]
    os: ["darwin", "linux"]
---
# Skill Instructions (Markdown)
```

Laden aus: Workspace > Managed > Bundled > Plugin

## Sandboxing

- Docker-basiert, optional
- Modes: off, non-main, all
- Scope: session, agent, shared
- Workspace Access: none, ro, rw
- `tools.elevated` = Escape Hatch (exec auf Host)

## Installation

```bash
npm install -g openclaw@latest
openclaw onboard --install-daemon
# Plugin installieren:
openclaw plugins install @myorg/my-plugin
```

## Unsere Nutzung

Clank nutzt OpenClaw mit 4 Agents in Produktion:
1. **clank** — Hauptagent, Claude Sonnet, Discord, voller Tool-Zugriff
2. **kalender** (Sepp) — Haiku, Telegram, nur exec
3. **feedfoundry-designer** (DropBot) — Haiku, File-basiert
4. **mentor** — Sonnet, Read-Only DB + Memory

Config: `/Users/bernhardgoetzendorfer/Projects/clank/config/openclaw.json`
