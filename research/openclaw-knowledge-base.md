# OpenClaw Knowledge Base

> Gesammelt von docs.openclaw.ai + Source Code, Stand 27.03.2026

## Inhaltsverzeichnis

1. [Gateway Architektur](#gateway-architektur)
2. [Memory System](#memory-system)
3. [Multi-Agent Routing](#multi-agent-routing)
4. [Browser Tool](#browser-tool)
5. [Plugin SDK](#plugin-sdk) (siehe research/openclaw-platform.md)
6. [Security](#security) (siehe research/openclaw-security-gaps.md)

---

## Gateway Architektur

### Design

Single long-lived Gateway Daemon. Managed alle Messaging-Plattformen.

- WebSocket API auf `127.0.0.1:18789`
- Typed Frame Exchange: `{type:"req", id, method, params}` -> `{type:"res", id, ok, payload|error}`
- Server-Push Events mit Schema Versioning
- Token-Auth via `OPENCLAW_GATEWAY_TOKEN`

### Client-Typen

| Client | Verbindung |
|--------|-----------|
| Control-Plane (macOS App, CLI, Web UI) | Default WS auf 127.0.0.1:18789 |
| Nodes (macOS/iOS/Android/Headless) | WS mit `role: node`, deklarieren Capabilities |
| WebChat | Statische UI, gleiche WS API |

### Device Trust

- Device Identity im Connection Handshake
- Challenge-Nonce Signatures (v3 Payload bindet Platform + deviceFamily)
- Approval Workflow; lokale Connections = Auto-Approve
- Device Tokens fuer Reconnections

### Domain Events

Gateway emitted: agent, chat, presence, health, heartbeat, cron Events.

---

## Memory System

### Zwei Layer

**Daily Logs** (`memory/YYYY-MM-DD.md`):
- Append-only Files pro Tag
- System laedt heute + gestern beim Session-Start
- Captures: Notes, Running Context

**Long-term Memory** (`MEMORY.md`):
- Kuratierter Speicher fuer Entscheidungen, Preferences, Facts
- Laedt nur in primaeren Sessions (nie in Gruppen)
- Deduplizierung via realpath wenn `MEMORY.md` und `memory.md` existieren

### Memory Tools

- `memory_search` — Semantische Suche ueber indexierte Markdown-Snippets
- `memory_get` — Gezieltes File/Line-Range Lesen, graceful degradation

### Automatic Memory Preservation

Vor Context Compaction: Stiller Agentic Turn erinnert Model an Memory Persistence.
Config: `agents.defaults.compaction.memoryFlush`
- Soft Threshold: Default 4,000 Tokens
- Custom Prompts moeglich
- Respektiert Sandbox Restrictions (ro/none)

### Vector Search

Hybrid Search: BM25 (Text) + Vector (Semantic)
- Adapter: OpenAI, Gemini, Voyage, Mistral, Ollama, lokale GGUF
- MMR Diversity Re-Ranking
- Temporal Decay
- QMD Sidecar Backend optional

---

## Multi-Agent Routing

### Agent = Isolierte Persona

Jeder Agent hat:
- **Workspace:** `SOUL.md`, `AGENTS.md`, `USER.md`, Persona Rules
- **State Dir:** `~/.openclaw/agents/<agentId>/` (Auth, Model Registry, Config)
- **Session Store:** `~/.openclaw/agents/<agentId>/sessions/`

### Config unter `agents.list`

| Property | Zweck |
|----------|-------|
| `id` | Unique Identifier |
| `workspace` | Working Directory |
| `agentDir` | State Directory |
| `model` | LLM Model |
| `default` | Fallback Agent Flag |
| `identity` | Name + Display |

### Routing via Bindings

Match: `{ channel, accountId, peer, guildId, teamId, roles }`

Prioritaet (most-specific wins):
1. Peer Match (exakte DM/Group/Channel ID)
2. Parent Peer Match (Thread Inheritance)
3. Guild ID + Roles (Discord)
4. Guild ID oder Team ID
5. Account ID
6. Channel-wide
7. Fallback auf Default Agent

### Per-Agent Sandboxing

```json
{
  "agents.list[].sandbox": {
    "mode": "all",
    "scope": "agent",
    "docker": { "setupCommand": "..." }
  }
}
```

Per-Agent Tool Restrictions: `tools.allow`, `tools.deny`

### Use Cases

- Channel-basiertes Routing: WhatsApp -> Fast Agent, Telegram -> Opus
- Peer-spezifisch: Kanal auf Standard, ein DM auf Premium
- Gruppen-Binding: Familie -> dedizierter Agent mit Mention-Gating
- DM Splitting: Verschiedene DMs -> verschiedene Agents

---

## Browser Tool

### Capabilities

- **Profile Management:** `openclaw` (isoliert) oder `user` (existierende Chrome Session)
- **Actions:** Navigate, Click, Type, Drag, Select, Hover, Scroll
- **Inspection:** Screenshots (full-page/element), Snapshots (AI refs/role refs)
- **State:** Cookies, Storage, Offline Mode, Headers, Credentials, Geo, Timezone
- **Advanced:** PDF Export, Downloads, Trace Recording

### Snapshot Refs

- AI Snapshots: Numerische Refs (`ref=12`)
- Role Snapshots: Role-based Refs (`ref=e12`)
- Deterministisch, keine fragilen CSS Selectors

### SSRF Protection

- Default: Trusted-Network Mode (private IPs erlaubt)
- Strict: `dangerouslyAllowPrivateNetwork: false`
- Hostname Allowlisting: `hostnameAllowlist` / `allowedHostnames`
- Pre-Navigation + Post-Navigation Check

### Evaluation Security

- `browser act kind=evaluate` fuehrt JavaScript im Page Context aus
- **Risiko:** Prompt Injection via evaluiertem Content
- **Mitigation:** `browser.evaluateEnabled=false` deaktiviert Evaluation komplett

---

## Weitere Docs-Seiten (nicht gescraped, URLs bekannt)

| Thema | URL |
|-------|-----|
| Getting Started | docs.openclaw.ai/getting-started |
| Channels (40+) | docs.openclaw.ai/channels/* |
| CLI Reference (70+) | docs.openclaw.ai/cli/* |
| Model Providers (50+) | docs.openclaw.ai/providers/* |
| Deployment | docs.openclaw.ai/installation/* |
| Gateway Config | docs.openclaw.ai/gateway/configuration |
| Cron/Webhooks | docs.openclaw.ai/automation/* |
| Canvas/A2UI | docs.openclaw.ai/tools/canvas |

Falls beim Hackathon mehr Details noetig: `docs.openclaw.ai/llms.txt` hat den vollen Index.
