# Existierende Assets fuer den Hackathon

## 1. BitGN PAC Agent (100% Score, 20/20 Tasks)

**Pfad:** `/Users/bernhardgoetzendorfer/Projects/BitGN-Hackathron/`
**Stack:** TypeScript, Vercel AI SDK v6, Claude, Zod, ConnectRPC
**Kosten:** ~$6.55 total API

### Wiederverwendbare Module

| Datei | LOC | Zweck | Adaptions-Aufwand |
|-------|-----|-------|-------------------|
| `src/security.ts` | 234 | 16 Injection Patterns + base64 + Phishing + Feature Detection | Niedrig — direkt kopierbar |
| `src/retry.ts` | 78 | Exponential Backoff + Jitter + Transient Error Detection | Minimal |
| `src/messages.ts` | 81 | Message Pruning, Token Estimation | Minimal |
| `src/schema.ts` | 120 | 11 Zod Tool Schemas | Mittel — muss an OpenClaw Tools angepasst werden |
| `src/prompts.ts` | 88 | SGR System Prompt, Outcome Decision Tree | Hoch — hackathon-spezifisch |
| `src/formatters.ts` | 126 | Shell-like Output Formatting | Optional |
| `src/agent.ts` | 200 | Core Agent Loop mit Tool Calling | Referenz, nicht kopieren |

### Key Patterns

1. **Schema-Guided Reasoning (SGR):** `STATE: → PLAN: → ACTION:` vor jedem Tool Call
2. **Outcome Decision Tree:** Priority-ordered Entscheidungsbaum (Security > Clarification > Unsupported > OK)
3. **Defense-in-Depth:** Prompt Layer + Code Layer + Post-Read Scanning
4. **One-Shot Examples > Instructions:** Ein Beispiel > 10 Zeilen Regeln

### Lessons Learned

- `claude-sonnet-4-6` (ohne Datum-Suffix) ist die korrekte Model ID
- `generateText()` mit native tool calling > `generateObject()` fuer Claude
- Post-Read Security Scanning ist effektiver als Pre-Read Blocking
- Iterative Failure Analysis: Run → Analyze → Categorize → Fix → Re-run

## 2. Clank Event Bus (52 Handler, Produktion)

**Pfad:** `/Users/bernhardgoetzendorfer/Projects/clank/services/event-bus/`
**Stack:** TypeScript, Express, SQLite, Prometheus, Docker

### Wiederverwendbare Module

| Datei | LOC | Zweck | Adaptions-Aufwand |
|-------|-----|-------|-------------------|
| `src/circuit-breaker.ts` | 266 | Circuit Breaker mit States + Metrics | Mittel — Prometheus strippen |
| `src/webhook.ts` | ~150 | HMAC Verification (GitHub, GitLab, Sentry) | Niedrig |
| `src/handlers/base-handler.ts` | ~300 | BaseHandler Pattern (Dedup, Error Boundary) | Hoch — zu komplex fuer Hackathon |
| `src/correlation.ts` | ~80 | Trace ID Generation, AsyncLocalStorage | Optional |

### Key Patterns

- **Event Routing:** Glob Pattern Matching + Priority Queue
- **Handler Registration:** Handler-Registry mit canHandle() Pattern
- **Dedup:** In-Memory Map + SQLite Persistence
- **Circuit Breaker:** Open/Half-Open/Closed States
- **HMAC:** Raw Body Buffer Verification (NICHT JSON.stringify!)

## 3. OpenClaw (4 Agents in Produktion)

**Pfad:** `/Users/bernhardgoetzendorfer/Projects/openclaw/openclaw/`
**Config:** `/Users/bernhardgoetzendorfer/Projects/clank/config/openclaw.json`

### Was wir davon nutzen koennen

- **Plugin-Architektur Verstaendnis:** Wir kennen die Plugin SDK aus der Praxis
- **Multi-Agent Config:** 4 Agents mit unterschiedlichen Berechtigungen
- **Real-World Use Cases:** CI/CD Automation, Email Triage, Calendar, Mentoring
- **Skills-System:** 20+ Skills in Produktion

## 4. ActionGuard (Konzept, kein Code)

**Status:** Idee-Phase, kein funktionierender Code
**Konzept:** Security Middleware fuer Next.js Server Actions
**Nutzen:** Konzeptuelle Inspiration fuer AgentShield, aber kein wiederverwendbarer Code

## 5. AgentBus (Konzept, kein Code)

**Status:** Idee-Phase, kein funktionierender Code
**Konzept:** Event-Routing Framework (Productized Clank Event Bus)
**Nutzen:** Option 2 wuerde dieses Konzept umsetzen

## 6. projects-baseline (Templates)

**Pfad:** `/Users/bernhardgoetzendorfer/Projects/projects-baseline/`

### Nuetzlich fuer den Hackathon

- ESLint v9 flat config (`@goetzendorfer/eslint-config`)
- Prettier config (`@goetzendorfer/prettier-config`)
- tsconfig.json Templates
- Express-Service Template Patterns

## 7. ai-gateway (Multi-Provider LLM Proxy)

**Pfad:** `/Users/bernhardgoetzendorfer/Projects/ai-gateway/`
**Stack:** Express 5, TypeScript, Helmet, Rate-Limiting, Zod

### Wiederverwendbar

- Request/Response Translation Patterns (OpenAI <-> Anthropic)
- Middleware Patterns (Auth, Rate-Limit, Error Handler)
- Schema Definitions (19 Schemas)

## Zusammenfassung: Was kopieren?

### Direkt kopieren (Snippets-Ordner):
1. `security.ts` aus BitGN — Injection Detection
2. `retry.ts` aus BitGN — Backoff
3. `circuit-breaker.ts` aus Clank — stripped

### Als Referenz nutzen (nicht kopieren):
- BitGN `agent.ts` — Agent Loop Pattern
- BitGN `prompts.ts` — SGR + Decision Tree
- Clank `webhook.ts` — HMAC Pattern
- Clank `base-handler.ts` — Handler Pattern
- ai-gateway Middleware — Auth/Rate-Limit
