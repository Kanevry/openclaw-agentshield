# AgentBus — Product Requirements Document

## Elevator Pitch

> "Zapier fuer AI Agents. Event-Driven, Self-Hosted, Open-Source."

Open-Source Event-Routing Framework das AI Agents mit Real-World Events verbindet. Extrahiert aus einem Production-System mit 52 Handlern.

## Problem

AI Agents sind maechtig, aber isoliert. Sie reagieren auf User-Input, aber nicht auf Events aus der echten Welt (GitHub Push, CI Failure, Sentry Error, Cron Trigger). Bestehende Loesungen (Zapier, n8n) verbinden Services, aber nicht AI Agents.

## Loesung

```typescript
import { AgentBus } from 'agentbus';

const bus = new AgentBus();

bus.on('github.push', async (event) => {
  const review = await agent.analyze(event.payload.commits);
  await bus.emit('discord.message', { channel: '#dev', text: review });
});

bus.listen(3000);
```

### Core Components

1. **Event Router** — Glob Pattern Matching + Priority Queue
2. **Handler Registry** — Register/Unregister Handlers dynamisch
3. **Webhook Receiver** — GitHub, GitLab, Sentry, Generic (HMAC verified)
4. **Agent Toolkit** — Vercel AI SDK Wrapper mit Retry + Security
5. **Output Connectors** — Discord, Slack, HTTP Generic

### OpenClaw Integration

AgentBus als OpenClaw Plugin: Events von Messaging → AgentBus → Orchestrated Response

## Architektur

```
Webhooks (GitHub/GitLab/Sentry/...)
  |
  v
[AgentBus Router]
  |
  +-- Pattern Match: "github.push" --> Handler A (AI Code Review)
  +-- Pattern Match: "sentry.*"    --> Handler B (AI Error Analysis)
  +-- Pattern Match: "cron.*"      --> Handler C (Scheduled Tasks)
  |
  v
[AI Agent] (Vercel AI SDK / OpenClaw)
  |
  v
[Output] (Discord/Slack/HTTP/Email)
```

## Reusable Code (aus Clank Event Bus)

- Router: `src/router.ts` — Glob → Regex, Priority Queues
- Types: `src/types.ts` — NormalizedEvent, HandlerResult, HandlerContext
- BaseHandler: `src/handlers/base-handler.ts` — Dedup, Error Boundary
- HMAC: `src/webhook.ts` — GitHub, GitLab, Sentry Verification
- Circuit Breaker: `src/circuit-breaker.ts`
- Correlation: `src/correlation.ts` — Trace IDs

## Demo

1. Push Code zu GitHub Repo
2. AgentBus empfaengt Webhook
3. AI Agent reviewt den Diff
4. Review erscheint in Discord
5. Zeige Trace ID durch die gesamte Kette

## Risiken

- API-Design ist kritisch — schlechte API = schlechte Demo
- Scope Creep — 52 Handler reduzieren auf 3-4 Demo-wuerdige
- Weniger Cross-Track Potential als AgentShield
