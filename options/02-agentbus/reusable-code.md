# AgentBus — Reusable Code Map

## Aus Clank Event Bus

| Datei | Zweck | Adaptions-Aufwand |
|-------|-------|-------------------|
| `services/event-bus/src/router.ts` | Glob Pattern → Regex, Route Matching | Mittel — Event Bus spezifisches strippen |
| `services/event-bus/src/types.ts` | NormalizedEvent, HandlerResult, HandlerContext | Niedrig — Generische Typen |
| `services/event-bus/src/handler-registry.ts` | Handler Registration Pattern | Mittel |
| `services/event-bus/src/handlers/base-handler.ts` | BaseHandler (Dedup, Error Boundary) | Hoch — Vereinfachen |
| `services/event-bus/src/webhook.ts` | HMAC Verification (GitHub, GitLab, Sentry) | Niedrig |
| `services/event-bus/src/circuit-breaker.ts` | Circuit Breaker States | Mittel — Prometheus strippen |
| `services/event-bus/src/correlation.ts` | Trace ID, AsyncLocalStorage | Niedrig |

## Aus BitGN PAC Agent

| Datei | Zweck | Adaptions-Aufwand |
|-------|-------|-------------------|
| `src/agent.ts` | Agent Loop Pattern (Tool Calling) | Referenz |
| `src/security.ts` | Injection Scanner (fuer Agent Input Protection) | Niedrig |
| `src/retry.ts` | Exponential Backoff | Keiner |
