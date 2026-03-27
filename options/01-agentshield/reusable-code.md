# AgentShield — Reusable Code Map

## Direkt kopierbar

### 1. security-scanner.ts (aus BitGN-Hackathron)

**Quelle:** `/Users/bernhardgoetzendorfer/Projects/BitGN-Hackathron/src/security.ts`
**LOC:** 234
**Adaptions-Aufwand:** Minimal

**Was es tut:**
- `scanForInjection(text)` — 16 Regex Patterns + base64 Decoding
- `validateEmailDomain(sender, contact)` — Domain Matching fuer Phishing
- `isUnsupportedFeature(text)` — Erkennt Requests fuer externe APIs
- `isTruncatedInstruction(text)` — Erkennt unvollstaendige Instruktionen

**Anpassungen noetig:**
- Neue Patterns fuer Tool Abuse (curl, rm, chmod) hinzufuegen
- Neue Patterns fuer Data Exfiltration hinzufuegen
- Return-Type erweitern um Severity Level
- Export als ESM

### 2. retry.ts (aus BitGN-Hackathron)

**Quelle:** `/Users/bernhardgoetzendorfer/Projects/BitGN-Hackathron/src/retry.ts`
**LOC:** 78
**Adaptions-Aufwand:** Keiner

**Was es tut:**
- `withRetry<T>(fn, opts)` — Generic Exponential Backoff
- `isTransientError(err)` — Klassifiziert Errors als transient/permanent
- Jitter: +-10% gegen Thundering Herd

**Nutzung:** Falls Dashboard HTTP-Calls macht oder externe APIs anspricht.

### 3. circuit-breaker.ts (aus Clank Event Bus)

**Quelle:** `/Users/bernhardgoetzendorfer/Projects/clank/services/event-bus/src/circuit-breaker.ts`
**LOC:** 266
**Adaptions-Aufwand:** Mittel (Prometheus-Imports strippen)

**Was es tut:**
- Circuit Breaker mit Open/Half-Open/Closed States
- Configurable Thresholds (failure count, timeout)
- Reset nach Recovery

**Anpassungen noetig:**
- Prometheus `createCounter`/`createGauge` Calls entfernen
- Standalone machen (keine Event Bus Dependencies)

**Nutzung:** Rate Anomaly Detection — wenn zu viele Tool Calls fehlschlagen, Circuit Breaker trippt.

## Als Referenz (nicht kopieren, Pattern uebernehmen)

### BitGN Agent Loop Pattern
- `src/agent.ts` — generateText() mit Tool Calling, Stagnation Detection, Message History
- **Pattern:** Bootstrap → Tool Loop → Security Scan → Context Prune

### BitGN SGR Prompts
- `src/prompts.ts` — Schema-Guided Reasoning, Outcome Decision Tree
- **Pattern:** STATE → PLAN → ACTION vor jedem Tool Call

### Clank HMAC Verification
- `services/event-bus/src/webhook.ts` — `verifyGitHubSignature()`, `verifySentrySignature()`
- **Pattern:** Raw Body Buffer, crypto.timingSafeEqual

### Clank BaseHandler
- `services/event-bus/src/handlers/base-handler.ts` — Dedup, Error Boundary, Metrics
- **Pattern:** canHandle() → handleEvent() → Dedup → Error Boundary
