# Plugin System Reliability Assessment

Stand: 27. März 2026. Server: OpenClaw 2026.3.13.

## Server-Status (verifiziert via SSH)

| Parameter | Wert |
|---|---|
| OpenClaw Version | **2026.3.13** (61d171a) |
| Node.js | v22.22.1 |
| OS | Ubuntu 24.04.4 LTS |
| RAM | 15.6GB (6.4GB frei) |
| Disk | 119GB frei von 150GB |
| OpenClaw Binary | /usr/bin/openclaw |

## Bekannte Plugin-Bugs (aus GitHub Issues)

### Gateway-Crash Risiken
- **#54790** (v2026.3.24): Update überschreibt dist/ während Gateway läuft → Crash-Loop
- **#53247** (v2026.3.23): WhatsApp Plugin crasht bei jeder Message
- **#54931** (v2026.3.24): Discord Health-Monitor Uncaught Exception → Crash
- **#40929**: Gateway unresponsive nach Plugin-Install (ID Mismatch)

### Hook-Probleme
- **#5513 + #5943**: Plugin Hooks wurden NIE invoked (Timing-Issue bei Registration)
  - Status: Gefixt in #9761, #10678, #11823, #11867, #12583
  - **RISIKO für uns: Müssen verifizieren dass Hooks auf v2026.3.13 funktionieren**
- **#36412**: Plugin HTTP-Call ohne Timeout → Gateway Deadlock
- **#46256**: Plugin-Loading verlangsamt Handshake (6-7s)

### Breaking Changes v2026.3.22
- 12 Breaking Changes, u.a. entferntes `openclaw/extension-api`
- **Betrifft uns NICHT — wir sind auf v2026.3.13**

## Risiko-Matrix für AgentShield

| Risiko | Wahrscheinlichkeit | Impact | Mitigation |
|---|---|---|---|
| Unhandled Exception → Gateway Crash | HOCH wenn kein try-catch | KRITISCH | Jeder Hook in try-catch wrappen, fail-open |
| Langsamer Hook → Gateway blockiert | MITTEL | HOCH | Scanner <50ms halten, keine async I/O in Hooks |
| Hook wird nicht invoked | NIEDRIG (auf v2026.3.13) | HOCH | Beim Hackathon-Start testen, Fallback: Tool-basiert |
| Plugin-ID Mismatch | NIEDRIG | MITTEL | ID in plugin.json = ID in export |
| Memory Leak bei langem Lauf | NIEDRIG (24h) | NIEDRIG | Ring Buffer mit Limit (1000 Entries) |
| Dashboard Route-Konflikt | NIEDRIG | NIEDRIG | Unique Path `/agentshield` |

## Architektur-Entscheidung: Dashboard

**Control UI kann NICHT durch Plugins erweitert werden.**

Optionen:
1. **`registerHttpRoute("/agentshield")`** — Eigene HTML-Seite innerhalb OpenClaw Server
   - Pro: Einfach, kein separater Service, gleicher Port
   - Contra: Limitiert auf was der HTTP-Handler kann (kein WebSocket, nur SSE)

2. **Standalone Dashboard** — Separater Express Service
   - Pro: Volle Kontrolle, WebSocket möglich
   - Contra: Extra Service deployen, extra Port, Caddy Config

**Empfehlung: Option 1 (`registerHttpRoute`).** Einfacher, weniger Infrastruktur, SSE reicht für Live-Events.

## Defensive Coding Rules

```typescript
// JEDER Hook-Handler MUSS so aussehen:
api.on("before_tool_call", (event, ctx) => {
  try {
    const result = scanExecCommand(event.params?.command as string);
    if (result.detected && ctx.config.strictMode) {
      auditLog.add({ severity: result.severity, action: "block", ... });
      return { block: true, blockReason: `AgentShield: ${result.details}` };
    }
    auditLog.add({ severity: "none", action: "allow", ... });
    return undefined; // allow
  } catch (err) {
    console.error("[AgentShield] before_tool_call error:", err);
    // FAIL-OPEN: Bei Fehler nicht blockieren
    return undefined;
  }
});
```

## Verification Checklist (beim Hackathon-Start)

- [ ] `openclaw plugins install ./agentshield` → Plugin lädt ohne Fehler
- [ ] Gateway Logs: `[AgentShield] Plugin registered`
- [ ] Test-Message senden → `message_received` Hook feuert
- [ ] Test-exec senden → `before_tool_call` Hook feuert
- [ ] Dashboard URL erreichbar → `/agentshield` gibt HTML zurück
- [ ] Absichtlich Exception werfen → Gateway crasht NICHT
