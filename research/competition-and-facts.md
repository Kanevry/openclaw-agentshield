# Verifizierte Fakten & Konkurrenzanalyse

Stand: 27. März 2026. Alle Claims fact-checked.

## OpenClaw Fakten

| Claim | Status | Quelle |
|-------|--------|--------|
| GitHub Stars | **337K+** (März 27) | github.com/openclaw/openclaw + star-history.com |
| Creator | Peter Steinberger (PSPDFKit) | fortune.com, techcrunch.com |
| Steinberger bei OpenAI | Seit Feb 2026 | techcrunch.com/2026/02/15/ |
| Prompt Injection out of scope | **Bestätigt** | github.com/openclaw/openclaw/security |
| Native Plugin System | **Bestätigt** | docs.openclaw.ai/tools/plugin |
| 22+ Messaging Channels | **Bestätigt** | docs.openclaw.ai |

## Bekannte Sicherheitslücken (verifiziert)

1. **Fake [System Message] Blocks** — Issue #30111 (offen)
2. **Circulating Payloads** — Issue #30448 (aktive Bedrohung)
3. **Indirect Injection via URL Previews** — Issue #22060 (ungelöst)
4. **SSH Key Exfiltration** — Via single crafted email/webpage möglich (giskard.ai)
5. **SOUL.md Persistence Attacks** — Durable behavioral changes (penligent.ai)

## Existierende Security-Lösungen für OpenClaw

### ClawSec (prompt-security/clawsec)
- **Typ:** OpenClaw Skill (installierbar via `npx clawhub@latest install clawsec-suite`)
- **Features:** SOUL.md Drift Detection, Automated Audits, Skill Integrity Verification
- **Status:** Aktiv (Feb 2026)
- **Was es NICHT hat:** Real-time Dashboard, aktives Blocking, Base64 Detection

### OpenClaw Shield (knostic/openclaw-shield)
- **Typ:** Native Security Plugin
- **Features:** Secret Leak Prevention, PII Exposure, Destructive Command Prevention
- **Was es NICHT hat:** Real-time Monitoring, SSE Dashboard, Prompt Injection Detection

### SecureClaw (adversa-ai/secureclaw)
- **Typ:** Plugin + Skill (OWASP-aligned)
- **Features:** 56 Audit Checks, 5 Hardening Modules, 3 Background Monitors
- **Was es NICHT hat:** Live Dashboard, Hook-basiertes aktives Blocking

### openclaw-security-monitor (adibirzu)
- **Typ:** Proaktives Monitoring Skill
- **Features:** ClawHavoc Detection, AMOS Stealer, CVE-2026-25253, Memory Poisoning
- **Was es NICHT hat:** Real-time Visualization, User-facing Dashboard

## Standalone AI Security Tools (nicht OpenClaw-spezifisch)

| Tool | Stars | Typ | Fokus |
|------|-------|-----|-------|
| Guardrails AI | 6.6K | Framework | Input/Output Validation, 50+ Validators |
| NeMo Guardrails (NVIDIA) | 5.8K | Toolkit | Conversational Guardrails, Jailbreak Detection |
| LLM Guard | 2.7K | Library | 15 Input + 20 Output Scanner |
| Vigil | 454 | Library | YARA + ML-based Injection Detection |
| Rebuff | - | Framework | 4-Layer Prompt Injection Defense |
| Lakera Guard | SaaS | API | 10M+ Attack Data Points |

## AgentShield Differenzierung (ehrlich)

### Was wir ANDERS machen
1. **Real-time Dashboard mit SSE** — Kein existierendes Tool hat live Security-Visualization
2. **Hook-basiertes aktives Blocking** — `before_tool_call` return `{block: true}` — nicht nur Logging
3. **Base64 + Unicode Obfuscation** — Decode-and-scan geht tiefer als Pattern-Matching
4. **Battle-tested Scanner** — Von BitGN PAC Agent (20/20 Score)
5. **Hackathon-Kontext** — Von Practitioners für Practitioners, nicht von einer Security-Firma

### Was wir NEU hinzugefügt haben (Session 28.03.2026)
6. **OWASP LLM Prompt Injection Prevention Alignment** — Typoglycemia-Erkennung, Hex-Decoding, HTML-Exfiltration nach OWASP Cheat Sheet
7. **Output Monitoring** — message_sending Hook scannt Agent-Antworten auf System Prompt Leakage
8. **Rate Anomaly Detection** — Sliding-Window-Counter erkennt abnormale Tool-Call-Frequenz
9. **340 Tests** — Von 125 auf 340 Tests erweitert (+215)
10. **60 Attack Corpus Cases** — Von 33 auf 60 erweitert (+27)

### Was wir NICHT behaupten dürfen
- ~~"Erstes Security-Tool für OpenClaw"~~ → Es gibt mindestens 4
- ~~"247K Stars"~~ → Aktuell 337K+
- ~~"OpenClaw hat keine Security"~~ → Hat Infra-Security, kein Agent-Level
- ~~"Niemand hat das Problem erkannt"~~ → Issue #30111, #30448, #22060 zeigen: Community weiß es

### Korrektes Framing
> "OpenClaw hat 337K Stars und ein aktives Sicherheitsökosystem. AgentShield ist die OWASP-aligned Real-time Security-Schicht die nicht nur auditiert, sondern aktiv blockt — mit Typoglycemia-Erkennung, Hex-Decoding, HTML-Exfiltration-Schutz und einem Live-Dashboard."
