# Konkurrenz — Verifizierte Analyse

Stand: 27. März 2026.

## OpenClaw-Native Security Tools

### ClawSec (prompt-security/clawsec)
| Fakt | Wert | Quelle |
|------|------|--------|
| Typ | OpenClaw Skill (nicht Plugin) | github.com/prompt-security/clawsec |
| Install | `npx clawhub@latest install clawsec-suite` | github.com/prompt-security/clawsec README |
| Features | SOUL.md Drift Detection, Automated Audits, Skill Integrity | github.com/prompt-security/clawsec |
| Hat Real-time Dashboard? | **NEIN** | Kein Dashboard in Repo/README (27.03. geprüft) |
| Hat aktives Blocking (before_tool_call)? | **NEIN** — ist ein Skill, kein Plugin mit Hooks | Skill-basiert, keine Hook-Registration |
| Hat Base64/Unicode Detection? | **Nicht dokumentiert** | README enthält keine Pattern-Liste |
| Hersteller | Prompt Security (kommerziell) | prompt-security.com |

### OpenClaw Shield (knostic/openclaw-shield)
| Fakt | Wert | Quelle |
|------|------|--------|
| Typ | Native Security Plugin | github.com/knostic/openclaw-shield |
| Features | Secret Leak Prevention, PII Exposure, Destructive Commands | github.com/knostic/openclaw-shield |
| Hat Real-time Dashboard? | **NEIN** | Kein Dashboard in Repo (27.03. geprüft) |
| Hat aktives Blocking? | Teilweise (Destructive Commands) | README: prevents destructive execution |
| Hat Prompt Injection Detection? | **NEIN** — Fokus auf Secrets/PII | README erwähnt keine Injection Detection |
| Hersteller | Knostic (kommerziell) | knostic.ai |

### SecureClaw (adversa-ai/secureclaw)
| Fakt | Wert | Quelle |
|------|------|--------|
| Typ | Plugin + Skill (OWASP-aligned) | github.com/adversa-ai/secureclaw |
| Features | 56 Audit Checks, 5 Hardening Modules, 3 Background Monitors | github.com/adversa-ai/secureclaw |
| Hat Real-time Dashboard? | **NEIN** — CLI-basiert | Kein Dashboard in Repo (27.03. geprüft) |
| Hat SSE Live Events? | **NEIN** | Keine SSE/WebSocket Implementation |
| Hat Base64 Decode? | **Nicht dokumentiert** | README listet keine Pattern-Details |
| Hersteller | Adversa AI (kommerziell) | adversa.ai |

### openclaw-security-monitor (adibirzu)
| Fakt | Wert | Quelle |
|------|------|--------|
| Typ | Proactive Monitoring Skill | github.com/adibirzu/openclaw-security-monitor |
| Features | ClawHavoc, AMOS Stealer, CVE-2026-25253, Memory Poisoning, Supply Chain | github.com/adibirzu/openclaw-security-monitor |
| Hat Real-time Dashboard? | **NEIN** | Skill-basiert, keine UI |
| Hat aktives Blocking? | **NEIN** — Monitoring/Alerting only | README: "proactive security monitoring" |
| Hersteller | Community (Einzelperson) | github.com/adibirzu |

## Standalone AI Security Tools (nicht OpenClaw-spezifisch)

| Tool | Stars | Hat OC-Integration? | Hat Real-time Dashboard? | Hat aktives Blocking? | Quelle |
|------|-------|---------------------|--------------------------|----------------------|--------|
| Guardrails AI | 6.6K | NEIN | NEIN | JA (Validators) | github.com/guardrails-ai/guardrails |
| NeMo Guardrails | 5.8K | NEIN | NEIN | JA (Rails) | github.com/NVIDIA-NeMo/Guardrails |
| LLM Guard | 2.7K | NEIN | NEIN | JA (Scanners) | github.com/protectai/llm-guard |
| Vigil | 454 | NEIN | NEIN | JA (YARA) | github.com/deadbits/vigil-llm |
| Lakera Guard | SaaS | NEIN | Dashboard (SaaS) | JA (API) | lakera.ai |

## Feature-Matrix: AgentShield vs. Alle

| Feature | ClawSec | OC Shield | SecureClaw | OC Monitor | AgentShield (wir) |
|---------|---------|-----------|------------|------------|-------------------|
| OpenClaw-native | Skill | Plugin | Plugin+Skill | Skill | **Plugin** |
| Prompt Injection Detection | Drift only | NEIN | Audit only | Monitoring | **Aktiv (20+ Patterns)** |
| Base64/Unicode Decode | ? | NEIN | ? | NEIN | **JA** |
| before_tool_call Blocking | NEIN | Teilweise | NEIN | NEIN | **JA (aktiv)** |
| tool_result_persist Scanning | NEIN | NEIN | NEIN | NEIN | **JA (Indirect Injection)** |
| Real-time Dashboard | NEIN | NEIN | NEIN | NEIN | **JA (HTML+SSE)** |
| SSE Live Events | NEIN | NEIN | NEIN | NEIN | **JA** |
| Structured Audit Trail | NEIN | NEIN | Audit Checks | NEIN | **JA (Ring Buffer)** |
| Agent-callable Tools | NEIN | NEIN | NEIN | NEIN | **JA (shield_scan, shield_audit)** |
| SOUL.md Protection | JA (Drift) | NEIN | JA (Hardening) | NEIN | Nicht in v1 |
| Supply Chain | NEIN | NEIN | NEIN | JA | Nicht in v1 |
