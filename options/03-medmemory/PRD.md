# MedMemory — Product Requirements Document

## Elevator Pitch

> "Ein AI-Assistent der sich an jeden Patienten erinnert."

AI Agent mit strukturiertem medizinischem Gedaechtnis fuer Aerzte. Merkt sich Medikamente, Diagnosen, Interaktionen. Laeuft auf OpenClaw, erreichbar via WhatsApp/Telegram.

## Problem

Aerzte sehen 20+ Patienten taeglich. Medikamenten-Interaktionen, Vorgeschichte, laufende Behandlungen — alles im Kopf behalten ist unmoeglich. EMR-Systeme sind umstaendlich und langsam.

## Loesung

OpenClaw Agent mit:
1. **Patient Memory Store** — Strukturierte Zod-Schemas fuer Patienten, Medikamente, Diagnosen
2. **Drug Interaction Check** — API-Anbindung (OpenFDA oder Mock)
3. **Multi-Channel** — WhatsApp fuer unterwegs, Desktop fuer Praxis
4. **Session Continuity** — Gleicher Kontext ueber alle Channels

## Risiken (HOCH)

- **Kein Healthcare-Domainwissen** — Judges (Olofsson, Dao) werden das merken
- **Drug Interaction DB** — Braucht echte Daten oder ueberzeugendes Mock
- **Compliance** — HIPAA/GDPR Fragen in 5 Min Demo beantworten
- **Nur sinnvoll mit Healthcare-Teampartner** vor Ort
