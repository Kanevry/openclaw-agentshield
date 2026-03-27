# Telegram Bot Setup — Learnings (27. Maerz 2026)

## Was wir versucht haben

Atlas Security Bot (@atlas_sec_bot) als zweiten Telegram-Bot neben Sepp einrichten.

## Was nicht funktioniert hat

### 1. Multi-Bot Telegram (providers/instances/accounts)
- `telegram.providers` → Stack Overflow im Config-Parser
- `telegram.instances` → Ignoriert, nur Default-Bot startet
- `telegram.accounts` → Ignoriert
- **Fazit**: OpenClaw v2026.3.24 unterstuetzt KEINEN Multi-Bot Telegram in der Config

### 2. Bot-Token Swap (Sepp → Atlas)
- Token in `.env` getauscht → Bot startet (`@atlas_sec_bot`)
- allowFrom auf Bernhards ID gesetzt
- **Nachrichten kommen an** (verifiziert via direktem `curl getUpdates`)
- **Aber Gateway verarbeitet sie nicht** — still verworfen, kein Log-Eintrag
- dmPolicy "open" und "allowlist" getestet — beide ohne Erfolg
- AgentShield Plugin deaktiviert — gleches Problem → Plugin ist NICHT die Ursache

### 3. Root Cause (vermutet)
- Manueller `curl getUpdates` Aufruf hat den **Polling-Offset des Gateways zerstoert**
- Telegram erlaubt nur EINEN getUpdates-Consumer — unser manueller Call hat einen 409 Conflict ausgeloest
- Danach war der Gateway-Polling-Loop permanent kaputt
- Moeglicherweise hat OpenClaw einen internen State der nicht nur vom Offset abhaengt

### 4. Zusaetzliche Probleme
- Gateway Log zeigt Nachrichten-Empfang NICHT an (auch nicht auf Debug-Level)
- Keine Fehlermeldungen — Messages werden lautlos verworfen
- Schwer zu debuggen ohne Zugriff auf OpenClaw-Internals

## Was funktioniert

- Sepp (@Sepp_kalenderbot) mit Lisas ID — funktionierte vorher, wiederhergestellt
- AgentShield Plugin wird geladen (`Plugin registered — 3 hooks, 2 tools, 4 routes`)
- Plugin-Installation via `openclaw plugins install -l`

## Empfehlung fuer Hackathon

1. **NICHT** den Production-Bot anfassen — zu riskant
2. **Separate OpenClaw-Instanz** fuer Atlas aufsetzen (Docker oder zweiter Port)
3. Oder: Atlas-Bot als **Standalone-Bot** ohne OpenClaw (direkt mit Grammy/Telegram API)
4. Oder: **Sepp** fuer Demo verwenden, Lisa vorab informieren

## Wichtige Regeln

- NIEMALS `curl getUpdates` manuell aufrufen wenn ein Bot-Prozess laeuft
- Telegram erlaubt NUR EINEN Polling-Consumer pro Bot-Token
- OpenClaw Config-Aenderungen an Telegram immer mit Backup testen
- Bei Problemen: sofort auf Backup zuruecksetzen, nicht weiter experimentieren
