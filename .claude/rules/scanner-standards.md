---
description: Scanner implementation standards and mandatory guards — ensures consistency across all scan functions
globs: ["src/lib/scanner.ts", "tests/scanner.test.ts", "src/index.ts"]
---

# Scanner Standards (established Session F)

## Mandatory Guards for Public Scan Functions

Every exported scan function MUST:
1. Check `MAX_SCAN_LENGTH` at entry — early return with clean result
2. Call `normalizeText()` before pattern matching (except for ASCII-only patterns like API keys)
3. Return a `ScanResult` with consistent shape: `{ detected, patterns, severity, category }`
4. Use `calcSeverity()` for severity calculation — never hardcode severity

## Whitespace Normalization

- `scanForInjection()` uses `collapseWhitespace()` to defeat newline-insertion evasion
- Exec/Write/PathTraversal scanners use `normalizeText()` for zero-width char removal
- Sensitive data patterns skip normalization (API keys are ASCII-only)

## Pattern Arrays

- All regex patterns: use lazy quantifiers `[^\n]*?` not greedy `.*`
- Regex literal in `readonly` array with `as const`
- New patterns: add to appropriate array, add corresponding test, update SSOT counts

## Base64/Hex/ROT13 Segment Limits

- `MAX_BASE64_SEGMENTS = 100` — prevent memory exhaustion from huge match arrays
- Each decoding function has its own `MAX_SCAN_LENGTH` check

## Issue Workflow

- Close issues with commit reference: `glab issue close <ID>` + `glab issue note -m "..."`
- Reference format: "Implemented in commit <short-hash>. <function> in <file>:<line>."
- Close immediately after implementation, not in batch

## SSE Connection Safety

- All SSE connections get heartbeat (15s) + inactivity timeout (5min)
- Cleanup function centralizes: clearInterval(heartbeat), clearInterval(inactivityCheck), unsubscribe()
- `req.on("close")` always calls cleanup
