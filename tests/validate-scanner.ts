/**
 * Scanner Validation Script — Runs attack corpus against the scanner
 *
 * Usage: pnpm run test:scanner
 *
 * Loads tests/attack-corpus.json and validates each case against
 * scanForInjection, scanExecCommand, and scanWriteContent.
 */

import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { scanForInjection, scanExecCommand, scanWriteContent } from "../src/lib/scanner.js";
import type { Severity } from "../src/lib/scanner.types.js";

const __dirname = dirname(fileURLToPath(import.meta.url));

interface TestCase {
  id: string;
  name?: string;
  description?: string;
  input: string;
  context: "message" | "exec" | "write" | "read" | "general";
  expectedDetected: boolean;
  expectedMinSeverity: Severity;
  allowedPatterns?: string[];
}

interface Corpus {
  cases: TestCase[];
}

const SEVERITY_ORDER: Record<Severity, number> = {
  none: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function severityAtLeast(actual: Severity, expected: Severity): boolean {
  return SEVERITY_ORDER[actual] >= SEVERITY_ORDER[expected];
}

// ── Main ─────────────────────────────────────────────────────────────

const corpusPath = resolve(__dirname, "attack-corpus.json");
const corpus: Corpus = JSON.parse(readFileSync(corpusPath, "utf-8"));

let passed = 0;
let failed = 0;
const failures: string[] = [];

for (const tc of corpus.cases) {
  let result;

  switch (tc.context) {
    case "exec":
      result = scanExecCommand(tc.input, tc.allowedPatterns);
      break;
    case "write":
      result = scanWriteContent(tc.input);
      break;
    default:
      result = scanForInjection(tc.input);
      break;
  }

  const detectionOk = result.detected === tc.expectedDetected;
  const severityOk =
    !tc.expectedDetected || severityAtLeast(result.severity, tc.expectedMinSeverity);

  if (detectionOk && severityOk) {
    passed++;
    const label = tc.name ?? tc.description ?? tc.id;
    console.log(`  \x1b[32m✓\x1b[0m ${tc.id}: ${label}`);
  } else {
    failed++;
    const reason = !detectionOk
      ? `detected=${result.detected}, expected=${tc.expectedDetected}`
      : `severity=${result.severity}, expected>=${tc.expectedMinSeverity}`;
    const label = tc.name ?? tc.description ?? tc.id;
    failures.push(`${tc.id}: ${label} — ${reason}`);
    console.log(`  \x1b[31m✗\x1b[0m ${tc.id}: ${label} — ${reason}`);
  }
}

// ── Summary ──────────────────────────────────────────────────────────

console.log("\n" + "═".repeat(60));
console.log(`Results: ${passed} passed, ${failed} failed out of ${corpus.cases.length}`);

if (failures.length > 0) {
  console.log("\nFailures:");
  for (const f of failures) {
    console.log(`  - ${f}`);
  }
  process.exit(1);
} else {
  console.log("\x1b[32m\nAll tests passed!\x1b[0m");
  process.exit(0);
}
