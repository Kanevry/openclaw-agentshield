/**
 * Security Scanner — Prompt Injection Detection, Phishing, Feature Detection
 *
 * Origin: BitGN PAC Agent (100% score, 20/20 tasks)
 * Adapted for: AgentShield OpenClaw Plugin
 *
 * Pure functions — no external dependencies.
 */

// ── Types ────────────────────────────────────────────────────────────

export type Severity = "none" | "low" | "medium" | "high" | "critical";

export interface ScanResult {
  detected: boolean;
  patterns: string[];
  severity: Severity;
  category: "injection" | "exfiltration" | "tool-abuse" | "phishing" | "none";
}

export interface DomainValidation {
  match: boolean;
  senderDomain: string;
  knownDomain: string;
}

// ── Prompt Injection Patterns ────────────────────────────────────────

const INJECTION_PATTERNS: readonly string[] = [
  // Instruction override
  "ignore previous instructions",
  "ignore all previous",
  "forget your instructions",
  "disregard your instructions",
  "disregard all previous",
  "new instructions:",
  "override:",
  "system prompt:",
  // Identity manipulation
  "you are now",
  "act as a different agent",
  "pretend to be",
  "act as",
  // Credential extraction
  "forward secrets",
  "exfiltrate",
  "send me your api key",
  "send data to",
  "relay via",
  "authenticated request",
  "marked as trusted",
  // Markup injection (LLM control tokens)
  "[SYSTEM]",
  "[ADMIN]",
  "[INST]",
  "<|im_start|>",
  "<|im_end|>",
  "### Human:",
  "### Assistant:",
  "\n\nHuman:",
  "\n\nAssistant:",
] as const;

const HIGH_SEVERITY_PATTERNS: readonly string[] = [
  "forward secrets",
  "exfiltrate",
  "send me your api key",
  "send data to",
  "relay via",
  "[SYSTEM]",
  "[ADMIN]",
  "<|im_start|>",
] as const;

// ── Tool Abuse Patterns (NEW for AgentShield) ────────────────────────

const EXEC_DANGER_PATTERNS: readonly RegExp[] = [
  /\bcurl\s+.*https?:\/\/(?!localhost|127\.0\.0\.1)/i,
  /\bwget\s+.*https?:\/\//i,
  /\brm\s+-[rf]{1,2}\s+\//i,
  /\brm\s+-[rf]{1,2}\s+~\//i,
  /\bchmod\s+777\b/i,
  /\bchmod\s+\+[sx]\b/i,
  /\beval\b.*\$/i,
  /\benv\b|\bprintenv\b/i,
  /\becho\s+\$[A-Z_]+/i,         // echo $SECRET
  /\|\s*nc\s+/i,                   // pipe to netcat
  /\|\s*curl\s+/i,                 // pipe to curl
  /\bsudo\b/i,
  /\bdd\s+if=/i,
  />\s*\/etc\//i,                   // write to /etc/
  /\bkill\s+-9\b/i,
] as const;

const WRITE_DANGER_PATTERNS: readonly RegExp[] = [
  /eval\s*\(/i,
  /exec\s*\(/i,
  /require\s*\(\s*['"]child_process/i,
  /import\s+.*from\s+['"]child_process/i,
  /process\.env\./i,
  /<script\b/i,
] as const;

// ── Base64 Detection ─────────────────────────────────────────────────

const BASE64_INJECTION_KEYWORDS: readonly string[] = [
  "ignore previous",
  "ignore all previous",
  "forget your instructions",
  "disregard your instructions",
  "system prompt",
  "override",
  "exfiltrate",
  "forward secrets",
  "send me your api key",
] as const;

const BASE64_SEGMENT_RE = /[A-Za-z0-9+/]{16,}={0,2}/g;

function isValidBase64(segment: string): boolean {
  if (segment.length % 4 !== 0) return false;
  try {
    const decoded = Buffer.from(segment, "base64").toString("utf-8");
    return /^[\x20-\x7E\t\n\r]+$/.test(decoded);
  } catch {
    return false;
  }
}

function checkBase64Injections(text: string): string[] {
  const matches: string[] = [];
  const segments = text.match(BASE64_SEGMENT_RE);
  if (!segments) return matches;

  for (const segment of segments) {
    if (!isValidBase64(segment)) continue;
    let decoded: string;
    try {
      decoded = Buffer.from(segment, "base64").toString("utf-8").toLowerCase();
    } catch {
      continue;
    }
    for (const keyword of BASE64_INJECTION_KEYWORDS) {
      if (decoded.includes(keyword)) {
        matches.push(`base64("${keyword}")`);
      }
    }
  }
  return matches;
}

// ── Core Scan Functions ──────────────────────────────────────────────

/**
 * Scan text for prompt injection patterns.
 * Checks plaintext + base64-encoded variants.
 */
export function scanForInjection(text: string): ScanResult {
  const lower = text.toLowerCase();
  const matched: string[] = [];

  for (const pattern of INJECTION_PATTERNS) {
    if (lower.includes(pattern.toLowerCase())) {
      matched.push(pattern);
    }
  }

  const base64Hits = checkBase64Injections(text);
  matched.push(...base64Hits);

  if (matched.length === 0) {
    return { detected: false, patterns: [], severity: "none", category: "none" };
  }

  const hasHigh = matched.some((m) =>
    HIGH_SEVERITY_PATTERNS.some((h) => m.toLowerCase().includes(h.toLowerCase())),
  );
  const severity: Severity =
    hasHigh || matched.length > 2
      ? "critical"
      : matched.length > 1
        ? "high"
        : "medium";

  return { detected: true, patterns: matched, severity, category: "injection" };
}

/**
 * Scan an exec command for dangerous patterns.
 */
export function scanExecCommand(command: string): ScanResult {
  const matched: string[] = [];

  for (const pattern of EXEC_DANGER_PATTERNS) {
    if (pattern.test(command)) {
      matched.push(pattern.source);
    }
  }

  if (matched.length === 0) {
    return { detected: false, patterns: [], severity: "none", category: "none" };
  }

  return {
    detected: true,
    patterns: matched,
    severity: matched.length > 1 ? "critical" : "high",
    category: "tool-abuse",
  };
}

/**
 * Scan file content being written for dangerous patterns.
 */
export function scanWriteContent(content: string): ScanResult {
  const matched: string[] = [];

  for (const pattern of WRITE_DANGER_PATTERNS) {
    if (pattern.test(content)) {
      matched.push(pattern.source);
    }
  }

  // Also check for injection in written content
  const injectionResult = scanForInjection(content);
  if (injectionResult.detected) {
    matched.push(...injectionResult.patterns.map((p) => `injection:${p}`));
  }

  if (matched.length === 0) {
    return { detected: false, patterns: [], severity: "none", category: "none" };
  }

  return {
    detected: true,
    patterns: matched,
    severity: matched.length > 1 ? "high" : "medium",
    category: "tool-abuse",
  };
}

// ── Email/Phishing Detection ─────────────────────────────────────────

function extractDomain(email: string): string {
  const atIndex = email.lastIndexOf("@");
  if (atIndex === -1) return "";
  return email.slice(atIndex + 1).toLowerCase().trim();
}

export function validateEmailDomain(
  senderEmail: string,
  knownContactEmail: string,
): DomainValidation {
  const senderDomain = extractDomain(senderEmail);
  const knownDomain = extractDomain(knownContactEmail);
  return { match: senderDomain === knownDomain, senderDomain, knownDomain };
}

// ── URL/Domain Checking ──────────────────────────────────────────────

/**
 * Check if a URL points to a potentially dangerous domain.
 */
export function isBlockedUrl(
  url: string,
  blockedDomains: string[] = [],
): boolean {
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();
    return blockedDomains.some(
      (d) => hostname === d || hostname.endsWith(`.${d}`),
    );
  } catch {
    return false;
  }
}

// ── Comprehensive Scan ───────────────────────────────────────────────

/**
 * Run all scans on a piece of text. Returns the highest severity result.
 */
export function fullScan(
  text: string,
  context?: { type: "exec" | "write" | "read" | "message" | "general" },
): ScanResult {
  // Always check for injection
  const injectionResult = scanForInjection(text);
  if (injectionResult.severity === "critical") return injectionResult;

  // Context-specific checks
  if (context?.type === "exec") {
    const execResult = scanExecCommand(text);
    if (execResult.detected) return execResult;
  }

  if (context?.type === "write") {
    const writeResult = scanWriteContent(text);
    if (writeResult.detected) return writeResult;
  }

  return injectionResult;
}
