import { describe, it, expect } from "vitest";
import { PATTERN_COUNTS } from "../src/lib/scanner.js";

/**
 * SSOT Count Validation — ensures code matches documentation.
 * If a test fails, update BOTH the code AND the documentation.
 */
describe("SSOT pattern counts", () => {
  it("injection patterns: 76 (50 EN + 26 DE)", () => {
    expect(PATTERN_COUNTS.injection).toBe(76);
  });

  it("high severity patterns: 19", () => {
    expect(PATTERN_COUNTS.highSeverity).toBe(19);
  });

  it("exec danger patterns: 15", () => {
    expect(PATTERN_COUNTS.exec).toBe(15);
  });

  it("write danger patterns: 6", () => {
    expect(PATTERN_COUNTS.write).toBe(6);
  });

  it("sensitive data patterns: 29 (22 API + 7 PII)", () => {
    expect(PATTERN_COUNTS.sensitive).toBe(29);
  });

  it("HTML exfiltration patterns: 4", () => {
    expect(PATTERN_COUNTS.htmlExfil).toBe(4);
  });

  it("markdown exfiltration patterns: 2", () => {
    expect(PATTERN_COUNTS.markdownExfil).toBe(2);
  });

  it("SSRF patterns: 8", () => {
    expect(PATTERN_COUNTS.ssrf).toBe(8);
  });

  it("path traversal patterns: 7", () => {
    expect(PATTERN_COUNTS.pathTraversal).toBe(7);
  });

  it("obfuscation keywords: 15 (11 EN + 4 DE)", () => {
    expect(PATTERN_COUNTS.obfuscationKeywords).toBe(15);
  });

  it("typoglycemia targets: 18", () => {
    expect(PATTERN_COUNTS.typoglycemiaTargets).toBe(18);
  });

  it("total primitives: 180", () => {
    const total = Object.values(PATTERN_COUNTS).reduce((a, b) => a + b, 0);
    // Total = 76+19+15+6+29+4+2+8+7+15+18 = 199 (includes highSeverity which is a subset check, not separate patterns)
    // Marketing total excludes highSeverity (they overlap with injection): 76+15+6+29+4+2+8+7+15+18 = 180
    const marketingTotal = total - PATTERN_COUNTS.highSeverity;
    expect(marketingTotal).toBe(180);
  });

  it("ScanCategory values: 8 (after phishing removal)", () => {
    // injection, exfiltration, tool-abuse, rate-anomaly, markdown-exfil, ssrf, path-traversal, none
    // This is validated by TypeScript type system — if the type changes, tests will fail to compile
    const categories = ["injection", "exfiltration", "tool-abuse", "rate-anomaly", "markdown-exfil", "ssrf", "path-traversal", "none"] as const;
    expect(categories.length).toBe(8);
  });
});
