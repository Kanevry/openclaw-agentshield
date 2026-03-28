import { describe, it, expect, vi, beforeEach } from "vitest";
import { AuditLog } from "../src/lib/audit-log.js";
import type { AuditEntry } from "../src/lib/scanner.types.js";

type EntryInput = Omit<AuditEntry, "id" | "timestamp">;

function makeEntry(overrides: Partial<EntryInput> = {}): EntryInput {
  return {
    hook: "before_tool_call",
    severity: "medium",
    category: "injection",
    patterns: ["test-pattern"],
    outcome: "blocked",
    details: "test entry",
    ...overrides,
  };
}

describe("AuditLog", () => {
  let log: AuditLog;

  beforeEach(() => {
    log = new AuditLog();
  });

  // ---------------------------------------------------------------
  // 1. add() — auto-generated id and timestamp
  // ---------------------------------------------------------------
  describe("add()", () => {
    it("creates entry with auto-generated string id", () => {
      const entry = log.add(makeEntry());
      expect(entry.id).toBe("1");
      expect(typeof entry.id).toBe("string");
    });

    it("creates entry with ISO timestamp", () => {
      const before = new Date().toISOString();
      const entry = log.add(makeEntry());
      const after = new Date().toISOString();

      expect(entry.timestamp).toBeDefined();
      expect(entry.timestamp >= before).toBe(true);
      expect(entry.timestamp <= after).toBe(true);
    });

    it("increments id for each added entry", () => {
      const e1 = log.add(makeEntry());
      const e2 = log.add(makeEntry());
      const e3 = log.add(makeEntry());

      expect(e1.id).toBe("1");
      expect(e2.id).toBe("2");
      expect(e3.id).toBe("3");
    });

    it("preserves all input fields on the returned entry", () => {
      const input = makeEntry({
        hook: "message_received",
        severity: "critical",
        category: "exfiltration",
        patterns: ["curl", "wget"],
        outcome: "warned",
        details: "suspicious command",
        toolName: "exec",
      });
      const entry = log.add(input);

      expect(entry.hook).toBe("message_received");
      expect(entry.severity).toBe("critical");
      expect(entry.category).toBe("exfiltration");
      expect(entry.patterns).toEqual(["curl", "wget"]);
      expect(entry.outcome).toBe("warned");
      expect(entry.details).toBe("suspicious command");
      expect(entry.toolName).toBe("exec");
    });

    it("increments size after add", () => {
      expect(log.size).toBe(0);
      log.add(makeEntry());
      expect(log.size).toBe(1);
      log.add(makeEntry());
      expect(log.size).toBe(2);
    });
  });

  // ---------------------------------------------------------------
  // 2. Ring buffer overflow
  // ---------------------------------------------------------------
  describe("ring buffer overflow", () => {
    it("evicts oldest entries when exceeding maxEntries", () => {
      const small = new AuditLog(3);

      small.add(makeEntry({ details: "first" }));
      small.add(makeEntry({ details: "second" }));
      small.add(makeEntry({ details: "third" }));
      expect(small.size).toBe(3);

      small.add(makeEntry({ details: "fourth" }));
      expect(small.size).toBe(3);

      const entries = small.getEntries({ limit: 10 });
      expect(entries).toHaveLength(3);
      expect(entries[0]!.details).toBe("second");
      expect(entries[1]!.details).toBe("third");
      expect(entries[2]!.details).toBe("fourth");
    });

    it("continues incrementing id after eviction", () => {
      const small = new AuditLog(2);

      small.add(makeEntry());
      small.add(makeEntry());
      const third = small.add(makeEntry());

      expect(third.id).toBe("3");
      expect(small.size).toBe(2);
    });

    it("never exceeds maxEntries capacity", () => {
      const small = new AuditLog(5);
      for (let i = 0; i < 20; i++) {
        small.add(makeEntry());
      }
      expect(small.size).toBe(5);
    });
  });

  // ---------------------------------------------------------------
  // 3. getEntries() — filtering
  // ---------------------------------------------------------------
  describe("getEntries() filtering", () => {
    beforeEach(() => {
      log.add(makeEntry({ severity: "high", category: "injection", hook: "before_tool_call" }));
      log.add(makeEntry({ severity: "low", category: "exfiltration", hook: "message_received" }));
      log.add(makeEntry({ severity: "high", category: "exfiltration", hook: "tool_result_persist" }));
      log.add(makeEntry({ severity: "medium", category: "injection", hook: "before_tool_call" }));
      log.add(makeEntry({ severity: "none", category: "none", hook: "manual" }));
    });

    it("returns all entries when no filters specified", () => {
      const entries = log.getEntries({ limit: 100 });
      expect(entries).toHaveLength(5);
    });

    it("filters by severity", () => {
      const entries = log.getEntries({ severity: "high", limit: 100 });
      expect(entries).toHaveLength(2);
      entries.forEach((e) => expect(e.severity).toBe("high"));
    });

    it("filters by category", () => {
      const entries = log.getEntries({ category: "exfiltration", limit: 100 });
      expect(entries).toHaveLength(2);
      entries.forEach((e) => expect(e.category).toBe("exfiltration"));
    });

    it("filters by hook", () => {
      const entries = log.getEntries({ hook: "before_tool_call", limit: 100 });
      expect(entries).toHaveLength(2);
      entries.forEach((e) => expect(e.hook).toBe("before_tool_call"));
    });

    it("combines multiple filters", () => {
      const entries = log.getEntries({
        severity: "high",
        category: "exfiltration",
        limit: 100,
      });
      expect(entries).toHaveLength(1);
      expect(entries[0]!.hook).toBe("tool_result_persist");
    });

    it("returns empty array when no entries match", () => {
      const entries = log.getEntries({ severity: "critical" });
      expect(entries).toEqual([]);
    });
  });

  // ---------------------------------------------------------------
  // 4. getEntries() limit — respects limit, returns newest
  // ---------------------------------------------------------------
  describe("getEntries() limit", () => {
    it("defaults to 50 entries", () => {
      for (let i = 0; i < 60; i++) {
        log.add(makeEntry({ details: `entry-${i}` }));
      }
      const entries = log.getEntries();
      expect(entries).toHaveLength(50);
      // Should be the newest 50 (entries 10..59)
      expect(entries[0]!.details).toBe("entry-10");
      expect(entries[49]!.details).toBe("entry-59");
    });

    it("respects explicit limit", () => {
      for (let i = 0; i < 10; i++) {
        log.add(makeEntry({ details: `entry-${i}` }));
      }
      const entries = log.getEntries({ limit: 3 });
      expect(entries).toHaveLength(3);
      // newest 3
      expect(entries[0]!.details).toBe("entry-7");
      expect(entries[1]!.details).toBe("entry-8");
      expect(entries[2]!.details).toBe("entry-9");
    });

    it("returns all if limit exceeds count", () => {
      log.add(makeEntry());
      log.add(makeEntry());
      const entries = log.getEntries({ limit: 100 });
      expect(entries).toHaveLength(2);
    });

    it("applies limit after filtering", () => {
      for (let i = 0; i < 10; i++) {
        log.add(makeEntry({ severity: i % 2 === 0 ? "high" : "low" }));
      }
      // 5 high entries exist; limit to 2
      const entries = log.getEntries({ severity: "high", limit: 2 });
      expect(entries).toHaveLength(2);
      entries.forEach((e) => expect(e.severity).toBe("high"));
    });
  });

  // ---------------------------------------------------------------
  // 5. getStats() — correct counts
  // ---------------------------------------------------------------
  describe("getStats()", () => {
    it("returns zeroed stats for empty log", () => {
      const stats = log.getStats();
      expect(stats.totalScanned).toBe(0);
      expect(stats.blocked).toBe(0);
      expect(stats.warned).toBe(0);
      expect(stats.allowed).toBe(0);
      expect(stats.bySeverity).toEqual({ none: 0, low: 0, medium: 0, high: 0, critical: 0 });
      expect(stats.byCategory).toEqual({ injection: 0, exfiltration: 0, "tool-abuse": 0, phishing: 0, none: 0 });
    });

    it("correctly counts totalScanned", () => {
      log.add(makeEntry());
      log.add(makeEntry());
      log.add(makeEntry());
      expect(log.getStats().totalScanned).toBe(3);
    });

    it("correctly counts outcomes (blocked, warned, allowed)", () => {
      log.add(makeEntry({ outcome: "blocked" }));
      log.add(makeEntry({ outcome: "blocked" }));
      log.add(makeEntry({ outcome: "warned" }));
      log.add(makeEntry({ outcome: "allowed" }));
      log.add(makeEntry({ outcome: "allowed" }));
      log.add(makeEntry({ outcome: "allowed" }));

      const stats = log.getStats();
      expect(stats.blocked).toBe(2);
      expect(stats.warned).toBe(1);
      expect(stats.allowed).toBe(3);
    });

    it("correctly counts bySeverity", () => {
      log.add(makeEntry({ severity: "none" }));
      log.add(makeEntry({ severity: "low" }));
      log.add(makeEntry({ severity: "low" }));
      log.add(makeEntry({ severity: "medium" }));
      log.add(makeEntry({ severity: "high" }));
      log.add(makeEntry({ severity: "critical" }));
      log.add(makeEntry({ severity: "critical" }));

      const stats = log.getStats();
      expect(stats.bySeverity.none).toBe(1);
      expect(stats.bySeverity.low).toBe(2);
      expect(stats.bySeverity.medium).toBe(1);
      expect(stats.bySeverity.high).toBe(1);
      expect(stats.bySeverity.critical).toBe(2);
    });

    it("correctly counts byCategory", () => {
      log.add(makeEntry({ category: "injection" }));
      log.add(makeEntry({ category: "injection" }));
      log.add(makeEntry({ category: "exfiltration" }));
      log.add(makeEntry({ category: "tool-abuse" }));
      log.add(makeEntry({ category: "phishing" }));
      log.add(makeEntry({ category: "none" }));

      const stats = log.getStats();
      expect(stats.byCategory.injection).toBe(2);
      expect(stats.byCategory.exfiltration).toBe(1);
      expect(stats.byCategory["tool-abuse"]).toBe(1);
      expect(stats.byCategory.phishing).toBe(1);
      expect(stats.byCategory.none).toBe(1);
    });
  });

  // ---------------------------------------------------------------
  // 6. subscribe() — listener receives new entries
  // ---------------------------------------------------------------
  describe("subscribe()", () => {
    it("listener receives newly added entries", () => {
      const received: AuditEntry[] = [];
      log.subscribe((entry) => received.push(entry));

      log.add(makeEntry({ details: "first" }));
      log.add(makeEntry({ details: "second" }));

      expect(received).toHaveLength(2);
      expect(received[0]!.details).toBe("first");
      expect(received[1]!.details).toBe("second");
    });

    it("multiple listeners all receive the entry", () => {
      const received1: AuditEntry[] = [];
      const received2: AuditEntry[] = [];

      log.subscribe((entry) => received1.push(entry));
      log.subscribe((entry) => received2.push(entry));

      log.add(makeEntry());

      expect(received1).toHaveLength(1);
      expect(received2).toHaveLength(1);
    });

    it("listener receives the fully hydrated entry with id and timestamp", () => {
      let captured: AuditEntry | undefined;
      log.subscribe((entry) => { captured = entry; });

      log.add(makeEntry());

      expect(captured).toBeDefined();
      expect(captured!.id).toBe("1");
      expect(captured!.timestamp).toBeDefined();
    });
  });

  // ---------------------------------------------------------------
  // 7. subscribe() cleanup — unsubscribe removes listener
  // ---------------------------------------------------------------
  describe("subscribe() cleanup", () => {
    it("unsubscribe stops further notifications", () => {
      const received: AuditEntry[] = [];
      const unsub = log.subscribe((entry) => received.push(entry));

      log.add(makeEntry());
      expect(received).toHaveLength(1);

      unsub();

      log.add(makeEntry());
      expect(received).toHaveLength(1); // no new entry
    });

    it("unsubscribe only removes the specific listener", () => {
      const received1: AuditEntry[] = [];
      const received2: AuditEntry[] = [];

      const unsub1 = log.subscribe((entry) => received1.push(entry));
      log.subscribe((entry) => received2.push(entry));

      unsub1();

      log.add(makeEntry());

      expect(received1).toHaveLength(0);
      expect(received2).toHaveLength(1);
    });
  });

  // ---------------------------------------------------------------
  // 8. subscribe() error isolation — bad listener doesn't crash
  // ---------------------------------------------------------------
  describe("subscribe() error isolation", () => {
    it("bad listener does not prevent entry from being added", () => {
      log.subscribe(() => {
        throw new Error("listener exploded");
      });

      const entry = log.add(makeEntry());
      expect(entry).toBeDefined();
      expect(log.size).toBe(1);
    });

    it("bad listener does not prevent other listeners from being called", () => {
      const received: AuditEntry[] = [];

      log.subscribe(() => {
        throw new Error("first listener fails");
      });
      log.subscribe((entry) => received.push(entry));

      log.add(makeEntry());

      expect(received).toHaveLength(1);
    });

    it("entry is returned correctly even when listener throws", () => {
      log.subscribe(() => {
        throw new Error("boom");
      });

      const entry = log.add(makeEntry({ details: "survives" }));
      expect(entry.details).toBe("survives");
      expect(entry.id).toBe("1");
    });
  });

  // ---------------------------------------------------------------
  // 9. clear() — resets entries
  // ---------------------------------------------------------------
  describe("clear()", () => {
    it("removes all entries", () => {
      log.add(makeEntry());
      log.add(makeEntry());
      log.add(makeEntry());
      expect(log.size).toBe(3);

      log.clear();
      expect(log.size).toBe(0);
    });

    it("getEntries returns empty after clear", () => {
      log.add(makeEntry());
      log.clear();
      expect(log.getEntries({ limit: 100 })).toEqual([]);
    });

    it("getStats returns zeroed after clear", () => {
      log.add(makeEntry({ outcome: "blocked", severity: "high" }));
      log.clear();

      const stats = log.getStats();
      expect(stats.totalScanned).toBe(0);
      expect(stats.blocked).toBe(0);
    });

    it("does not affect id counter — ids keep incrementing", () => {
      log.add(makeEntry());
      log.add(makeEntry());
      log.clear();

      const entry = log.add(makeEntry());
      expect(entry.id).toBe("3");
    });
  });

  // ---------------------------------------------------------------
  // 10. Instance independence — each instance has its own ID counter
  // ---------------------------------------------------------------
  describe("instance independence", () => {
    it("separate instances have independent ID counters", () => {
      const log1 = new AuditLog();
      const log2 = new AuditLog();

      const e1 = log1.add(makeEntry());
      const e2 = log1.add(makeEntry());
      const e3 = log2.add(makeEntry());

      expect(e1.id).toBe("1");
      expect(e2.id).toBe("2");
      expect(e3.id).toBe("1"); // independent counter
    });

    it("separate instances have independent entries", () => {
      const log1 = new AuditLog();
      const log2 = new AuditLog();

      log1.add(makeEntry());
      log1.add(makeEntry());
      log2.add(makeEntry());

      expect(log1.size).toBe(2);
      expect(log2.size).toBe(1);
    });

    it("separate instances have independent listeners", () => {
      const log1 = new AuditLog();
      const log2 = new AuditLog();
      const received: string[] = [];

      log1.subscribe(() => received.push("log1"));
      log2.subscribe(() => received.push("log2"));

      log1.add(makeEntry());

      expect(received).toEqual(["log1"]);
    });
  });
});
