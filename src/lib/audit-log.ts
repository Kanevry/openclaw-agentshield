/**
 * Audit Log — Ring Buffer + SSE Event Emitter
 *
 * In-memory ring buffer for security events with SSE support for dashboard.
 * Max 1000 entries, oldest evicted on overflow.
 *
 * @example
 * const log = new AuditLog();
 * log.add({ hook: "before_tool_call", severity: "high", ... });
 * log.subscribe((entry) => sseStream.write(entry));
 */

import type { AuditEntry, AuditStats, Severity, ScanCategory } from "./scanner.types.js";

type AuditListener = (entry: AuditEntry) => void;

let nextId = 1;

export class AuditLog {
  private readonly entries: AuditEntry[] = [];
  private readonly maxEntries: number;
  private readonly listeners = new Set<AuditListener>();

  constructor(maxEntries = 1000) {
    this.maxEntries = maxEntries;
  }

  add(entry: Omit<AuditEntry, "id" | "timestamp">): AuditEntry {
    const full: AuditEntry = {
      ...entry,
      id: String(nextId++),
      timestamp: new Date().toISOString(),
    };

    this.entries.push(full);
    if (this.entries.length > this.maxEntries) {
      this.entries.shift();
    }

    for (const listener of this.listeners) {
      try {
        listener(full);
      } catch {
        // Don't let a bad listener crash the audit log
      }
    }

    return full;
  }

  getEntries(opts?: {
    limit?: number;
    severity?: Severity;
    category?: ScanCategory;
    hook?: string;
  }): AuditEntry[] {
    let filtered = this.entries;

    if (opts?.severity) {
      filtered = filtered.filter((e) => e.severity === opts.severity);
    }
    if (opts?.category) {
      filtered = filtered.filter((e) => e.category === opts.category);
    }
    if (opts?.hook) {
      filtered = filtered.filter((e) => e.hook === opts.hook);
    }

    const limit = opts?.limit ?? 50;
    return filtered.slice(-limit);
  }

  getStats(): AuditStats {
    const stats: AuditStats = {
      totalScanned: this.entries.length,
      blocked: 0,
      warned: 0,
      allowed: 0,
      bySeverity: { none: 0, low: 0, medium: 0, high: 0, critical: 0 },
      byCategory: { injection: 0, exfiltration: 0, "tool-abuse": 0, phishing: 0, none: 0 },
    };

    for (const entry of this.entries) {
      stats[entry.outcome]++;
      stats.bySeverity[entry.severity]++;
      stats.byCategory[entry.category]++;
    }

    return stats;
  }

  subscribe(listener: AuditListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  clear(): void {
    this.entries.length = 0;
  }

  get size(): number {
    return this.entries.length;
  }
}
