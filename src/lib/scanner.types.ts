/**
 * Scanner Type Definitions — Shared across all scanner modules
 *
 * These types are the contract between scanner, hooks, audit log, and dashboard.
 */

export type Severity = "none" | "low" | "medium" | "high" | "critical";

export type ScanCategory =
  | "injection"
  | "exfiltration"
  | "tool-abuse"
  | "phishing"
  | "rate-anomaly"
  | "none";

export interface ScanResult {
  detected: boolean;
  patterns: string[];
  severity: Severity;
  category: ScanCategory;
}

export interface AuditEntry {
  id: string;
  timestamp: string;
  hook: "message_received" | "before_tool_call" | "tool_result_persist" | "message_sending" | "manual";
  toolName?: string;
  severity: Severity;
  category: ScanCategory;
  patterns: string[];
  outcome: "blocked" | "allowed" | "warned";
  details: string;
}

export interface AuditStats {
  totalScanned: number;
  blocked: number;
  warned: number;
  allowed: number;
  bySeverity: Record<Severity, number>;
  byCategory: Record<ScanCategory, number>;
}
