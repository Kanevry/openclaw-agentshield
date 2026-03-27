/**
 * AgentShield — OpenClaw Security Plugin
 *
 * Hooks:
 *   - message_received: Scan inbound messages for injection
 *   - before_tool_call: Context-aware tool call guarding
 *   - tool_result_persist: Scan tool results for indirect injection
 *
 * Tools:
 *   - shield_scan: Manual security scan
 *   - shield_audit: Query audit log
 *
 * Dashboard:
 *   - GET /agentshield — HTML dashboard
 *   - GET /agentshield/events — SSE live stream
 */

// NOTE: Import types from OpenClaw plugin SDK when building
// import type { OpenClawPluginApi } from "openclaw/plugin-sdk";

// Placeholder types for scaffolding (replace with real imports at hackathon)
type OpenClawPluginApi = {
  on: (event: string, handler: (...args: unknown[]) => unknown) => void;
  registerTool: (tool: unknown, opts?: { optional?: boolean }) => void;
  registerHttpRoute: (params: { path: string; handler: (req: unknown, res: unknown) => void }) => void;
  registerCli?: (params: unknown) => void;
};

// ── Audit Log ────────────────────────────────────────────────────────

interface AuditEntry {
  timestamp: string;
  hook: string;
  severity: string;
  category: string;
  patterns: string[];
  outcome: "blocked" | "allowed" | "warned";
  details: string;
}

const auditLog: AuditEntry[] = [];
const MAX_AUDIT_ENTRIES = 1000;

function addAuditEntry(entry: Omit<AuditEntry, "timestamp">): void {
  auditLog.push({ ...entry, timestamp: new Date().toISOString() });
  if (auditLog.length > MAX_AUDIT_ENTRIES) {
    auditLog.shift();
  }
  // TODO: Emit SSE event for dashboard
}

// ── Plugin Entry ─────────────────────────────────────────────────────

export default {
  id: "agentshield",

  register(api: OpenClawPluginApi) {
    // ── Hook: message_received ──
    api.on("message_received", (event: unknown) => {
      // TODO: Import scanForInjection from core/scanner.ts
      // const result = scanForInjection(event.content);
      // if (result.detected) {
      //   addAuditEntry({ hook: "message_received", severity: result.severity, ... });
      //   event.messages?.push(`⚠️ AgentShield: Injection detected (${result.severity})`);
      // }
    });

    // ── Hook: before_tool_call ──
    api.on("before_tool_call", (event: unknown) => {
      // TODO: Import scanExecCommand, scanWriteContent from core/scanner.ts
      // const { toolName, params } = event as { toolName: string; params: Record<string, unknown> };
      //
      // if (toolName === "exec") {
      //   const result = scanExecCommand(params.command as string);
      //   if (result.detected) {
      //     addAuditEntry({ hook: "before_tool_call", outcome: "blocked", ... });
      //     return { block: true, blockReason: `AgentShield: ${result.category} detected` };
      //   }
      // }
      //
      // if (toolName === "write") {
      //   const result = scanWriteContent(params.content as string);
      //   if (result.detected) {
      //     addAuditEntry({ hook: "before_tool_call", outcome: "blocked", ... });
      //     return { block: true, blockReason: `AgentShield: ${result.category} in write` };
      //   }
      // }
      //
      // return undefined; // allow
    });

    // ── Hook: tool_result_persist ──
    api.on("tool_result_persist", (event: unknown) => {
      // TODO: Scan tool results for indirect injection
      // const { message } = event as { message: { content: string } };
      // const result = scanForInjection(message.content);
      // if (result.detected) {
      //   addAuditEntry({ hook: "tool_result_persist", outcome: "warned", ... });
      //   // Optionally modify message to include warning
      // }
    });

    // ── Tool: shield_scan ──
    // api.registerTool({
    //   name: "shield_scan",
    //   description: "Scan text for prompt injection, phishing, or suspicious patterns",
    //   parameters: { type: "object", properties: { text: { type: "string" } }, required: ["text"] },
    //   async execute(_id, params) {
    //     const result = fullScan(params.text);
    //     return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
    //   }
    // });

    // ── Tool: shield_audit ──
    // api.registerTool({
    //   name: "shield_audit",
    //   description: "Query the security audit log",
    //   parameters: { type: "object", properties: { limit: { type: "number" } } },
    //   async execute(_id, params) {
    //     const entries = auditLog.slice(-(params.limit ?? 20));
    //     return { content: [{ type: "text", text: JSON.stringify(entries, null, 2) }] };
    //   }
    // });

    // ── Dashboard HTTP Route ──
    // api.registerHttpRoute({
    //   path: "/agentshield",
    //   handler: (req, res) => {
    //     // Serve HTML dashboard
    //   }
    // });

    console.log("[AgentShield] Plugin registered — 3 hooks, 2 tools, 1 dashboard");
  },
};
