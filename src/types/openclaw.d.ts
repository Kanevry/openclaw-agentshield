/**
 * OpenClaw Plugin SDK Type Definitions
 *
 * Verified from OpenClaw source code (v2026.3.13).
 * Replace with real `openclaw/plugin-sdk` imports when available at runtime.
 */

// ── Agent Messages ──────────────────────────────────────────────────

export interface AgentMessage {
  role: "user" | "assistant" | "system";
  content: string;
  toolCalls?: ToolCall[];
  toolResults?: ToolResult[];
}

export interface ToolCall {
  id: string;
  name: string;
  arguments: Record<string, unknown>;
}

export interface ToolResult {
  toolCallId: string;
  content: string;
}

// ── Hook Event Types ────────────────────────────────────────────────

// Real event format (verified from OpenClaw 2026.3.24 gateway source):
// { from, content, timestamp, metadata: { to, provider, surface, threadId, senderId, senderName, ... } }
export interface MessageReceivedEvent {
  from?: string;
  content?: string;
  timestamp?: string;
  metadata?: Record<string, unknown>;
}

export interface BeforeToolCallEvent {
  toolName: string;
  params: Record<string, unknown>;
}

export interface BeforeToolCallResult {
  block?: boolean;
  blockReason?: string;
  params?: Record<string, unknown>;
}

export interface ToolResultPersistEvent {
  toolName?: string;
  toolCallId?: string;
  message: AgentMessage;
  isSynthetic?: boolean;
}

export interface ToolResultPersistResult {
  message?: AgentMessage;
}

// ── Plugin Context ──────────────────────────────────────────────────

export interface PluginContext {
  config: AgentShieldConfig;
}

export interface AgentShieldConfig {
  strictMode: boolean;
  allowedExecPatterns: string[];
  blockedDomains: string[];
  dashboard: boolean;
  rateLimit: number;
  blockOutbound: boolean;
}

// ── Plugin API ──────────────────────────────────────────────────────

export interface OpenClawPluginApi {
  on(
    event: "message_received",
    handler: (event: Record<string, unknown>, ctx: PluginContext) => void,
  ): void;
  on(
    event: "before_tool_call",
    handler: (
      event: BeforeToolCallEvent,
      ctx: PluginContext,
    ) => BeforeToolCallResult | undefined | void,
  ): void;
  on(
    event: "tool_result_persist",
    handler: (
      event: ToolResultPersistEvent,
      ctx: PluginContext,
    ) => ToolResultPersistResult | undefined | void,
  ): void;
  on(
    event: "message_sending",
    handler: (
      event: { message: AgentMessage },
      ctx: PluginContext,
    ) => { cancel?: boolean } | void,
  ): void;

  registerTool(
    tool: ToolDefinition,
    opts?: { optional?: boolean },
  ): void;

  registerHttpRoute(params: {
    path: string;
    handler: (req: import("node:http").IncomingMessage, res: import("node:http").ServerResponse) => Promise<boolean | void> | boolean | void;
    auth: "gateway" | "plugin";
    match?: "exact" | "prefix";
    replaceExisting?: boolean;
  }): void;
}

export interface ToolDefinition {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
  execute?: (id: string, params: Record<string, unknown>) => Promise<ToolExecuteResult>;
}

export interface ToolExecuteResult {
  content: Array<{ type: "text"; text: string }>;
}

// ── HTTP Types ──────────────────────────────────────────────────────
// Plugin HTTP routes use Node.js standard IncomingMessage / ServerResponse
// imported inline in registerHttpRoute signature above.

// ── Plugin Entry ────────────────────────────────────────────────────

export interface PluginEntry {
  id: string;
  register(api: OpenClawPluginApi): void;
}
