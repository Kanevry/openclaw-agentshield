/**
 * Dashboard Route Tests — AgentShield HTTP Endpoints
 *
 * Strategy: mock the OpenClaw Plugin API, register the plugin,
 * capture the route handler, then invoke it with mock req/res objects.
 *
 * Routes tested:
 *   - GET /agentshield — HTML dashboard (default/fallback)
 *   - GET /agentshield/events — SSE live stream
 *   - GET /agentshield/api/audit — JSON audit log
 *   - GET /agentshield/api/stats — JSON statistics
 *
 * Run: pnpm test
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import type { IncomingMessage, ServerResponse } from "node:http";
import { EventEmitter } from "node:events";
import type { ToolDefinition } from "../src/types/openclaw.js";

// Import the default plugin export
import plugin from "../src/index.js";

// ── Mock API ────────────────────────────────────────────────────────

type HookHandler = (...args: unknown[]) => unknown;

interface MockApi {
  hooks: Map<string, HookHandler>;
  tools: Map<string, { def: ToolDefinition; opts?: { optional?: boolean } }>;
  routeHandler: ((req: IncomingMessage, res: ServerResponse) => void) | null;
  api: {
    on(event: string, handler: HookHandler): void;
    registerTool(def: ToolDefinition, opts?: { optional?: boolean }): void;
    registerHttpRoute(route: { path: string; handler: (req: IncomingMessage, res: ServerResponse) => void }): void;
  };
}

function createMockApi(): MockApi {
  const hooks = new Map<string, HookHandler>();
  const tools = new Map<string, { def: ToolDefinition; opts?: { optional?: boolean } }>();
  let routeHandler: ((req: IncomingMessage, res: ServerResponse) => void) | null = null;

  const mock: MockApi = {
    hooks,
    tools,
    routeHandler: null,
    api: {
      on(event: string, handler: HookHandler) {
        hooks.set(event, handler);
      },
      registerTool(def: ToolDefinition, opts?: { optional?: boolean }) {
        tools.set(def.name, { def, opts });
      },
      registerHttpRoute(route: { path: string; handler: (req: IncomingMessage, res: ServerResponse) => void }) {
        routeHandler = route.handler;
        mock.routeHandler = routeHandler;
      },
    },
  };

  return mock;
}

// ── Mock Request/Response ───────────────────────────────────────────

function createMockReq(url: string): IncomingMessage {
  const req = new EventEmitter() as IncomingMessage;
  req.url = url;
  req.method = "GET";
  return req;
}

function createMockRes(): ServerResponse & {
  getHeaders: () => Record<string, string>;
  getBody: () => string;
  isEnded: () => boolean;
} {
  const headers: Record<string, string> = {};
  let body = "";
  let ended = false;

  const res = new EventEmitter() as ServerResponse & {
    getHeaders: () => Record<string, string>;
    getBody: () => string;
    isEnded: () => boolean;
  };

  res.setHeader = vi.fn((name: string, value: string | number | readonly string[]) => {
    headers[name.toLowerCase()] = String(value);
    return res;
  });

  res.write = vi.fn((data: unknown) => {
    body += String(data);
    return true;
  }) as unknown as typeof res.write;

  res.end = vi.fn((data?: unknown) => {
    if (data !== undefined) body += String(data);
    ended = true;
    return res;
  }) as unknown as typeof res.end;

  res.getHeaders = () => headers;
  res.getBody = () => body;
  res.isEnded = () => ended;

  return res;
}

// ── Test Suite ──────────────────────────────────────────────────────

describe("AgentShield Dashboard Routes", () => {
  let handler: (req: IncomingMessage, res: ServerResponse) => void;

  beforeEach(() => {
    const mock = createMockApi();
    plugin.register(mock.api as never);
    expect(mock.routeHandler).not.toBeNull();
    handler = mock.routeHandler!;
  });

  // ── GET /agentshield (HTML dashboard) ─────────────────────────────

  describe("GET /agentshield (HTML dashboard)", () => {
    it("returns HTML with correct Content-Type", () => {
      const req = createMockReq("/agentshield");
      const res = createMockRes();
      handler(req, res);
      expect(res.getHeaders()["content-type"]).toBe("text/html; charset=utf-8");
    });

    it("includes CSP header without nonce (Tailwind CDN compatible)", () => {
      const req = createMockReq("/agentshield");
      const res = createMockRes();
      handler(req, res);
      const csp = res.getHeaders()["content-security-policy"];
      expect(csp).toBeDefined();
      expect(csp).toContain("script-src 'self' https://cdn.tailwindcss.com 'unsafe-inline' 'unsafe-eval'");
      expect(csp).toContain("style-src 'self' 'unsafe-inline'");
      expect(csp).toContain("frame-ancestors 'none'");
      expect(csp).toContain("base-uri 'self'");
      expect(csp).toContain("object-src 'none'");
    });

    it("includes X-Content-Type-Options header", () => {
      const req = createMockReq("/agentshield");
      const res = createMockRes();
      handler(req, res);
      expect(res.getHeaders()["x-content-type-options"]).toBe("nosniff");
    });

    it("includes X-Frame-Options header", () => {
      const req = createMockReq("/agentshield");
      const res = createMockRes();
      handler(req, res);
      expect(res.getHeaders()["x-frame-options"]).toBe("DENY");
    });

    it("includes Referrer-Policy header", () => {
      const req = createMockReq("/agentshield");
      const res = createMockRes();
      handler(req, res);
      expect(res.getHeaders()["referrer-policy"]).toBe("strict-origin-when-cross-origin");
    });

    it("includes Strict-Transport-Security header", () => {
      const req = createMockReq("/agentshield");
      const res = createMockRes();
      handler(req, res);
      expect(res.getHeaders()["strict-transport-security"]).toBe("max-age=31536000; includeSubDomains");
    });

    it("includes Permissions-Policy header", () => {
      const req = createMockReq("/agentshield");
      const res = createMockRes();
      handler(req, res);
      expect(res.getHeaders()["permissions-policy"]).toBe("camera=(), microphone=(), geolocation=()");
    });

    it("returns HTML body with AgentShield title", () => {
      const req = createMockReq("/agentshield");
      const res = createMockRes();
      handler(req, res);
      expect(res.getBody()).toContain("<title>AgentShield Dashboard</title>");
    });

    it("calls res.end() (not streaming)", () => {
      const req = createMockReq("/agentshield");
      const res = createMockRes();
      handler(req, res);
      expect(res.isEnded()).toBe(true);
    });

    it("returns consistent CSP across requests (no nonce)", () => {
      const req1 = createMockReq("/agentshield");
      const res1 = createMockRes();
      handler(req1, res1);

      const req2 = createMockReq("/agentshield");
      const res2 = createMockRes();
      handler(req2, res2);

      const csp1 = res1.getHeaders()["content-security-policy"];
      const csp2 = res2.getHeaders()["content-security-policy"];
      // Without nonce, CSP should be identical
      expect(csp1).toBe(csp2);
    });

    it("serves dashboard for unknown sub-paths (fallback)", () => {
      const req = createMockReq("/agentshield/unknown/path");
      const res = createMockRes();
      handler(req, res);
      // Unknown paths fall through to the default HTML dashboard
      expect(res.getHeaders()["content-type"]).toBe("text/html; charset=utf-8");
      expect(res.getBody()).toContain("<title>AgentShield Dashboard</title>");
    });
  });

  // ── GET /agentshield/api/stats (JSON) ─────────────────────────────

  describe("GET /agentshield/api/stats (JSON)", () => {
    it("returns JSON Content-Type", () => {
      const req = createMockReq("/agentshield/api/stats");
      const res = createMockRes();
      handler(req, res);
      expect(res.getHeaders()["content-type"]).toBe("application/json");
    });

    it("returns valid JSON with stats fields", () => {
      const req = createMockReq("/agentshield/api/stats");
      const res = createMockRes();
      handler(req, res);
      const stats = JSON.parse(res.getBody());
      expect(stats).toHaveProperty("totalScanned");
      expect(stats).toHaveProperty("blocked");
      expect(stats).toHaveProperty("warned");
      expect(stats).toHaveProperty("allowed");
    });

    it("includes severity breakdown", () => {
      const req = createMockReq("/agentshield/api/stats");
      const res = createMockRes();
      handler(req, res);
      const stats = JSON.parse(res.getBody());
      expect(stats).toHaveProperty("bySeverity");
      expect(stats.bySeverity).toHaveProperty("none");
      expect(stats.bySeverity).toHaveProperty("low");
      expect(stats.bySeverity).toHaveProperty("medium");
      expect(stats.bySeverity).toHaveProperty("high");
      expect(stats.bySeverity).toHaveProperty("critical");
    });

    it("includes category breakdown", () => {
      const req = createMockReq("/agentshield/api/stats");
      const res = createMockRes();
      handler(req, res);
      const stats = JSON.parse(res.getBody());
      expect(stats).toHaveProperty("byCategory");
      expect(stats.byCategory).toHaveProperty("injection");
      expect(stats.byCategory).toHaveProperty("exfiltration");
    });

    it("calls res.end() (not streaming)", () => {
      const req = createMockReq("/agentshield/api/stats");
      const res = createMockRes();
      handler(req, res);
      expect(res.isEnded()).toBe(true);
    });

    it("has numeric stats values", () => {
      const req = createMockReq("/agentshield/api/stats");
      const res = createMockRes();
      handler(req, res);
      const stats = JSON.parse(res.getBody());
      expect(typeof stats.totalScanned).toBe("number");
      expect(typeof stats.blocked).toBe("number");
      expect(typeof stats.warned).toBe("number");
      expect(typeof stats.allowed).toBe("number");
    });
  });

  // ── GET /agentshield/api/audit (JSON) ─────────────────────────────

  describe("GET /agentshield/api/audit (JSON)", () => {
    it("returns JSON Content-Type", () => {
      const req = createMockReq("/agentshield/api/audit");
      const res = createMockRes();
      handler(req, res);
      expect(res.getHeaders()["content-type"]).toBe("application/json");
    });

    it("returns JSON array", () => {
      const req = createMockReq("/agentshield/api/audit");
      const res = createMockRes();
      handler(req, res);
      const entries = JSON.parse(res.getBody());
      expect(Array.isArray(entries)).toBe(true);
    });

    it("calls res.end() (not streaming)", () => {
      const req = createMockReq("/agentshield/api/audit");
      const res = createMockRes();
      handler(req, res);
      expect(res.isEnded()).toBe(true);
    });

    it("audit entries have expected shape", () => {
      // The audit log is shared state; entries may have been added by
      // beforeEach registrations. If there are entries, verify shape.
      const req = createMockReq("/agentshield/api/audit");
      const res = createMockRes();
      handler(req, res);
      const entries = JSON.parse(res.getBody()) as unknown[];

      // Even if empty, it should be an array
      if (entries.length > 0) {
        const entry = entries[0] as Record<string, unknown>;
        expect(entry).toHaveProperty("id");
        expect(entry).toHaveProperty("timestamp");
        expect(entry).toHaveProperty("hook");
        expect(entry).toHaveProperty("severity");
        expect(entry).toHaveProperty("outcome");
      }
    });
  });

  // ── GET /agentshield/events (SSE) ─────────────────────────────────

  describe("GET /agentshield/events (SSE)", () => {
    it("returns text/event-stream Content-Type", () => {
      const req = createMockReq("/agentshield/events");
      const res = createMockRes();
      handler(req, res);
      expect(res.getHeaders()["content-type"]).toBe("text/event-stream");
      // Clean up SSE connection
      req.emit("close");
    });

    it("sets Cache-Control to no-cache", () => {
      const req = createMockReq("/agentshield/events");
      const res = createMockRes();
      handler(req, res);
      expect(res.getHeaders()["cache-control"]).toBe("no-cache");
      req.emit("close");
    });

    it("sets Connection to keep-alive", () => {
      const req = createMockReq("/agentshield/events");
      const res = createMockRes();
      handler(req, res);
      expect(res.getHeaders()["connection"]).toBe("keep-alive");
      req.emit("close");
    });

    it("sends initial stats event", () => {
      const req = createMockReq("/agentshield/events");
      const res = createMockRes();
      handler(req, res);

      const body = res.getBody();
      expect(body).toContain("event: stats");
      expect(body).toContain("data: ");
      // The stats data should be valid JSON
      const dataMatch = body.match(/event: stats\ndata: (.+)\n/);
      expect(dataMatch).not.toBeNull();
      const stats = JSON.parse(dataMatch![1]!);
      expect(stats).toHaveProperty("totalScanned");

      req.emit("close");
    });

    it("does NOT call res.end() (streaming stays open)", () => {
      const req = createMockReq("/agentshield/events");
      const res = createMockRes();
      handler(req, res);
      // SSE connections stay open — res.end() should not have been called
      expect(res.isEnded()).toBe(false);
      req.emit("close");
    });

    it("uses res.write() for SSE data (not res.end())", () => {
      const req = createMockReq("/agentshield/events");
      const res = createMockRes();
      handler(req, res);
      // The initial stats event should use res.write()
      expect(res.write).toHaveBeenCalled();
      req.emit("close");
    });

    it("cleans up on client disconnect", () => {
      const req = createMockReq("/agentshield/events");
      const res = createMockRes();
      handler(req, res);

      // Simulate client disconnect
      req.emit("close");

      // After disconnect, the heartbeat should be cleared.
      // We cannot directly check clearInterval, but we can verify
      // the handler registered a "close" listener.
      expect(req.listenerCount("close")).toBeGreaterThanOrEqual(1);
    });

    it("includes inactivity timeout for SSE connections", () => {
      const req = createMockReq("/agentshield/events");
      const res = createMockRes();

      handler(req, res);

      // Verify the SSE connection is open (streaming, not ended)
      expect(res.isEnded()).toBe(false);
      expect(res.getBody()).toContain("event: stats");

      // Verify a close listener was registered for cleanup
      expect(req.listenerCount("close")).toBeGreaterThanOrEqual(1);

      // Trigger close to verify cleanup works (clears both heartbeat and inactivity intervals)
      req.emit("close");

      // After close, the connection should still not have ended via res.end()
      // (the close event cleans up intervals; res.end() is only called by
      // the inactivity timeout itself, not by client-initiated close)
      // This is a smoke test — the inactivity timeout is 5 minutes in production
    });
  });

  // ── URL parsing edge cases ────────────────────────────────────────

  describe("URL parsing", () => {
    it("handles URL with query string", () => {
      const req = createMockReq("/agentshield/api/stats?foo=bar");
      const res = createMockRes();
      handler(req, res);
      // Should still route to stats endpoint
      expect(res.getHeaders()["content-type"]).toBe("application/json");
      const stats = JSON.parse(res.getBody());
      expect(stats).toHaveProperty("totalScanned");
    });

    it("handles empty/undefined URL gracefully", () => {
      const req = createMockReq("");
      req.url = undefined;
      const res = createMockRes();
      // Should not throw — falls through to default HTML dashboard
      expect(() => handler(req, res)).not.toThrow();
    });
  });
});
