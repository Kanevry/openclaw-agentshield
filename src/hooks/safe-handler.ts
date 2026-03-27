/**
 * Safe Handler Wrapper — Fail-Open Protection
 *
 * Every hook handler MUST be wrapped in this to prevent gateway crashes.
 * On error: logs the error, returns undefined (fail-open = allow).
 *
 * @example
 * api.on("before_tool_call", safeHandler("before_tool_call", (event, ctx) => {
 *   // ... handler logic
 * }));
 */

export function safeHandler<TEvent, TCtx, TResult>(
  hookName: string,
  handler: (event: TEvent, ctx: TCtx) => TResult,
): (event: TEvent, ctx: TCtx) => TResult | undefined {
  return (event: TEvent, ctx: TCtx): TResult | undefined => {
    try {
      return handler(event, ctx);
    } catch (err) {
      console.error(
        `[AgentShield] Error in ${hookName} hook:`,
        err instanceof Error ? err.message : err,
      );
      return undefined; // fail-open: allow the request through
    }
  };
}
