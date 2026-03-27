/**
 * Retry with Exponential Backoff + Jitter
 *
 * Origin: BitGN PAC Agent
 * Adapted: Removed ConnectRPC dependency, generic error detection
 *
 * Pure functions — no external dependencies.
 */

export interface RetryOptions {
  maxRetries?: number;
  baseDelay?: number;
  maxDelay?: number;
  retryOn?: (err: unknown) => boolean;
}

const TRANSIENT_PATTERNS = [
  "429",
  "rate limit",
  "timeout",
  "econnreset",
  "etimedout",
  "econnrefused",
  "fetch failed",
  "network error",
  "socket hang up",
];

export function isTransientError(err: unknown): boolean {
  const message =
    err instanceof Error ? err.message : typeof err === "string" ? err : "";
  return TRANSIENT_PATTERNS.some((p) => message.toLowerCase().includes(p));
}

function jitter(delay: number): number {
  const factor = 0.9 + Math.random() * 0.2; // +/-10%
  return Math.round(delay * factor);
}

export async function withRetry<T>(
  fn: () => Promise<T>,
  opts?: RetryOptions,
): Promise<T> {
  const maxRetries = opts?.maxRetries ?? 3;
  const baseDelay = opts?.baseDelay ?? 200;
  const maxDelay = opts?.maxDelay ?? 5000;
  const shouldRetry = opts?.retryOn ?? isTransientError;

  let lastError: unknown;

  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastError = err;

      if (attempt >= maxRetries || !shouldRetry(err)) {
        throw err;
      }

      const delay = jitter(Math.min(baseDelay * 2 ** attempt, maxDelay));
      await new Promise((resolve) => setTimeout(resolve, delay));
    }
  }

  throw lastError;
}
