/**
 * Circuit Breaker — Failure Protection for External Calls
 *
 * Origin: Clank Event Bus (production, 7 instances)
 * Adapted: Stripped Prometheus metrics + Clank logger dependency
 *
 * States: CLOSED (normal) -> OPEN (failing, fast-fail) -> HALF_OPEN (test one request)
 *
 * @example
 * const breaker = new CircuitBreaker({ name: "scanner" });
 * const result = await breaker.execute(() => scanDocument(doc));
 */

export type CircuitState = "closed" | "open" | "half_open";

export interface CircuitBreakerConfig {
  name: string;
  /** Consecutive failures before tripping to OPEN. Default: 5 */
  failureThreshold?: number;
  /** Ms before OPEN -> HALF_OPEN. Default: 60_000 */
  resetTimeoutMs?: number;
  /** Optional callback on state change. */
  onStateChange?: (name: string, from: CircuitState, to: CircuitState) => void;
  /** Optional callback when circuit trips. */
  onTrip?: (name: string) => void;
}

export class CircuitBreaker {
  readonly name: string;
  private state: CircuitState = "closed";
  private failureCount = 0;
  private readonly failureThreshold: number;
  private readonly resetTimeoutMs: number;
  private lastFailureTime = 0;
  private readonly onStateChange?: CircuitBreakerConfig["onStateChange"];
  private readonly onTrip?: CircuitBreakerConfig["onTrip"];

  constructor(config: CircuitBreakerConfig) {
    this.name = config.name;
    this.failureThreshold = config.failureThreshold ?? 5;
    this.resetTimeoutMs = config.resetTimeoutMs ?? 60_000;
    this.onStateChange = config.onStateChange;
    this.onTrip = config.onTrip;
  }

  async execute<T>(fn: () => Promise<T>): Promise<T> {
    if (!this.canExecute()) {
      throw new CircuitOpenError(this.name);
    }

    try {
      const result = await fn();
      this.recordSuccess();
      return result;
    } catch (err) {
      this.recordFailure();
      throw err;
    }
  }

  canExecute(): boolean {
    if (this.state === "closed") return true;

    if (this.state === "open") {
      const elapsed = Date.now() - this.lastFailureTime;
      if (elapsed >= this.resetTimeoutMs) {
        this.transition("half_open");
        return true;
      }
      return false;
    }

    return true; // half_open: allow one test request
  }

  recordSuccess(): void {
    if (this.state === "half_open") {
      this.transition("closed");
    }
    this.failureCount = 0;
  }

  recordFailure(): void {
    this.lastFailureTime = Date.now();
    this.failureCount++;

    if (this.state === "half_open") {
      this.transition("open");
      return;
    }

    if (this.state === "closed" && this.failureCount >= this.failureThreshold) {
      this.transition("open");
    }
  }

  getState(): CircuitState {
    if (this.state === "open") {
      const elapsed = Date.now() - this.lastFailureTime;
      if (elapsed >= this.resetTimeoutMs) {
        this.transition("half_open");
      }
    }
    return this.state;
  }

  getFailureCount(): number {
    return this.failureCount;
  }

  reset(): void {
    const prev = this.state;
    this.state = "closed";
    this.failureCount = 0;
    this.lastFailureTime = 0;
    if (prev !== "closed") {
      this.onStateChange?.(this.name, prev, "closed");
    }
  }

  private transition(newState: CircuitState): void {
    const prev = this.state;
    if (prev === newState) return;

    this.state = newState;
    this.onStateChange?.(this.name, prev, newState);

    if (newState === "open") {
      this.onTrip?.(this.name);
    }
  }
}

export class CircuitOpenError extends Error {
  readonly circuitName: string;

  constructor(circuitName: string) {
    super(`Circuit breaker [${circuitName}] is open — request rejected`);
    this.name = "CircuitOpenError";
    this.circuitName = circuitName;
  }
}
