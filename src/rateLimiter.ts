/**
 * @module rateLimiter
 * @description
 * Per-tenant / per-agent token-bucket rate limiter used as a pre-check inside
 * the `SecurityGateway`.
 *
 * Why in the gateway and not in a pack?
 *   • Rate limiting is a **structural** defence, not a content-scan pack.
 *     It should run BEFORE any pack evaluation — no point spending CPU on a
 *     compromised agent that is hammering us at 10k req/s.
 *   • It's the only gateway-level response that is cheap to compute and
 *     deterministic enough to short-circuit the evaluation pipeline.
 *
 * Token-bucket semantics:
 *   • Each bucket has `capacity` tokens; every call to `consume()` takes 1.
 *   • Tokens refill at `refillPerSecond` with fractional accumulation, so a
 *     burst of `capacity` is allowed but sustained throughput is capped.
 *   • Once the bucket is empty, subsequent calls are rejected until refill.
 *
 * Keying:
 *   • Default key = `tenantId` if present, else `agentId`.
 *   • Callers can override via `keyFn`.
 *
 * Bucket lifecycle:
 *   • Stored in an in-memory Map. This is intentional — the gateway is an
 *     in-process component. For cross-process sharing, callers plug in a
 *     Redis-backed limiter via the abstract `RateLimiter` interface.
 *   • An optional `maxBuckets` bound prevents unbounded memory growth when
 *     many unique tenants appear; oldest-accessed buckets are evicted.
 */

/** Result of a rate-limit consume attempt. */
export interface RateLimitDecision {
  /** True when the caller may proceed. */
  allowed: boolean;
  /** Remaining tokens (post-decrement if allowed). */
  remaining: number;
  /** Bucket capacity (reported back for observability). */
  capacity: number;
  /** If denied, seconds until at least 1 token is available again. */
  retryAfterSeconds?: number;
}

/** Abstract rate limiter — lets consumers swap in Redis/memcached backends. */
export interface RateLimiter {
  consume(key: string, cost?: number): RateLimitDecision | Promise<RateLimitDecision>;
}

/** Config for the in-memory token-bucket limiter. */
export interface TokenBucketConfig {
  /** Tokens a bucket holds when full (burst size). */
  capacity: number;
  /** Tokens added per second. Must be > 0. */
  refillPerSecond: number;
  /** Maximum distinct buckets retained in memory. Default 10 000. */
  maxBuckets?: number;
  /** Injected clock (ms) — for deterministic tests. Default `Date.now`. */
  now?: () => number;
}

interface BucketState {
  tokens: number;
  lastRefillMs: number;
  lastAccessMs: number;
}

export class TokenBucketRateLimiter implements RateLimiter {
  private readonly config: Required<Omit<TokenBucketConfig, 'now'>> & { now: () => number };
  private readonly buckets = new Map<string, BucketState>();

  constructor(config: TokenBucketConfig) {
    if (!Number.isFinite(config.capacity) || config.capacity <= 0) {
      throw new Error('TokenBucketRateLimiter: capacity must be a positive number');
    }
    if (!Number.isFinite(config.refillPerSecond) || config.refillPerSecond <= 0) {
      throw new Error('TokenBucketRateLimiter: refillPerSecond must be a positive number');
    }
    this.config = {
      capacity: config.capacity,
      refillPerSecond: config.refillPerSecond,
      maxBuckets: config.maxBuckets ?? 10_000,
      now: config.now ?? (() => Date.now()),
    };
  }

  consume(key: string, cost = 1): RateLimitDecision {
    if (cost <= 0) {
      return { allowed: true, remaining: this.config.capacity, capacity: this.config.capacity };
    }

    const now = this.config.now();
    let state = this.buckets.get(key);
    if (!state) {
      state = { tokens: this.config.capacity, lastRefillMs: now, lastAccessMs: now };
      this.evictIfNeeded();
      this.buckets.set(key, state);
    } else {
      // Refill based on elapsed time.
      const elapsedSec = Math.max(0, (now - state.lastRefillMs) / 1000);
      if (elapsedSec > 0) {
        state.tokens = Math.min(
          this.config.capacity,
          state.tokens + elapsedSec * this.config.refillPerSecond,
        );
        state.lastRefillMs = now;
      }
      state.lastAccessMs = now;
    }

    if (state.tokens >= cost) {
      state.tokens -= cost;
      return {
        allowed: true,
        remaining: Math.floor(state.tokens),
        capacity: this.config.capacity,
      };
    }

    const deficit = cost - state.tokens;
    const retryAfterSeconds = deficit / this.config.refillPerSecond;
    return {
      allowed: false,
      remaining: Math.floor(state.tokens),
      capacity: this.config.capacity,
      retryAfterSeconds,
    };
  }

  /** Testing / observability helper. */
  getBucketCount(): number {
    return this.buckets.size;
  }

  /** Reset all buckets — useful in tests. */
  reset(): void {
    this.buckets.clear();
  }

  private evictIfNeeded(): void {
    if (this.buckets.size < this.config.maxBuckets) return;
    // Evict the least-recently accessed bucket. O(n) but only runs when the
    // map is at the cap, which is configured to a reasonable upper bound.
    let oldestKey: string | null = null;
    let oldestAccess = Infinity;
    for (const [k, v] of this.buckets) {
      if (v.lastAccessMs < oldestAccess) {
        oldestAccess = v.lastAccessMs;
        oldestKey = k;
      }
    }
    if (oldestKey !== null) this.buckets.delete(oldestKey);
  }
}
