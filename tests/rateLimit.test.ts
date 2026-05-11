/**
 * Tests for the rate-limit pre-check in SecurityGateway and for the
 * standalone TokenBucketRateLimiter.
 */

import { describe, it, expect, vi } from 'vitest';
import { SecurityGateway } from '../src/gateway';
import { TokenBucketRateLimiter, type RateLimiter } from '../src/rateLimiter';
import type { SecurityEvalContext } from '../src/types';

function mkCtx(agentId = 'agent-a', tenantId?: string): SecurityEvalContext {
  return {
    agent: { agentId, tenantId, framework: 'test' },
    action: { type: 'tool_call', toolCalls: [{ name: 'echo', arguments: { x: 1 } }] },
  };
}

describe('TokenBucketRateLimiter', () => {
  it('allows up to capacity then rejects', () => {
    let nowMs = 0;
    const rl = new TokenBucketRateLimiter({
      capacity: 3,
      refillPerSecond: 1,
      now: () => nowMs,
    });
    expect(rl.consume('k').allowed).toBe(true);
    expect(rl.consume('k').allowed).toBe(true);
    expect(rl.consume('k').allowed).toBe(true);
    const denied = rl.consume('k');
    expect(denied.allowed).toBe(false);
    expect(denied.retryAfterSeconds).toBeGreaterThan(0);
  });

  it('refills tokens over time', () => {
    let nowMs = 0;
    const rl = new TokenBucketRateLimiter({
      capacity: 2,
      refillPerSecond: 2, // 1 token per 500ms
      now: () => nowMs,
    });
    rl.consume('k');
    rl.consume('k');
    expect(rl.consume('k').allowed).toBe(false);
    nowMs += 500;
    expect(rl.consume('k').allowed).toBe(true);
  });

  it('isolates buckets by key', () => {
    const rl = new TokenBucketRateLimiter({ capacity: 1, refillPerSecond: 1 });
    expect(rl.consume('a').allowed).toBe(true);
    expect(rl.consume('a').allowed).toBe(false);
    expect(rl.consume('b').allowed).toBe(true); // different key still fresh
  });

  it('rejects invalid config', () => {
    expect(() => new TokenBucketRateLimiter({ capacity: 0, refillPerSecond: 1 })).toThrow();
    expect(() => new TokenBucketRateLimiter({ capacity: 1, refillPerSecond: 0 })).toThrow();
    expect(
      () => new TokenBucketRateLimiter({ capacity: NaN, refillPerSecond: 1 }),
    ).toThrow();
  });

  it('evicts LRU buckets when maxBuckets is exceeded', () => {
    let nowMs = 0;
    const rl = new TokenBucketRateLimiter({
      capacity: 1,
      refillPerSecond: 1,
      maxBuckets: 2,
      now: () => nowMs,
    });
    rl.consume('a'); nowMs += 10;
    rl.consume('b'); nowMs += 10;
    // Touch 'a' to keep it fresh.
    rl.consume('a'); nowMs += 10;
    // Inserting 'c' must evict 'b' (oldest lastAccess).
    rl.consume('c');
    expect(rl.getBucketCount()).toBe(2);
  });
});

describe('SecurityGateway rate-limit pre-check', () => {
  it('blocks when capacity is exhausted and returns the system:rate-limit check', async () => {
    const gateway = new SecurityGateway({
      rateLimit: { capacity: 2, refillPerSecond: 0.001, keyBy: 'tenant' },
    });

    const ctx = mkCtx('agent-1', 'tenant-x');
    // First 2 should go through pre-check (packs may still return verdicts but
    // for a benign tool_call with default packs we expect pass-ish).
    const first = await gateway.evaluate(ctx);
    expect(first.checks.some((c) => c.checkId === 'system:rate-limit')).toBe(false);
    await gateway.evaluate(ctx);

    // 3rd call — pre-check should block.
    const blocked = await gateway.evaluate(ctx);
    expect(blocked.verdict).toBe('block');
    expect(blocked.packsEvaluated).toEqual(['system:rate-limit']);
    expect(blocked.checks[0].checkId).toBe('system:rate-limit');
    expect(blocked.checks[0].metadata?.rateLimitKey).toBe('tenant:tenant-x');
  });

  it('keys by tenant by default — different tenants are independent', async () => {
    const gateway = new SecurityGateway({
      rateLimit: { capacity: 1, refillPerSecond: 0.001 },
    });
    const t1 = mkCtx('a1', 'tenant-one');
    const t2 = mkCtx('a2', 'tenant-two');

    await gateway.evaluate(t1);
    const t1Blocked = await gateway.evaluate(t1);
    expect(t1Blocked.verdict).toBe('block');

    // Different tenant — still fresh.
    const t2First = await gateway.evaluate(t2);
    expect(t2First.packsEvaluated).not.toEqual(['system:rate-limit']);
  });

  it("falls back to agentId when tenantId is missing", async () => {
    const gateway = new SecurityGateway({
      rateLimit: { capacity: 1, refillPerSecond: 0.001 },
    });
    const ctx = mkCtx('solo-agent'); // no tenantId
    await gateway.evaluate(ctx);
    const blocked = await gateway.evaluate(ctx);
    expect(blocked.verdict).toBe('block');
    expect(blocked.checks[0].metadata?.rateLimitKey).toBe('tenant:solo-agent');
  });

  it('keyBy="agent" keys strictly by agentId regardless of tenant', async () => {
    const gateway = new SecurityGateway({
      rateLimit: { capacity: 1, refillPerSecond: 0.001, keyBy: 'agent' },
    });
    const a = mkCtx('shared-agent', 'tenant-alpha');
    const b = mkCtx('shared-agent', 'tenant-beta');
    await gateway.evaluate(a);
    // Same agentId → shared bucket → blocked even from a different tenant.
    const blocked = await gateway.evaluate(b);
    expect(blocked.verdict).toBe('block');
    expect(blocked.checks[0].metadata?.rateLimitKey).toBe('agent:shared-agent');
  });

  it('custom rateLimiter injection overrides in-memory bucket', async () => {
    const fake: RateLimiter = {
      consume: vi.fn().mockResolvedValue({
        allowed: false,
        remaining: 0,
        capacity: 42,
        retryAfterSeconds: 7,
      }),
    };
    const gateway = new SecurityGateway({
      rateLimiter: { consume: fake.consume, keyFn: (ctx) => `custom:${ctx.agent.agentId}` },
    });

    const res = await gateway.evaluate(mkCtx('agent-x'));
    expect(res.verdict).toBe('block');
    expect(res.checks[0].checkId).toBe('system:rate-limit');
    expect(res.checks[0].metadata?.retryAfterSeconds).toBe(7);
    expect(res.checks[0].metadata?.capacity).toBe(42);
    expect(fake.consume).toHaveBeenCalledWith('custom:agent-x', 1);
  });

  it('no rateLimit config → no pre-check overhead', async () => {
    const gateway = new SecurityGateway();
    const res = await gateway.evaluate(mkCtx());
    // system:rate-limit must not appear anywhere.
    expect(res.packsEvaluated).not.toContain('system:rate-limit');
  });
});
