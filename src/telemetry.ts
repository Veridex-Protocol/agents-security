/**
 * @packageDocumentation
 * @module TelemetryReporter
 * @description
 * Reports security evaluation events to the Veridex platform.
 *
 * When external agents use @veridex/agent-security, every evaluation
 * automatically appears in the enterprise/developer portal — providing
 * unified visibility across ALL agents (SDK and non-SDK).
 *
 * Events are batched and flushed asynchronously to minimize latency impact.
 * The reporter never throws — all errors are silently swallowed to avoid
 * disrupting the agent's execution path.
 *
 * Usage:
 * ```ts
 * import { SecurityGateway } from '@veridex/agent-security';
 * import { TelemetryReporter } from '@veridex/agent-security';
 *
 * const reporter = new TelemetryReporter({
 *   platformUrl: 'https://relayer.veridex.network',
 *   licenseKey: 'vdx_live_...',
 * });
 *
 * const gateway = new SecurityGateway();
 * // Attach reporter to auto-report all evaluations
 * gateway.onEvaluate((ctx, result) => reporter.report(ctx, result));
 * ```
 */

import type {
  SecurityEvalContext,
  SecurityEvalResult,
  SecurityTelemetryEvent,
  TelemetryReporterConfig,
} from './types';

export class TelemetryReporter {
  private config: Required<TelemetryReporterConfig>;
  private buffer: SecurityTelemetryEvent[] = [];
  private timer: ReturnType<typeof setInterval> | null = null;
  private flushing = false;

  constructor(config: TelemetryReporterConfig) {
    this.config = {
      platformUrl: config.platformUrl.replace(/\/+$/, ''),
      licenseKey: config.licenseKey,
      appId: config.appId,
      tenantId: config.tenantId ?? '',
      batchSize: config.batchSize ?? 25,
      flushIntervalMs: config.flushIntervalMs ?? 10_000,
      enabled: config.enabled ?? true,
    };

    if (this.config.enabled) {
      this.timer = setInterval(() => this.flush(), this.config.flushIntervalMs);
      // Unref so it doesn't keep the process alive
      if (typeof this.timer === 'object' && 'unref' in this.timer) {
        (this.timer as NodeJS.Timeout).unref();
      }
    }
  }

  /**
   * Report a security evaluation. Call after every gateway.evaluate().
   * Non-blocking — events are buffered and flushed in batches.
   */
  report(ctx: SecurityEvalContext, result: SecurityEvalResult): void {
    if (!this.config.enabled) return;

    const event: SecurityTelemetryEvent = {
      eventId: this.generateId(),
      timestamp: new Date(result.evaluatedAt).toISOString(),
      agent: ctx.agent,
      actionType: ctx.action.type,
      verdict: result.verdict,
      riskScore: result.riskScore,
      reasons: result.reasons,
      packsEvaluated: result.packsEvaluated,
      checksRun: result.checks.length,
      checksFailed: result.checks.filter((c) => !c.passed).length,
      durationMs: result.durationMs,
      licenseKey: this.config.licenseKey,
    };

    this.buffer.push(event);

    if (this.buffer.length >= this.config.batchSize) {
      this.flush();
    }
  }

  /**
   * Flush buffered events to the platform.
   * Called automatically on interval and when batch size is reached.
   */
  async flush(): Promise<void> {
    if (!this.config.enabled || this.buffer.length === 0 || this.flushing) return;

    this.flushing = true;
    const batch = this.buffer.splice(0, this.config.batchSize);

    try {
      await fetch(`${this.config.platformUrl}/apps/${encodeURIComponent(this.config.appId)}/security/events/ingest`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'x-license-key': this.config.licenseKey,
          ...(this.config.tenantId ? { 'x-tenant-id': this.config.tenantId } : {}),
        },
        body: JSON.stringify({ events: batch }),
        signal: AbortSignal.timeout(5000),
      });
    } catch {
      // Silently drop — telemetry must never block the agent
      // Put events back if we want retry (optional; for now, drop)
    } finally {
      this.flushing = false;
    }
  }

  /**
   * Shutdown the reporter. Flushes remaining events.
   */
  async shutdown(): Promise<void> {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
    await this.flush();
  }

  private generateId(): string {
    // Compact sortable ID: timestamp hex + random suffix
    const ts = Date.now().toString(36);
    const rand = Math.random().toString(36).slice(2, 8);
    return `sec_${ts}_${rand}`;
  }
}
