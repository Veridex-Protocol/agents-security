/**
 * @packageDocumentation
 * @module SecurityClient
 * @description
 * Lightweight HTTP client for the Veridex Security Gateway.
 * Zero dependencies — uses native fetch.
 *
 * Usage:
 * ```ts
 * import { SecurityClient } from '@veridex/agent-security';
 *
 * const client = new SecurityClient({
 *   gatewayUrl: 'http://localhost:3100',
 *   apiKey: 'my-key',
 *   defaultAgent: { agentId: 'my-agent', framework: 'langchain' },
 * });
 *
 * // Before executing a tool call
 * const result = await client.checkToolCall('bash', { command: 'ls' });
 * if (result.verdict === 'block') throw new Error(result.reasons[0]);
 *
 * // Before sending money
 * const payment = await client.checkPayment(500, 'ethereum');
 * if (payment.verdict !== 'pass') console.warn('Payment flagged');
 * ```
 */

import type {
  SecurityClientConfig,
  SecurityEvalContext,
  SecurityEvalResult,
  ContentScanResult,
  AgentIdentity,
  SecurityAction,
} from './types';

export class SecurityClient {
  private config: SecurityClientConfig;

  constructor(config: SecurityClientConfig) {
    this.config = config;
  }

  private get baseUrl(): string {
    return this.config.gatewayUrl.replace(/\/+$/, '');
  }

  private get headers(): Record<string, string> {
    return {
      'Content-Type': 'application/json',
      'x-api-key': this.config.apiKey,
    };
  }

  private agent(override?: AgentIdentity): AgentIdentity {
    return override ?? this.config.defaultAgent ?? { agentId: 'unknown' };
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs ?? 10_000);

    try {
      const res = await fetch(`${this.baseUrl}${path}`, {
        method: 'POST',
        headers: this.headers,
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      if (!res.ok) {
        const text = await res.text();
        throw new Error(`Security gateway error (${res.status}): ${text}`);
      }

      return await res.json() as T;
    } finally {
      clearTimeout(timeout);
    }
  }

  private async get<T>(path: string): Promise<T> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      method: 'GET',
      headers: this.headers,
    });
    if (!res.ok) throw new Error(`Security gateway error (${res.status})`);
    return await res.json() as T;
  }

  // ── Core ──

  /** Full security evaluation. */
  async evaluate(ctx: SecurityEvalContext): Promise<SecurityEvalResult> {
    return this.post('/v1/evaluate', ctx);
  }

  /** Evaluate an action using the default agent identity. */
  async evaluateAction(action: SecurityAction, opts?: {
    runId?: string;
    turnIndex?: number;
    runSpendUsd?: number;
    totalTokens?: number;
  }): Promise<SecurityEvalResult> {
    return this.evaluate({
      agent: this.agent(),
      action,
      ...opts,
    });
  }

  // ── Quick checks ──

  /** Scan content for injections and secrets. */
  async scanContent(content: string, contentType?: 'prompt' | 'response' | 'tool_output'): Promise<ContentScanResult> {
    return this.post('/v1/scan/content', {
      agent: this.agent(),
      content,
      contentType,
    });
  }

  /** Check if a tool call is safe. */
  async checkToolCall(
    toolName: string,
    args: Record<string, unknown>,
    description?: string,
  ): Promise<SecurityEvalResult> {
    return this.post('/v1/scan/tool-call', {
      agent: this.agent(),
      toolName,
      arguments: args,
      description,
    });
  }

  /** Check if a payment is safe. */
  async checkPayment(
    amountUsd: number,
    chain?: string,
    targetAddress?: string,
  ): Promise<SecurityEvalResult> {
    return this.post('/v1/scan/payment', {
      agent: this.agent(),
      amountUsd,
      chain,
      targetAddress,
    });
  }

  // ── Pack Management ──

  /** List all registered packs on the gateway. */
  async listPacks(): Promise<Array<{ id: string; name: string; enabled: boolean }>> {
    const data = await this.get<{ packs: Array<{ id: string; name: string; enabled: boolean }> }>('/v1/packs');
    return data.packs;
  }

  /** Toggle a pack on the gateway. */
  async togglePack(packId: string, enabled: boolean): Promise<void> {
    await this.post(`/v1/packs/${encodeURIComponent(packId)}/toggle`, { enabled });
  }

  // ── Health ──

  /** Check gateway health. */
  async health(): Promise<{ status: string; packs: number; version: string }> {
    return this.get('/v1/health');
  }
}
