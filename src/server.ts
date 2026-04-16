/**
 * @packageDocumentation
 * @module SecurityGatewayServer
 * @description
 * HTTP server that exposes the SecurityGateway as a REST API.
 * Any agent framework can call this over HTTP — zero SDK dependency.
 *
 * Deploy this as a sidecar, standalone service, or use the built-in Hono app.
 *
 * Endpoints:
 * - POST /v1/evaluate          Full security evaluation
 * - POST /v1/scan/content      Quick content scan (injection + secrets)
 * - POST /v1/scan/tool-call    Quick tool call check
 * - POST /v1/scan/payment      Quick payment check
 * - GET  /v1/packs             List registered security packs
 * - POST /v1/packs/:id/toggle  Enable/disable a pack
 * - GET  /v1/health            Health check
 */

import { SecurityGateway } from './gateway';
import type {
  SecurityEvalContext,
  SecurityGatewayConfig,
  ContentScanRequest,
  AgentIdentity,
} from './types';

export interface SecurityServerConfig extends SecurityGatewayConfig {
  /** Port to listen on (default: 3100) */
  port?: number;
  /** API key for authenticating incoming requests (required in production) */
  apiKeys?: string[];
  /** Enable CORS (default: true) */
  cors?: boolean;
}

/**
 * Create a Hono app that serves the Security Gateway REST API.
 * Can be used standalone or mounted into an existing Hono app.
 */
export function createSecurityGatewayApp(config?: SecurityServerConfig) {
  // Dynamic import pattern to keep hono as optional peer dep
  // eslint-disable-next-line @typescript-eslint/no-var-requires
  const { Hono } = require('hono') as typeof import('hono');

  const app = new Hono();
  const gateway = new SecurityGateway(config);
  const apiKeys = new Set(config?.apiKeys ?? []);

  // ── Auth Middleware ──
  app.use('/v1/*', async (c: any, next: any) => {
    if (apiKeys.size === 0) {
      return c.json({ error: 'Security gateway not configured — apiKeys required' }, 503);
    }
    const key = c.req.header('x-api-key') ?? c.req.header('authorization')?.replace('Bearer ', '');
    if (!key || !apiKeys.has(key)) {
      return c.json({ error: 'Unauthorized — provide x-api-key header' }, 401);
    }
    return next();
  });

  // ── Health ──
  app.get('/v1/health', (c: any) => c.json({
    status: 'ok',
    packs: gateway.packCount,
    version: '0.1.0',
  }));

  // ── Full Evaluation ──
  app.post('/v1/evaluate', async (c: any) => {
    try {
      const body = await c.req.json() as SecurityEvalContext;
      if (!body.agent?.agentId) {
        return c.json({ error: 'agent.agentId is required' }, 400);
      }
      if (!body.action?.type) {
        return c.json({ error: 'action.type is required' }, 400);
      }
      const result = await gateway.evaluate(body);
      return c.json(result);
    } catch (err) {
      return c.json({ error: err instanceof Error ? err.message : 'Evaluation failed' }, 500);
    }
  });

  // ── Quick Content Scan ──
  app.post('/v1/scan/content', async (c: any) => {
    try {
      const body = await c.req.json() as ContentScanRequest;
      if (!body.agent?.agentId || !body.content) {
        return c.json({ error: 'agent.agentId and content are required' }, 400);
      }
      const result = await gateway.scanContent(body);
      return c.json(result);
    } catch (err) {
      return c.json({ error: err instanceof Error ? err.message : 'Scan failed' }, 500);
    }
  });

  // ── Quick Tool Call Check ──
  app.post('/v1/scan/tool-call', async (c: any) => {
    try {
      const body = await c.req.json() as {
        agent: AgentIdentity;
        toolName: string;
        arguments: Record<string, unknown>;
        description?: string;
      };
      if (!body.agent?.agentId || !body.toolName) {
        return c.json({ error: 'agent.agentId and toolName are required' }, 400);
      }
      const result = await gateway.checkToolCall(
        body.agent, body.toolName, body.arguments ?? {}, body.description);
      return c.json(result);
    } catch (err) {
      return c.json({ error: err instanceof Error ? err.message : 'Check failed' }, 500);
    }
  });

  // ── Quick Payment Check ──
  app.post('/v1/scan/payment', async (c: any) => {
    try {
      const body = await c.req.json() as {
        agent: AgentIdentity;
        amountUsd: number;
        chain?: string;
        targetAddress?: string;
      };
      if (!body.agent?.agentId || body.amountUsd == null) {
        return c.json({ error: 'agent.agentId and amountUsd are required' }, 400);
      }
      const result = await gateway.checkPayment(
        body.agent, body.amountUsd, body.chain, body.targetAddress);
      return c.json(result);
    } catch (err) {
      return c.json({ error: err instanceof Error ? err.message : 'Check failed' }, 500);
    }
  });

  // ── Pack Management ──
  app.get('/v1/packs', (c: any) => c.json({ packs: gateway.listPacks() }));

  app.post('/v1/packs/:id/toggle', async (c: any) => {
    try {
      const packId = c.req.param('id');
      const body = await c.req.json() as { enabled: boolean };
      const toggled = gateway.togglePack(packId, body.enabled);
      if (!toggled) return c.json({ error: 'Pack not found' }, 404);
      return c.json({ success: true, packId, enabled: body.enabled });
    } catch (err) {
      return c.json({ error: err instanceof Error ? err.message : 'Toggle failed' }, 500);
    }
  });

  return { app, gateway };
}

/**
 * Start a standalone Security Gateway HTTP server.
 *
 * ```ts
 * import { startSecurityGateway } from '@veridex/agent-security/server';
 *
 * await startSecurityGateway({ port: 3100, apiKeys: ['my-key'] });
 * ```
 */
export async function startSecurityGateway(config?: SecurityServerConfig): Promise<{
  gateway: SecurityGateway;
  close: () => void;
}> {
  const { app, gateway } = createSecurityGatewayApp(config);
  const port = config?.port ?? 3100;

  // Use Node.js built-in serve
  const { serve } = await import('@hono/node-server' as string);
  const server = serve({ fetch: app.fetch, port });

  return {
    gateway,
    close: () => {
      if (server && typeof (server as any).close === 'function') {
        (server as any).close();
      }
    },
  };
}
