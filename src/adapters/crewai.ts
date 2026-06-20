/**
 * @packageDocumentation
 * @module CrewAIAdapter
 * @description
 * Security adapter for CrewAI agents.
 * Provides pre/post execution hooks that integrate with CrewAI's
 * tool execution and task lifecycle.
 *
 * Usage:
 * ```ts
 * import { SecurityGateway } from '@veridex/agent-security';
 * import { VeridexCrewAIGuard } from '@veridex/agent-security/adapters/crewai';
 *
 * const guard = new VeridexCrewAIGuard({
 *   gateway: new SecurityGateway(),
 *   crewId: 'my-crew',
 * });
 *
 * // Before a crew agent executes a tool
 * const result = await guard.beforeToolExecution({
 *   agentRole: 'Researcher',
 *   toolName: 'web_search',
 *   toolArgs: { query: 'latest news' },
 * });
 *
 * if (result.blocked) throw new Error(result.reason);
 * ```
 */

import type { SecurityGateway } from '../gateway';
import type { SecurityClient } from '../client';
import type { SecurityEvalResult, AgentIdentity } from '../types';

export interface CrewAIGuardConfig {
  /** Local gateway instance. */
  gateway?: SecurityGateway;
  /** Remote client. */
  client?: SecurityClient;
  /** Crew identifier. */
  crewId: string;
  /** Action on block (default: 'throw'). */
  onBlock?: 'throw' | 'log' | 'callback';
  /** Block callback. */
  blockCallback?: (result: SecurityEvalResult, context: CrewAIActionContext) => void | Promise<void>;
}

export interface CrewAIActionContext {
  agentRole: string;
  toolName: string;
  toolArgs: Record<string, unknown>;
  taskDescription?: string;
}

export interface CrewAIGuardResult {
  allowed: boolean;
  blocked: boolean;
  verdict: string;
  reasons: string[];
  riskScore: number;
  raw: SecurityEvalResult;
}

export class VeridexCrewAIGuard {
  private config: CrewAIGuardConfig;

  constructor(config: CrewAIGuardConfig) {
    if (!config.gateway && !config.client) {
      throw new Error('Either gateway or client must be provided');
    }
    this.config = config;
  }

  private agentFromRole(role: string): AgentIdentity {
    return {
      agentId: `${this.config.crewId}:${role}`,
      name: role,
      framework: 'crewai',
      metadata: { crewId: this.config.crewId },
    };
  }

  private async evalAndHandle(ctx: Parameters<SecurityGateway['evaluate']>[0], actionCtx: CrewAIActionContext): Promise<CrewAIGuardResult> {
    let result: SecurityEvalResult;
    if (this.config.gateway) {
      result = await this.config.gateway.evaluate(ctx);
    } else {
      result = await this.config.client?.evaluate(ctx);
    }

    const blocked = result.verdict === 'block';

    if (blocked && this.config.onBlock === 'throw') {
      throw new Error(`[VeridexSecurity] CrewAI action blocked for ${actionCtx.agentRole}: ${result.reasons.join('; ')}`);
    }
    if (blocked && this.config.onBlock === 'callback' && this.config.blockCallback) {
      await this.config.blockCallback(result, actionCtx);
    }

    return {
      allowed: !blocked,
      blocked,
      verdict: result.verdict,
      reasons: result.reasons,
      riskScore: result.riskScore,
      raw: result,
    };
  }

  /**
   * Check a CrewAI agent's tool execution before it runs.
   */
  async beforeToolExecution(ctx: CrewAIActionContext): Promise<CrewAIGuardResult> {
    return this.evalAndHandle({
      agent: this.agentFromRole(ctx.agentRole),
      action: {
        type: 'tool_call',
        toolCalls: [{ name: ctx.toolName, arguments: ctx.toolArgs }],
        content: JSON.stringify(ctx.toolArgs),
      },
    }, ctx);
  }

  /**
   * Scan a CrewAI agent's LLM output.
   */
  async afterAgentThink(agentRole: string, thought: string): Promise<CrewAIGuardResult> {
    const dummy: CrewAIActionContext = { agentRole, toolName: 'llm_think', toolArgs: {} };
    return this.evalAndHandle({
      agent: this.agentFromRole(agentRole),
      action: {
        type: 'llm_call',
        content: thought,
      },
    }, dummy);
  }

  /**
   * Check a delegation (handoff) between CrewAI agents.
   */
  async beforeDelegation(fromRole: string, toRole: string, taskDescription: string): Promise<CrewAIGuardResult> {
    const ctx: CrewAIActionContext = {
      agentRole: fromRole,
      toolName: 'delegate',
      toolArgs: { toRole, taskDescription },
    };
    return this.evalAndHandle({
      agent: this.agentFromRole(fromRole),
      action: {
        type: 'handoff',
        targetAgentId: `${this.config.crewId}:${toRole}`,
        content: taskDescription,
      },
    }, ctx);
  }
}
