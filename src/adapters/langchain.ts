/**
 * @packageDocumentation
 * @module LangChainAdapter
 * @description
 * Drop-in security adapter for LangChain/LangGraph agents.
 * Wraps the Veridex SecurityGateway (local) or SecurityClient (remote)
 * to intercept tool calls, LLM calls, and chain outputs.
 *
 * Usage with local gateway:
 * ```ts
 * import { SecurityGateway } from '@veridex/agent-security';
 * import { VeridexLangChainGuard } from '@veridex/agent-security/adapters/langchain';
 *
 * const guard = new VeridexLangChainGuard({
 *   gateway: new SecurityGateway(),
 *   agentId: 'my-langchain-agent',
 * });
 *
 * // Before tool execution
 * const result = await guard.beforeToolCall('bash', { command: 'rm -rf /' });
 * if (result.blocked) throw new Error(result.reason);
 *
 * // Wrap an entire tool executor
 * const safeTool = guard.wrapTool(myTool);
 * ```
 *
 * Usage with remote gateway:
 * ```ts
 * import { SecurityClient } from '@veridex/agent-security';
 * import { VeridexLangChainGuard } from '@veridex/agent-security/adapters/langchain';
 *
 * const guard = new VeridexLangChainGuard({
 *   client: new SecurityClient({ gatewayUrl: 'http://localhost:3100', apiKey: 'key' }),
 *   agentId: 'my-langchain-agent',
 * });
 * ```
 */

import type { SecurityGateway } from '../gateway';
import type { SecurityClient } from '../client';
import type { SecurityEvalResult, AgentIdentity } from '../types';

export interface LangChainGuardConfig {
  /** Local gateway instance (preferred for latency). */
  gateway?: SecurityGateway;
  /** Remote client (for multi-service deployments). */
  client?: SecurityClient;
  /** Agent identifier. */
  agentId: string;
  /** Agent name (optional). */
  agentName?: string;
  /** Action to take on block (default: 'throw'). */
  onBlock?: 'throw' | 'log' | 'callback';
  /** Callback when block action is 'callback'. */
  blockCallback?: (result: SecurityEvalResult) => void | Promise<void>;
}

/** Result from a guard check — simplified for framework consumption. */
export interface GuardCheckResult {
  allowed: boolean;
  blocked: boolean;
  verdict: string;
  reasons: string[];
  riskScore: number;
  /** Full evaluation result for inspection. */
  raw: SecurityEvalResult;
}

export class VeridexLangChainGuard {
  private config: LangChainGuardConfig;
  private agent: AgentIdentity;
  private turnIndex = 0;

  constructor(config: LangChainGuardConfig) {
    if (!config.gateway && !config.client) {
      throw new Error('Either gateway or client must be provided');
    }
    this.config = config;
    this.agent = {
      agentId: config.agentId,
      name: config.agentName,
      framework: 'langchain',
    };
  }

  /** Increment the turn counter (call at each agent step). */
  nextTurn(): void {
    this.turnIndex++;
  }

  /** Reset the turn counter (call at start of new conversation). */
  resetTurn(): void {
    this.turnIndex = 0;
  }

  private async evaluate(action: SecurityEvalResult extends never ? never : Parameters<SecurityGateway['evaluate']>[0]): Promise<GuardCheckResult> {
    let result: SecurityEvalResult;
    if (this.config.gateway) {
      result = await this.config.gateway.evaluate(action);
    } else {
      result = await this.config.client?.evaluate(action);
    }

    const blocked = result.verdict === 'block';

    if (blocked && this.config.onBlock === 'throw') {
      throw new Error(`[VeridexSecurity] Action blocked: ${result.reasons.join('; ')}`);
    }
    if (blocked && this.config.onBlock === 'callback' && this.config.blockCallback) {
      await this.config.blockCallback(result);
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
   * Check a tool call before execution.
   * Call this in your LangChain tool's `_call()` method or in a custom callback.
   */
  async beforeToolCall(
    toolName: string,
    args: Record<string, unknown>,
    description?: string,
  ): Promise<GuardCheckResult> {
    return this.evaluate({
      agent: this.agent,
      action: {
        type: 'tool_call',
        toolCalls: [{ name: toolName, arguments: args, description }],
        content: JSON.stringify(args),
      },
      turnIndex: this.turnIndex,
    });
  }

  /**
   * Scan LLM output before it's processed.
   * Call this in a LangChain callback handler's `handleLLMEnd`.
   */
  async afterLLMCall(output: string): Promise<GuardCheckResult> {
    return this.evaluate({
      agent: this.agent,
      action: {
        type: 'llm_call',
        content: output,
      },
      turnIndex: this.turnIndex,
    });
  }

  /**
   * Check a payment/transfer action.
   */
  async beforePayment(
    amountUsd: number,
    chain?: string,
    targetAddress?: string,
  ): Promise<GuardCheckResult> {
    return this.evaluate({
      agent: this.agent,
      action: {
        type: 'payment',
        amountUsd,
        chain,
        targetAddress,
      },
      turnIndex: this.turnIndex,
    });
  }

  /**
   * Wrap a LangChain-style tool to auto-check before execution.
   * Returns a proxy that calls beforeToolCall, then the original.
   *
   * Works with any object that has a `name` and `invoke(input)` method.
   */
  wrapTool<T extends { name: string; invoke: (input: any) => Promise<any> }>(tool: T): T {
    const originalInvoke = tool.invoke.bind(tool);

    (tool as any).invoke = async (input: any) => {
      await this.beforeToolCall(
        tool.name,
        typeof input === 'object' ? input : { input },
      );
      return originalInvoke(input);
    };

    return tool;
  }

  /**
   * Create a LangChain callback handler that automatically checks
   * all tool calls and LLM outputs.
   *
   * Returns an object compatible with LangChain's BaseCallbackHandler shape.
   */
  createCallbackHandler(): {
    handleToolStart: (tool: { name: string }, input: string) => Promise<void>;
    handleLLMEnd: (output: { generations: Array<Array<{ text: string }>> }) => Promise<void>;
  } {
    const guard = this;
    return {
      async handleToolStart(tool: { name: string }, input: string) {
        try {
          const args = JSON.parse(input);
          await guard.beforeToolCall(tool.name, args);
        } catch (e) {
          if (e instanceof SyntaxError) {
            await guard.beforeToolCall(tool.name, { raw: input });
          } else {
            throw e;
          }
        }
      },
      async handleLLMEnd(output: { generations: Array<Array<{ text: string }>> }) {
        for (const gen of output.generations) {
          for (const g of gen) {
            if (g.text) await guard.afterLLMCall(g.text);
          }
        }
      },
    };
  }
}
