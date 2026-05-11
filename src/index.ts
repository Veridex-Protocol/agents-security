/**
 * @packageDocumentation
 * @module @veridex/agent-security
 * @description
 * Framework-agnostic agent security gateway by Veridex.
 *
 * Protect ANY AI agent — LangChain, CrewAI, AutoGPT, custom — with
 * enterprise-grade security packs: injection detection, secret scanning,
 * tool poisoning, financial safety rails, anomaly detection, and more.
 *
 * ## Quick Start (in-process)
 * ```ts
 * import { SecurityGateway } from '@veridex/agent-security';
 *
 * const gateway = new SecurityGateway();
 * const result = await gateway.evaluate({
 *   agent: { agentId: 'my-agent', framework: 'langchain' },
 *   action: { type: 'tool_call', toolCalls: [{ name: 'bash', arguments: { cmd: 'ls' } }] },
 * });
 * ```
 *
 * ## Quick Start (HTTP client)
 * ```ts
 * import { SecurityClient } from '@veridex/agent-security';
 *
 * const client = new SecurityClient({
 *   gatewayUrl: 'http://localhost:3100',
 *   apiKey: 'my-key',
 *   defaultAgent: { agentId: 'agent-1', framework: 'crewai' },
 * });
 * const result = await client.checkToolCall('bash', { cmd: 'ls' });
 * ```
 *
 * ## Framework Adapters
 * ```ts
 * import { VeridexLangChainGuard } from '@veridex/agent-security/adapters/langchain';
 * import { VeridexCrewAIGuard } from '@veridex/agent-security/adapters/crewai';
 * ```
 */

// ── Core ──
export { SecurityGateway } from './gateway';
export type { EvaluateListener } from './gateway';
export { SecurityClient } from './client';
export { TelemetryReporter } from './telemetry';

// ── Hardened fetch wrapper ──
export { createSecureFetch, SecureFetchViolationError } from './secureFetch';
export type {
  FetchFn,
  CanaryScanFn,
  CanaryScanResult,
  TLSValidatorFn,
  TLSValidationResult,
  ViolationPolicy,
  ViolationListener,
  SecureFetchViolation,
  SecureFetchOptions,
} from './secureFetch';

// ── Rate limiting ──
export { TokenBucketRateLimiter } from './rateLimiter';
export type { RateLimiter, RateLimitDecision, TokenBucketConfig } from './rateLimiter';

// ── Types ──
export type {
  // Agent identity
  AgentIdentity,
  // Actions
  ActionType,
  ToolCallAction,
  SecurityAction,
  // Evaluation
  SecurityEvalContext,
  SecurityVerdict,
  SecurityCheckResult,
  SecurityEvalResult,
  // Config
  SecurityGatewayConfig,
  SecurityClientConfig,
  // Packs
  SecurityPack,
  // Convenience
  ContentScanRequest,
  ContentScanResult,
  // Telemetry
  SecurityTelemetryEvent,
  TelemetryReporterConfig,
} from './types';

// ── Built-in Packs ──
export {
  createDefaultPacks,
  injectionDetectionPack,
  toolPoisoningPack,
  secretDetectionPack,
  budgetCeilingPack,
  shellCommandSafetyPack,
  endpointAllowlistPack,
  handoffSafetyPack,
  financialSafetyPack,
  crossTurnAnomalyPack,
  llmResponseGuardPack,
} from './packs';
