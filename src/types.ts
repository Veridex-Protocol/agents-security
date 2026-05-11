/**
 * @packageDocumentation
 * @module AgentSecurityTypes
 * @description
 * Framework-agnostic types for the Veridex Agent Security Gateway.
 *
 * These types define the universal contract for securing ANY AI agent,
 * regardless of framework (LangChain, CrewAI, AutoGPT, custom, etc.)
 *
 * Design principle: an external agent only needs to describe its action
 * as a simple JSON payload. No framework-specific types required.
 */

// ── Agent Identity ──

/** Minimal agent identity for security evaluation. */
export interface AgentIdentity {
  /** Unique agent identifier (any format — UUID, name, etc.) */
  agentId: string;
  /** Human-readable agent name */
  name?: string;
  /** Optional tenant/workspace scope */
  tenantId?: string;
  /** Agent framework identifier (e.g. 'langchain', 'crewai', 'autogpt', 'custom') */
  framework?: string;
  /** Additional identity metadata */
  metadata?: Record<string, unknown>;
}

// ── Action Proposals (framework-agnostic) ──

/** The universal action types any agent can propose. */
export type ActionType =
  | 'tool_call'
  | 'llm_call'
  | 'payment'
  | 'memory_write'
  | 'handoff'
  | 'http_request'
  | 'shell_command'
  | 'file_operation'
  | 'custom';

/** A tool call proposed by an agent. */
export interface ToolCallAction {
  /** Tool name */
  name: string;
  /** Tool description (for poisoning detection) */
  description?: string;
  /** Tool arguments as key-value pairs */
  arguments: Record<string, unknown>;
}

/** A universal action proposal from any agent. */
export interface SecurityAction {
  /** Action type discriminator */
  type: ActionType;
  /** Tool calls (when type = 'tool_call') */
  toolCalls?: ToolCallAction[];
  /** Raw content to scan (LLM prompt/response, shell command, etc.) */
  content?: string;
  /** Target endpoint URL (for HTTP/API calls) */
  endpoint?: string;
  /** Target agent ID (for handoffs) */
  targetAgentId?: string;
  /** Financial amount in USD (for payment actions) */
  amountUsd?: number;
  /** Target chain identifier (for blockchain actions) */
  chain?: string;
  /** Target address (for blockchain/payment actions) */
  targetAddress?: string;
  /** Raw metadata for custom actions */
  metadata?: Record<string, unknown>;
}

// ── Evaluation Context ──

/** Full context for a security evaluation request. */
export interface SecurityEvalContext {
  /** Agent identity */
  agent: AgentIdentity;
  /** The action being evaluated */
  action: SecurityAction;
  /** Current run/conversation identifier */
  runId?: string;
  /** Turn/step number within the current run */
  turnIndex?: number;
  /** Total spend so far in this run (USD) */
  runSpendUsd?: number;
  /** Total tokens consumed so far */
  totalTokens?: number;
  /** Timestamp of the evaluation request */
  timestamp?: number;
}

// ── Verdict & Results ──

/** Security verdict levels. */
export type SecurityVerdict = 'pass' | 'flag' | 'escalate' | 'block';

/** Result from a single security check. */
export interface SecurityCheckResult {
  /** Check identifier (pack_id:rule_id) */
  checkId: string;
  /** Human-readable check name */
  checkName: string;
  /** Whether the check passed */
  passed: boolean;
  /** Verdict from this check */
  verdict: SecurityVerdict;
  /** Explanation */
  reason: string;
  /** Risk contribution (0.0 - 1.0) */
  riskContribution: number;
  /** Which security pack produced this result */
  packId?: string;
  /** Optional structured metadata (e.g. rate-limit key, canary hits). */
  metadata?: Record<string, unknown>;
}

/** Complete evaluation result. */
export interface SecurityEvalResult {
  /** Final verdict (worst of all checks) */
  verdict: SecurityVerdict;
  /** Aggregate risk score (0.0-1.0) */
  riskScore: number;
  /** Human-readable reasons for non-pass verdicts */
  reasons: string[];
  /** Individual check results */
  checks: SecurityCheckResult[];
  /** Which packs were evaluated */
  packsEvaluated: string[];
  /** Evaluation timestamp */
  evaluatedAt: number;
  /** Evaluation duration in milliseconds */
  durationMs: number;
}

// ── Security Pack Interface (standalone) ──

/** A security pack that can evaluate actions independently. */
export interface SecurityPack {
  /** Unique pack identifier */
  id: string;
  /** Human-readable name */
  name: string;
  /** What this pack defends against */
  description: string;
  /** Semantic version */
  version: string;
  /** Action types this pack applies to ('*' for all) */
  appliesTo: ActionType[] | '*';
  /** Whether this pack is enabled */
  enabled: boolean;
  /** Evaluate a security context. Return check results. */
  evaluate(ctx: SecurityEvalContext): SecurityCheckResult[] | Promise<SecurityCheckResult[]>;
}

// ── Gateway Configuration ──

/** Options for constructing a SecurityGateway instance. */
export interface SecurityGatewayConfig {
  /** Which default packs to enable (default: all) */
  enabledPacks?: string[];
  /** Which default packs to disable */
  disabledPacks?: string[];
  /** Custom packs to register */
  customPacks?: SecurityPack[];
  /** Options passed to individual packs */
  packOptions?: Record<string, Record<string, unknown>>;
  /** Whether to fail-closed on pack errors (default: true) */
  failClosed?: boolean;
  /** Maximum evaluation time in ms before short-circuiting (default: 5000) */
  timeoutMs?: number;

  // ── License & Platform Binding ──

  /** Veridex license key — required for production use. */
  licenseKey?: string;
  /** Veridex platform URL for license validation and pack updates. */
  platformUrl?: string;
  /** App ID on the Veridex platform. Required for approval workflows. */
  appId?: string;
  /** How often to re-validate the license (ms). Default: 1 hour. */
  licenseCheckIntervalMs?: number;
  /** Whether to allow offline/degraded mode when platform is unreachable. */
  allowOfflineGracePeriod?: boolean;
  /** Offline grace period in ms (default: 24h). After this, evaluations block. */
  offlineGracePeriodMs?: number;

  // ── Rate limiting ──

  /**
   * Per-tenant / per-agent rate limit applied as a pre-check before any pack
   * runs. Omit to disable. If both `rateLimit` and `rateLimiter` are provided,
   * `rateLimiter` wins.
   */
  rateLimit?: {
    /** Tokens the bucket holds (burst size). */
    capacity: number;
    /** Tokens refilled per second. */
    refillPerSecond: number;
    /**
     * Key to group requests by. Default 'tenant' → falls back to `agentId` if
     * `tenantId` is missing. 'agent' always keys by `agentId`.
     */
    keyBy?: 'tenant' | 'agent' | ((ctx: import('./types').SecurityEvalContext) => string);
  };
  /**
   * Plug in a custom rate limiter (e.g. Redis-backed). If present, overrides
   * the in-memory token-bucket built from `rateLimit`.
   */
  rateLimiter?: {
    consume(key: string, cost?: number): { allowed: boolean; remaining: number; capacity: number; retryAfterSeconds?: number } | Promise<{ allowed: boolean; remaining: number; capacity: number; retryAfterSeconds?: number }>;
    /**
     * Key function for the custom limiter. Required when `rateLimiter` is
     * set without matching `rateLimit.keyBy`.
     */
    keyFn?: (ctx: import('./types').SecurityEvalContext) => string;
  };
}

// ── Client Configuration ──

/** Options for the universal HTTP client. */
export interface SecurityClientConfig {
  /** Gateway server URL (e.g. https://security.veridex.network) */
  gatewayUrl: string;
  /** API key for authentication */
  apiKey: string;
  /** Default agent identity to attach to all requests */
  defaultAgent?: AgentIdentity;
  /** Request timeout in ms (default: 10000) */
  timeoutMs?: number;
}

// ── Scan types for convenience methods ──

/** Quick scan request for content (prompt/response text). */
export interface ContentScanRequest {
  /** Agent identity */
  agent: AgentIdentity;
  /** Content to scan */
  content: string;
  /** Content type hint */
  contentType?: 'prompt' | 'response' | 'tool_output' | 'unknown';
}

/** Quick scan result for content. */
export interface ContentScanResult {
  /** Whether the content is clean */
  clean: boolean;
  /** Detections found */
  detections: Array<{
    type: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
    description: string;
    location?: string;
  }>;
  /** Redacted version of the content (secrets replaced) */
  redacted?: string;
}

// ── Telemetry & Portal Integration ──

/** A security event to report to the Veridex platform. */
export interface SecurityTelemetryEvent {
  /** Unique event ID */
  eventId: string;
  /** ISO 8601 timestamp */
  timestamp: string;
  /** The agent that triggered the evaluation */
  agent: AgentIdentity;
  /** Action type that was evaluated */
  actionType: ActionType | string;
  /** Final verdict */
  verdict: SecurityVerdict;
  /** Risk score 0-1 */
  riskScore: number;
  /** Human-readable reasons (especially for non-pass) */
  reasons: string[];
  /** Which packs were evaluated */
  packsEvaluated: string[];
  /** Total checks run */
  checksRun: number;
  /** Checks that failed */
  checksFailed: number;
  /** Evaluation duration in ms */
  durationMs: number;
  /** The license key used (for attribution) */
  licenseKey?: string;
}

/** Configuration for the telemetry reporter. */
export interface TelemetryReporterConfig {
  /** Veridex platform URL (e.g. https://api.veridex.network) */
  platformUrl: string;
  /** License key for authentication and attribution */
  licenseKey: string;
  /** App ID on the Veridex platform */
  appId: string;
  /** Tenant ID on the platform */
  tenantId?: string;
  /** Batch size before flushing (default: 25) */
  batchSize?: number;
  /** Flush interval in ms (default: 10000) */
  flushIntervalMs?: number;
  /** Whether telemetry is enabled (default: true) */
  enabled?: boolean;
}
