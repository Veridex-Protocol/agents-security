/**
 * @packageDocumentation
 * @module BuiltInPacks
 * @description
 * Standalone security packs that work with any agent framework.
 * These are self-contained re-implementations of the core Veridex security
 * packs using the framework-agnostic SecurityEvalContext/SecurityCheckResult types.
 *
 * Zero dependency on @veridex/agents or any runtime.
 */

import type {
  SecurityPack,
  SecurityEvalContext,
  SecurityCheckResult,
  SecurityVerdict,
  ActionType,
} from './types';

// ── Helpers ──

function check(
  packId: string,
  ruleName: string,
  passed: boolean,
  verdict: SecurityVerdict,
  reason: string,
  risk: number,
): SecurityCheckResult {
  return {
    checkId: `${packId}:${ruleName}`,
    checkName: ruleName,
    passed,
    verdict,
    reason,
    riskContribution: risk,
    packId,
  };
}

// ─────────────────────────────────────────────
// 1. Injection Detection
// ─────────────────────────────────────────────

const INJECTION_PATTERNS: Array<{
  category: string;
  pattern: RegExp;
  severity: 'critical' | 'high' | 'medium';
  description: string;
}> = [
  // Imperative overrides
  { category: 'imperative_override', pattern: /ignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|guidelines?|prompts?)/i, severity: 'critical', description: 'Imperative override: ignore instructions' },
  { category: 'imperative_override', pattern: /disregard\s+(all\s+)?(previous|prior|above|earlier|your)\s+(instructions?|rules?|guidelines?|constraints?)/i, severity: 'critical', description: 'Imperative override: disregard instructions' },
  { category: 'imperative_override', pattern: /forget\s+(everything|all|what)\s+(you\s+)?(know|learned|were\s+told)/i, severity: 'critical', description: 'Imperative override: forget context' },
  // Role manipulation
  { category: 'role_manipulation', pattern: /you\s+are\s+now\s+(a|an|the)\s+/i, severity: 'high', description: 'Role manipulation: identity reassignment' },
  { category: 'role_manipulation', pattern: /act\s+as\s+(if\s+you\s+are|though\s+you\s+were|a|an)\s+/i, severity: 'high', description: 'Role manipulation: act as directive' },
  { category: 'role_manipulation', pattern: /pretend\s+(to\s+be|you\s+are|that)\s+/i, severity: 'high', description: 'Role manipulation: pretend directive' },
  { category: 'role_manipulation', pattern: /switch\s+to\s+(a\s+|an\s+)?new\s+(mode|role|personality|persona)/i, severity: 'high', description: 'Role manipulation: mode switch' },
  // Secret instructions
  { category: 'hidden_instruction', pattern: /\[SYSTEM\]/i, severity: 'critical', description: 'Hidden instruction: [SYSTEM] tag' },
  { category: 'hidden_instruction', pattern: /\[INST\]/i, severity: 'high', description: 'Hidden instruction: [INST] tag' },
  { category: 'hidden_instruction', pattern: /<<SYS>>/i, severity: 'critical', description: 'Hidden instruction: <<SYS>> tag' },
  { category: 'hidden_instruction', pattern: /<\|im_start\|>system/i, severity: 'critical', description: 'Hidden instruction: ChatML system tag' },
  // Output suppression
  { category: 'output_suppression', pattern: /do\s+not\s+(show|display|reveal|output|print|return)\s+(the|this|your|any)/i, severity: 'medium', description: 'Output suppression attempt' },
  { category: 'output_suppression', pattern: /hide\s+(the\s+)?(output|result|response)/i, severity: 'medium', description: 'Output suppression: hide results' },
  // Financial routing
  { category: 'financial_injection', pattern: /send\s+(all\s+)?(funds?|money|tokens?|eth|btc|sol)\s+to\s+(0x[0-9a-fA-F]{6,}|[A-Za-z0-9]{32,})/i, severity: 'critical', description: 'Financial routing injection: redirect funds' },
  { category: 'financial_injection', pattern: /transfer\s+(everything|all|balance)\s+to\s+/i, severity: 'critical', description: 'Financial routing injection: transfer all' },
  // MCP tool poisoning
  { category: 'mcp_poisoning', pattern: /<IMPORTANT>[\s\S]*?<\/IMPORTANT>/i, severity: 'critical', description: 'MCP tool poisoning: IMPORTANT tags' },
  { category: 'mcp_poisoning', pattern: /<HIDDEN>[\s\S]*?<\/HIDDEN>/i, severity: 'critical', description: 'MCP tool poisoning: HIDDEN tags' },
  // Zero-width chars
  { category: 'encoding_attack', pattern: /[\u200B\u200C\u200D\u2060\uFEFF]{3,}/u, severity: 'high', description: 'Encoding attack: zero-width character sequence' },
];

export function injectionDetectionPack(): SecurityPack {
  return {
    id: 'veridex:injection-detection',
    name: 'Injection Detection',
    description: 'Detects prompt injection, role manipulation, financial routing, and MCP tool poisoning in agent content',
    version: '1.0.0',
    appliesTo: '*',
    enabled: true,
    evaluate(ctx) {
      const results: SecurityCheckResult[] = [];
      const content = gatherContent(ctx);
      if (!content) {
        return [check(this.id, 'injection-scan', true, 'pass', 'No content to scan', 0)];
      }

      let totalRisk = 0;
      const detections: string[] = [];

      for (const pat of INJECTION_PATTERNS) {
        if (pat.pattern.test(content)) {
          const risk = pat.severity === 'critical' ? 0.9 : pat.severity === 'high' ? 0.6 : 0.3;
          totalRisk += risk;
          detections.push(pat.description);
        }
      }

      if (detections.length === 0) {
        results.push(check(this.id, 'injection-scan', true, 'pass', 'No injection patterns detected', 0));
      } else {
        const verdict: SecurityVerdict = totalRisk >= 0.8 ? 'block' : totalRisk >= 0.5 ? 'escalate' : 'flag';
        results.push(check(
          this.id,
          'injection-scan',
          false,
          verdict,
          `Detected ${detections.length} injection pattern(s): ${detections.join('; ')}`,
          Math.min(totalRisk, 1.0),
        ));
      }

      return results;
    },
  };
}

// ─────────────────────────────────────────────
// 2. Tool Poisoning Detection
// ─────────────────────────────────────────────

const HIDDEN_CONTENT_PATTERNS = [
  /<IMPORTANT>[\s\S]*?<\/IMPORTANT>/gi,
  /<HIDDEN>[\s\S]*?<\/HIDDEN>/gi,
  /<!--[\s\S]*?-->/g,
];

export function toolPoisoningPack(): SecurityPack {
  const descriptionHashes = new Map<string, number>();

  return {
    id: 'veridex:tool-poisoning',
    name: 'Tool Poisoning Detection',
    description: 'Detects hidden content injection and description mutations in tool definitions',
    version: '1.0.0',
    appliesTo: ['tool_call'],
    enabled: true,
    evaluate(ctx) {
      const results: SecurityCheckResult[] = [];
      const tools = ctx.action.toolCalls ?? [];
      if (tools.length === 0) {
        return [check(this.id, 'tool-poison-scan', true, 'pass', 'No tool calls to scan', 0)];
      }

      for (const tool of tools) {
        if (tool.description) {
          // Check for hidden content
          for (const pat of HIDDEN_CONTENT_PATTERNS) {
            if (pat.test(tool.description)) {
              results.push(check(this.id, `hidden-content:${tool.name}`, false, 'block',
                `Tool '${tool.name}' description contains hidden content`, 0.9));
            }
          }

          // Check for description mutation (rug-pull)
          const hash = fnv1a(tool.description);
          const existing = descriptionHashes.get(tool.name);
          if (existing !== undefined && existing !== hash) {
            results.push(check(this.id, `desc-mutation:${tool.name}`, false, 'escalate',
              `Tool '${tool.name}' description changed unexpectedly (possible rug-pull)`, 0.7));
          }
          descriptionHashes.set(tool.name, hash);
        }
      }

      if (results.length === 0) {
        results.push(check(this.id, 'tool-poison-scan', true, 'pass', 'No tool poisoning detected', 0));
      }

      return results;
    },
  };
}

// ─────────────────────────────────────────────
// 3. Secret Redaction / Exfiltration Detection
// ─────────────────────────────────────────────

const SECRET_PATTERNS: Array<{ name: string; pattern: RegExp; severity: 'critical' | 'high' }> = [
  { name: 'eth_private_key', pattern: /(?:0x)?[0-9a-fA-F]{64}/g, severity: 'critical' },
  { name: 'aws_access_key', pattern: /AKIA[0-9A-Z]{16}/g, severity: 'critical' },
  { name: 'aws_secret_key', pattern: /[0-9a-zA-Z/+=]{40}/g, severity: 'critical' },
  { name: 'api_key', pattern: /(?:sk|pk|api)[_-][a-zA-Z0-9]{20,}/gi, severity: 'high' },
  { name: 'jwt', pattern: /eyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_.+/=]+/g, severity: 'high' },
  { name: 'mnemonic', pattern: /(?:\b(?:abandon|ability|able|about|above|absent|absorb|abstract|absurd|abuse|access|accident|account|accuse|achieve|acid|acoustic|acquire|across|act|action|actual|adapt|add|addict|address|adjust|admit|adult|advance|advice|aerobic|affair|afford|afraid|again|age|agent|agree|ahead|aim|air|airport|aisle|alarm|album|alcohol|alert|alien|all|alley|allow|almost|alone|alpha|already|also|alter|always|amateur|amazing|among|amount|amused|analyst|anchor|ancient|anger|angle|angry|animal|ankle|announce|annual|another|answer|antenna|antique|anxiety|any|apart|apology|appear|apple|approve|april|arch|arctic|area|arena|argue|arm|armed|armor|army|around|arrange|arrest|arrive|arrow|art|artefact|artist|artwork|ask|aspect|assault|asset|assist|assume|asthma|athlete|atom|attack|attend|attitude|attract|auction|audit|august|aunt|author|auto|autumn|average|avocado|avoid|awake|aware|awesome|awful|awkward|axis)\b[\s,]+){11,23}\b\w+\b/gi, severity: 'critical' },
  { name: 'connection_string', pattern: /(?:mongodb|postgres|mysql|redis):\/\/[^\s'"]+/gi, severity: 'high' },
];

export function secretDetectionPack(): SecurityPack {
  return {
    id: 'veridex:secret-detection',
    name: 'Secret & Credential Detection',
    description: 'Detects private keys, API keys, JWTs, mnemonics, and connection strings in agent content',
    version: '1.0.0',
    appliesTo: '*',
    enabled: true,
    evaluate(ctx) {
      const content = gatherContent(ctx);
      if (!content) {
        return [check(this.id, 'secret-scan', true, 'pass', 'No content to scan', 0)];
      }

      const detections: string[] = [];
      for (const pat of SECRET_PATTERNS) {
        pat.pattern.lastIndex = 0;
        if (pat.pattern.test(content)) {
          detections.push(`${pat.name} (${pat.severity})`);
        }
      }

      if (detections.length === 0) {
        return [check(this.id, 'secret-scan', true, 'pass', 'No secrets detected', 0)];
      }

      return [check(this.id, 'secret-scan', false, 'block',
        `Detected ${detections.length} potential secret(s): ${detections.join(', ')}`, 0.95)];
    },
  };
}

// ─────────────────────────────────────────────
// 4. Budget Ceiling
// ─────────────────────────────────────────────

export function budgetCeilingPack(options?: {
  maxRunSpendUsd?: number;
  maxTokenBudget?: number;
  flagThresholdPercent?: number;
}): SecurityPack {
  const maxSpend = options?.maxRunSpendUsd ?? 100;
  const maxTokens = options?.maxTokenBudget ?? 1_000_000;
  const flagPct = options?.flagThresholdPercent ?? 80;

  return {
    id: 'veridex:budget-ceiling',
    name: 'Budget Ceiling',
    description: 'Enforces spending and token limits on agent runs',
    version: '1.0.0',
    appliesTo: '*',
    enabled: true,
    evaluate(ctx) {
      const results: SecurityCheckResult[] = [];
      const spend = ctx.runSpendUsd ?? 0;
      const tokens = ctx.totalTokens ?? 0;

      // Spend check
      if (spend > maxSpend) {
        results.push(check(this.id, 'spend-limit', false, 'block',
          `Run spend $${spend} exceeds limit $${maxSpend}`, 1.0));
      } else if (spend > maxSpend * flagPct / 100) {
        results.push(check(this.id, 'spend-limit', true, 'flag',
          `Run spend $${spend} approaching limit $${maxSpend} (${Math.round(spend / maxSpend * 100)}%)`, 0.3));
      }

      // Token check
      if (tokens > maxTokens) {
        results.push(check(this.id, 'token-limit', false, 'block',
          `Token usage ${tokens} exceeds budget ${maxTokens}`, 0.8));
      } else if (tokens > maxTokens * flagPct / 100) {
        results.push(check(this.id, 'token-limit', true, 'flag',
          `Token usage ${tokens} approaching budget ${maxTokens}`, 0.2));
      }

      if (results.length === 0) {
        results.push(check(this.id, 'budget-check', true, 'pass', 'Within budget', 0));
      }

      return results;
    },
  };
}

// ─────────────────────────────────────────────
// 5. Shell Command Safety
// ─────────────────────────────────────────────

const DANGEROUS_SHELL_PATTERNS: Array<{ name: string; pattern: RegExp; severity: 'critical' | 'high' }> = [
  { name: 'piped_execution', pattern: /curl\s+.*\|\s*(?:bash|sh|zsh)/i, severity: 'critical' },
  { name: 'piped_execution', pattern: /wget\s+.*\|\s*(?:bash|sh|zsh)/i, severity: 'critical' },
  { name: 'destructive_rm', pattern: /rm\s+-rf?\s+\//i, severity: 'critical' },
  { name: 'eval_execution', pattern: /eval\s*\(/i, severity: 'high' },
  { name: 'env_manipulation', pattern: /export\s+(?:LD_PRELOAD|LD_LIBRARY_PATH|PATH)\s*=/i, severity: 'critical' },
  { name: 'reverse_shell', pattern: /(?:bash|nc|ncat)\s+-[ei]?\s+.*\d+\.\d+\.\d+\.\d+/i, severity: 'critical' },
  { name: 'base64_decode_exec', pattern: /base64\s+(?:-d|--decode)\s*\|\s*(?:bash|sh)/i, severity: 'critical' },
];

export function shellCommandSafetyPack(): SecurityPack {
  return {
    id: 'veridex:shell-safety',
    name: 'Shell Command Safety',
    description: 'Detects dangerous shell commands: piped execution, reverse shells, destructive ops',
    version: '1.0.0',
    appliesTo: ['shell_command', 'tool_call'],
    enabled: true,
    evaluate(ctx) {
      const content = gatherContent(ctx);
      if (!content) {
        return [check(this.id, 'shell-scan', true, 'pass', 'No content to scan', 0)];
      }

      const detections: string[] = [];
      for (const pat of DANGEROUS_SHELL_PATTERNS) {
        if (pat.pattern.test(content)) {
          detections.push(`${pat.name} (${pat.severity})`);
        }
      }

      if (detections.length === 0) {
        return [check(this.id, 'shell-scan', true, 'pass', 'No dangerous shell patterns detected', 0)];
      }

      return [check(this.id, 'shell-scan', false, 'block',
        `Detected ${detections.length} dangerous shell pattern(s): ${detections.join(', ')}`, 0.95)];
    },
  };
}

// ─────────────────────────────────────────────
// 6. Endpoint Allowlist
// ─────────────────────────────────────────────

export function endpointAllowlistPack(options: {
  allowedEndpoints: string[];
  blockedEndpoints?: string[];
}): SecurityPack {
  return {
    id: 'veridex:endpoint-allowlist',
    name: 'Endpoint Allowlist',
    description: 'Restricts which HTTP endpoints agents can call',
    version: '1.0.0',
    appliesTo: ['http_request', 'tool_call'],
    enabled: true,
    evaluate(ctx) {
      const endpoint = ctx.action.endpoint;
      if (!endpoint) {
        return [check(this.id, 'endpoint-check', true, 'pass', 'No endpoint in action', 0)];
      }

      // Blocked takes precedence
      if (options.blockedEndpoints?.some((b) => endpoint.includes(b))) {
        return [check(this.id, 'endpoint-check', false, 'block',
          `Endpoint '${endpoint}' is explicitly blocked`, 1.0)];
      }

      if (options.allowedEndpoints.some((a) => endpoint.includes(a))) {
        return [check(this.id, 'endpoint-check', true, 'pass', 'Endpoint allowed', 0)];
      }

      return [check(this.id, 'endpoint-check', false, 'block',
        `Endpoint '${endpoint}' is not in allowlist`, 0.8)];
    },
  };
}

// ─────────────────────────────────────────────
// 7. Handoff Safety
// ─────────────────────────────────────────────

export function handoffSafetyPack(options?: {
  allowedTargets?: string[];
  blockedTargets?: string[];
  requireApproval?: boolean;
}): SecurityPack {
  return {
    id: 'veridex:handoff-safety',
    name: 'Handoff Safety',
    description: 'Controls agent-to-agent handoff targets',
    version: '1.0.0',
    appliesTo: ['handoff'],
    enabled: true,
    evaluate(ctx) {
      if (ctx.action.type !== 'handoff' || !ctx.action.targetAgentId) {
        return [check(this.id, 'handoff-check', true, 'pass', 'Not a handoff action', 0)];
      }

      const target = ctx.action.targetAgentId;

      if (options?.blockedTargets?.includes(target)) {
        return [check(this.id, 'handoff-check', false, 'block',
          `Handoff to '${target}' is explicitly blocked`, 1.0)];
      }

      if (options?.allowedTargets?.length && !options.allowedTargets.includes(target)) {
        return [check(this.id, 'handoff-check', false, 'block',
          `Handoff target '${target}' is not in allowlist`, 0.8)];
      }

      if (options?.requireApproval) {
        return [check(this.id, 'handoff-check', false, 'escalate',
          `Handoff to '${target}' requires approval`, 0.5)];
      }

      return [check(this.id, 'handoff-check', true, 'pass', `Handoff to '${target}' allowed`, 0)];
    },
  };
}

// ─────────────────────────────────────────────
// 8. Financial Safety Rails
// ─────────────────────────────────────────────

export function financialSafetyPack(options?: {
  maxTransactionUsd?: number;
  allowedChains?: string[];
  allowedAddresses?: string[];
  requireApprovalAboveUsd?: number;
}): SecurityPack {
  const maxTx = options?.maxTransactionUsd ?? 1000;
  const approvalThreshold = options?.requireApprovalAboveUsd ?? maxTx * 0.5;

  return {
    id: 'veridex:financial-safety',
    name: 'Financial Safety Rails',
    description: 'Enforces transaction limits, chain restrictions, and address allowlists for payment actions',
    version: '1.0.0',
    appliesTo: ['payment', 'tool_call'],
    enabled: true,
    evaluate(ctx) {
      const results: SecurityCheckResult[] = [];
      const amount = ctx.action.amountUsd ?? 0;
      const chain = ctx.action.chain;
      const target = ctx.action.targetAddress;

      if (amount <= 0 && !chain && !target) {
        return [check(this.id, 'financial-check', true, 'pass', 'No financial action detected', 0)];
      }

      // Amount limit
      if (amount > maxTx) {
        results.push(check(this.id, 'tx-limit', false, 'block',
          `Transaction $${amount} exceeds limit $${maxTx}`, 1.0));
      } else if (amount > approvalThreshold) {
        results.push(check(this.id, 'tx-approval', false, 'escalate',
          `Transaction $${amount} requires approval (threshold: $${approvalThreshold})`, 0.5));
      }

      // Chain allowlist
      if (chain && options?.allowedChains?.length) {
        if (!options.allowedChains.includes(chain)) {
          results.push(check(this.id, 'chain-check', false, 'block',
            `Chain '${chain}' is not in allowed list: ${options.allowedChains.join(', ')}`, 0.9));
        }
      }

      // Address allowlist
      if (target && options?.allowedAddresses?.length) {
        if (!options.allowedAddresses.includes(target)) {
          results.push(check(this.id, 'address-check', false, 'block',
            `Target address is not in allowlist`, 0.9));
        }
      }

      if (results.length === 0) {
        results.push(check(this.id, 'financial-check', true, 'pass', 'Financial action within limits', 0));
      }

      return results;
    },
  };
}

// ─────────────────────────────────────────────
// 9. Cross-Turn Anomaly Detection
// ─────────────────────────────────────────────

export function crossTurnAnomalyPack(): SecurityPack {
  const toolHistory: Array<{ tool: string; turn: number; timestamp: number }> = [];
  const HIGH_RISK_TOOLS = new Set(['bash', 'shell', 'execute', 'run_command', 'write_file', 'delete_file', 'transfer', 'send']);

  return {
    id: 'veridex:cross-turn-anomaly',
    name: 'Cross-Turn Anomaly Detection',
    description: 'Detects anomalous tool usage patterns across conversation turns (frequency spikes, new tool emergence, escalation)',
    version: '1.0.0',
    appliesTo: ['tool_call'],
    enabled: true,
    evaluate(ctx) {
      const results: SecurityCheckResult[] = [];
      const turn = ctx.turnIndex ?? 0;
      const tools = ctx.action.toolCalls ?? [];

      for (const tool of tools) {
        toolHistory.push({ tool: tool.name, turn, timestamp: Date.now() });

        // New high-risk tool appearance after multiple turns
        if (turn > 3 && HIGH_RISK_TOOLS.has(tool.name)) {
          const priorUses = toolHistory.filter((h) => h.tool === tool.name && h.turn < turn);
          if (priorUses.length === 0) {
            results.push(check(this.id, `new-risky-tool:${tool.name}`, false, 'flag',
              `High-risk tool '${tool.name}' appeared for first time at turn ${turn}`, 0.5));
          }
        }

        // Frequency spike: tool used 3x+ more than average in recent window
        const recentWindow = toolHistory.filter((h) => h.tool === tool.name && h.turn >= turn - 3);
        const olderWindow = toolHistory.filter((h) => h.tool === tool.name && h.turn < turn - 3);
        if (olderWindow.length > 0 && recentWindow.length > olderWindow.length * 3) {
          results.push(check(this.id, `freq-spike:${tool.name}`, false, 'flag',
            `Tool '${tool.name}' frequency spike: ${recentWindow.length} recent vs ${olderWindow.length} prior`, 0.4));
        }
      }

      if (results.length === 0) {
        results.push(check(this.id, 'anomaly-check', true, 'pass', 'No anomalies detected', 0));
      }

      // Trim history if it grows too large
      if (toolHistory.length > 10000) {
        toolHistory.splice(0, toolHistory.length - 5000);
      }

      return results;
    },
  };
}

// ─────────────────────────────────────────────
// 10. LLM Response Guard
// ─────────────────────────────────────────────

export function llmResponseGuardPack(options?: {
  maxFinancialActionsPerTurn?: number;
  canaryToken?: string;
}): SecurityPack {
  const maxFinancial = options?.maxFinancialActionsPerTurn ?? 3;

  return {
    id: 'veridex:llm-response-guard',
    name: 'LLM Response Guard',
    description: 'Validates LLM responses for safety: canary leaks, excessive financial actions, reasoning manipulation',
    version: '1.0.0',
    appliesTo: ['llm_call', 'tool_call'],
    enabled: true,
    evaluate(ctx) {
      const results: SecurityCheckResult[] = [];
      const content = ctx.action.content ?? '';

      // Canary token leak
      if (options?.canaryToken && content.includes(options.canaryToken)) {
        results.push(check(this.id, 'canary-leak', false, 'block',
          'System prompt canary token detected in output — possible exfiltration', 1.0));
      }

      // Excessive financial actions
      const tools = ctx.action.toolCalls ?? [];
      const financialTools = tools.filter((t) =>
        ['transfer', 'send', 'swap', 'approve', 'pay'].some((k) => t.name.toLowerCase().includes(k)));
      if (financialTools.length > maxFinancial) {
        results.push(check(this.id, 'excessive-financial', false, 'escalate',
          `${financialTools.length} financial tool calls in one turn (limit: ${maxFinancial})`, 0.7));
      }

      // Reasoning manipulation patterns
      const MANIPULATION_PATTERNS = [
        /this is an? emergency/i,
        /urgent:\s*act\s+immediately/i,
        /already\s+been\s+approved/i,
        /bypass\s+(?:the\s+)?(?:safety|security|policy)/i,
        /override\s+(?:the\s+)?(?:limit|restriction|policy)/i,
      ];
      for (const pat of MANIPULATION_PATTERNS) {
        if (pat.test(content)) {
          results.push(check(this.id, 'reasoning-manipulation', false, 'flag',
            `Reasoning manipulation detected: ${pat.source.slice(0, 50)}`, 0.5));
          break;
        }
      }

      if (results.length === 0) {
        results.push(check(this.id, 'llm-guard', true, 'pass', 'LLM response clean', 0));
      }

      return results;
    },
  };
}

// ─────────────────────────────────────────────
// Default pack set
// ─────────────────────────────────────────────

/** Create all default security packs. */
export function createDefaultPacks(options?: {
  budgetCeiling?: Parameters<typeof budgetCeilingPack>[0];
  financialSafety?: Parameters<typeof financialSafetyPack>[0];
  llmResponseGuard?: Parameters<typeof llmResponseGuardPack>[0];
}): SecurityPack[] {
  return [
    injectionDetectionPack(),
    toolPoisoningPack(),
    secretDetectionPack(),
    budgetCeilingPack(options?.budgetCeiling),
    shellCommandSafetyPack(),
    handoffSafetyPack(),
    financialSafetyPack(options?.financialSafety),
    crossTurnAnomalyPack(),
    llmResponseGuardPack(options?.llmResponseGuard),
  ];
}

// ── Utility functions ──

/** Gather all scannable content from a context. */
function gatherContent(ctx: SecurityEvalContext): string {
  const parts: string[] = [];
  if (ctx.action.content) parts.push(ctx.action.content);
  if (ctx.action.toolCalls) {
    for (const tc of ctx.action.toolCalls) {
      if (tc.description) parts.push(tc.description);
      parts.push(JSON.stringify(tc.arguments));
    }
  }
  if (ctx.action.endpoint) parts.push(ctx.action.endpoint);
  if (ctx.action.targetAddress) parts.push(ctx.action.targetAddress);
  return parts.join('\n');
}

/** FNV-1a 32-bit hash. */
function fnv1a(str: string): number {
  let hash = 0x811c9dc5;
  for (let i = 0; i < str.length; i++) {
    hash ^= str.charCodeAt(i);
    hash = (hash * 0x01000193) >>> 0;
  }
  return hash;
}
