# @veridex/agent-security

> Framework-agnostic agent security gateway. Protect any AI agent — LangChain, CrewAI, AutoGPT, OpenAI Agents SDK, Veridex, or your own — with versioned security packs that address the OWASP LLM Top 10 and MCP threat model.

## Status

Beta. Production-deployed at Veridex. Public API stabilising for `1.0`.

## Why this package exists

Most agent frameworks treat security as the developer's problem. The result is a long-tail of LLM01–LLM10 failures: prompt injection, tool poisoning, secret exfiltration, runaway spend, confused-deputy handoffs. `@veridex/agent-security` packages the mitigations as **versioned, composable security packs** that drop into any agent — Veridex or otherwise — via in-process gateway or HTTP/MCP sidecar.

## Installation

```bash
npm install @veridex/agent-security
# or
pnpm add @veridex/agent-security
```

## Quick Start

### In-process

```ts
import { SecurityGateway, createDefaultPacks } from '@veridex/agent-security';

const gateway = new SecurityGateway({ packs: createDefaultPacks() });

const result = await gateway.evaluate({
  agent: { agentId: 'support-1', framework: 'langchain' },
  action: { type: 'tool_call', toolCalls: [{ name: 'bash', arguments: { cmd: 'ls /' } }] },
});

if (result.verdict === 'deny') {
  throw new SecurityError(result.reason);
}
```

### HTTP sidecar (any framework)

```ts
import { SecurityClient } from '@veridex/agent-security';

const client = new SecurityClient({
  gatewayUrl: 'http://localhost:3100',
  apiKey: process.env.VERIDEX_SECURITY_KEY!,
  defaultAgent: { agentId: 'crewai-team-1', framework: 'crewai' },
});

const check = await client.checkToolCall('bash', { cmd: 'rm -rf /' });
// → { verdict: 'deny', reason: 'shellCommandSafetyPack: destructive command' }
```

### Framework adapters

```ts
import { VeridexLangChainGuard } from '@veridex/agent-security/adapters/langchain';
import { VeridexCrewAIGuard }     from '@veridex/agent-security/adapters/crewai';

// Drop into an existing LangChain executor:
executor.callbacks.push(new VeridexLangChainGuard(gateway));
```

## Security Packs

| Pack | Addresses | What it does |
|---|---|---|
| `injectionDetectionPack` | LLM01 (Prompt Injection) | Heuristic + classifier-based detection on untrusted input |
| `toolPoisoningPack` | MCP TPA / LLM05 | Detects hostile instructions in tool descriptions |
| `secretDetectionPack` | LLM02 / LLM10 | Detects secrets in inputs and outputs |
| `budgetCeilingPack` | LLM10 (Unbounded Consumption) | Per-run / per-tenant / per-window spend caps |
| `shellCommandSafetyPack` | LLM05 / Command Injection | Denies destructive shell patterns |
| `endpointAllowlistPack` | Data exfiltration | Restricts outbound HTTP egress |
| `handoffSafetyPack` | Confused Deputy | Validates identity on A2A/ACP handoffs |
| `piiStrictPack` | LLM02 | Denies or redacts PII in tool I/O |
| `supplyChainPack` | LLM06 | Verifies tool signatures and provenance |
| `canaryCredentialsPack` | LLM10 | Plants honeypot creds; emits security event on access |
| `transparencyLogPack` | Audit integrity | Anchors event chain roots to an external log |

Default bundle:

```ts
import { createDefaultPacks } from '@veridex/agent-security';

const packs = createDefaultPacks({
  budgetCeiling: { perRunUsd: 5 },
  endpointAllowlist: ['api.stripe.com', 'api.openai.com'],
});
```

## Key Features

### Hardened fetch wrapper

```ts
import { createSecureFetch } from '@veridex/agent-security';

const fetch = createSecureFetch({
  endpointAllowlist: ['api.openai.com'],
  canaryScan: defaultCanaryScan,           // detects honeypot creds in responses
  tlsValidator: defaultTLSValidator,        // pinning + min version
  onViolation: (v) => logger.warn(v),
});
```

### Token-bucket rate limiting

```ts
import { TokenBucketRateLimiter } from '@veridex/agent-security';
const limiter = new TokenBucketRateLimiter({ capacity: 100, refillPerSecond: 10 });
const decision = await limiter.consume({ key: `tenant:${tenantId}`, cost: 1 });
```

### Telemetry

Every verdict emits a structured `SecurityTelemetryEvent` with a taxonomy field. Route to your SIEM:

```ts
import { TelemetryReporter } from '@veridex/agent-security';

const reporter = new TelemetryReporter({
  endpoint: 'https://siem.example.com/ingest',
  apiKey: process.env.SIEM_KEY!,
});

gateway.onEvaluate((event) => reporter.report(event));
```

## Documentation

- [Security Packs overview](../../documentation/pages/agent-fabric/security/overview.mdx)
- [Transports & PEP](../../documentation/pages/agent-fabric/transports.mdx)
- [Tools & safety classes](../../documentation/pages/agent-fabric/tools.mdx)
- ADRs: [0052](../../docs/architecture/decisions/0052-tool-sandboxing-and-safety-classes.md), [0053](../../docs/architecture/decisions/0053-policy-engine-rule-composition.md), [0057](../../docs/architecture/decisions/0057-mcp-transport-security-hardening.md)

## Comparison

| Capability | `@veridex/agent-security` | Hand-rolled per-agent |
|---|---|---|
| Versioned, composable packs | ✅ | rare |
| Framework-agnostic gateway | ✅ in-proc + HTTP | usually framework-locked |
| Hardened fetch + canary creds | ✅ | rare |
| Telemetry → SIEM | ✅ structured | logs |
| Adapter for LangChain, CrewAI, MCP | ✅ | DIY |

## Ecosystem

- Runtime: [`@veridex/agents`](../agents)
- Treasury policy: [`@veridex/agents-treasury`](../agents-treasury)
- Control plane policy distribution: [`@veridex/agents-control-plane`](../agents-control-plane)
- Adapters for incremental migration: [`@veridex/agents-adapters`](../agents-adapters)

## License

MIT — see [LICENSE](./LICENSE).
