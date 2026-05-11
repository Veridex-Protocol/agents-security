/**
 * @module secureFetch
 * @description
 * Drop-in `fetch` replacement that enforces Veridex outbound-call guardrails
 * **at the call site**, not at a runtime hook the caller might bypass.
 *
 * The existing `CanaryCredentialDeployer` and `TLSCertPinner` run as
 * `RuntimeHook`s inside the `@veridex/agents` loop. That's great when tools
 * use the runtime's model providers, but any tool that reaches for raw
 * `fetch`/`axios`/`node-fetch`/the OpenAI SDK silently skips every guard.
 * That's exactly where exfiltration actually happens — malicious tools don't
 * go through the hook bus, they go around it.
 *
 * `createSecureFetch` closes that gap by wrapping `fetch` itself. Every
 * outbound request:
 *
 *   1. Has its URL validated against the TLS pin allowlist (hostname +
 *      optional cert fingerprint).
 *   2. Has its URL, headers, and request body scanned for canary credentials
 *      BEFORE the packet leaves the process. A canary appearing here is a
 *      live exfiltration-in-progress signal.
 *   3. Has its response body scanned for canary credentials AFTER it arrives
 *      (covers server-side reflection attacks).
 *
 * The wrapper fails closed by default — violations raise, not log. Callers
 * who need soft-warn behavior pass `onViolation: 'warn'` explicitly.
 *
 * Intended usage:
 *
 *   // In agent/tool bootstrap:
 *   const secureFetch = createSecureFetch({
 *     canaryScanner: (text) => deployer.scan(text),
 *     tlsValidator: (url) => pinner.validate(url),
 *     onViolation: 'throw',
 *   });
 *   globalThis.fetch = secureFetch; // or inject into tool ctx
 *
 * Performance: validation + scan is O(canaryCount) string search + one URL
 * parse. Typical overhead on a request is sub-millisecond.
 */

// This package's tsconfig targets ES2022 only — no DOM, no Node types. Declare
// the minimal ambient surface we use so the file compiles everywhere without
// pulling DOM/Node into the lib config.
declare const console: { warn(...args: unknown[]): void };
declare const URL: {
  new (url: string, base?: string): { hostname: string; toString(): string };
  prototype: { hostname: string; toString(): string };
};
declare const TextDecoder: {
  new (label?: string, options?: { fatal?: boolean }): { decode(input: ArrayBufferLike | ArrayBufferView): string };
};

// ── Minimal structural types (no dependency on node/dom) ──
// We avoid importing DOM lib types so this file compiles in both runtimes.

/** The canonical fetch signature we wrap. */
export type FetchFn = (
  input: string | { url: string } | any,
  init?: any,
) => Promise<any>;

/** Result of a canary scan. Opaque to this module — we only count non-empty. */
export type CanaryScanResult = { canaryId?: string; value?: string; [k: string]: unknown };

/** Callable that scans an arbitrary string and returns any canary hits. */
export type CanaryScanFn = (text: string) => readonly CanaryScanResult[];

/** Result of TLS pin validation. */
export interface TLSValidationResult {
  valid: boolean;
  provider?: string;
  hostname?: string;
  reason?: string;
  /** Whether this is a known router (validator MAY mark valid with this flag). */
  router?: boolean;
}

/** Callable that validates a URL against TLS/hostname pins. */
export type TLSValidatorFn = (url: string) => TLSValidationResult;

/** How to react when a guard fires. */
export type ViolationPolicy = 'throw' | 'warn' | 'silent';

/** Opaque listener notified on any violation (for audit routing). */
export type ViolationListener = (violation: SecureFetchViolation) => void;

export interface SecureFetchViolation {
  kind: 'canary_in_request' | 'canary_in_response' | 'tls_pin_mismatch' | 'tls_unknown_host';
  url: string;
  /** When the violation was detected (unix ms). */
  detectedAt: number;
  /** Human-readable detail. */
  reason: string;
  /** Raw scan hits when relevant. */
  canaryHits?: readonly CanaryScanResult[];
  /** TLS validation payload when relevant. */
  tls?: TLSValidationResult;
}

export interface SecureFetchOptions {
  /** The underlying fetch implementation. Defaults to globalThis.fetch. */
  baseFetch?: FetchFn;
  /** Canary scanner. If omitted, canary checks are skipped. */
  canaryScanner?: CanaryScanFn;
  /** TLS pin validator. If omitted, TLS checks are skipped. */
  tlsValidator?: TLSValidatorFn;
  /**
   * What to do on a violation. `throw` fails the fetch (fail-closed).
   * `warn` logs to console and proceeds. `silent` only invokes `onViolation`.
   * Default: `throw`.
   */
  onViolation?: ViolationPolicy;
  /** Audit listener invoked on every violation, regardless of policy. */
  onViolationListener?: ViolationListener;
  /** Skip response-body scan. Useful for binary/streaming responses. Default false. */
  skipResponseScan?: boolean;
  /**
   * Maximum bytes of the response body to scan for canaries. Default 256KiB.
   * Larger responses are scanned up to the limit then skipped.
   */
  responseScanLimitBytes?: number;
  /** Allow-list of hostnames that bypass TLS validation (e.g. your own API). */
  allowlistHosts?: readonly string[];
}

export class SecureFetchViolationError extends Error {
  constructor(public readonly violation: SecureFetchViolation) {
    super(`[veridex:secure-fetch] ${violation.kind}: ${violation.reason}`);
    this.name = 'SecureFetchViolationError';
  }
}

const DEFAULT_RESPONSE_SCAN_LIMIT = 256 * 1024;

/**
 * Serialize request init for canary scanning. We stringify everything we
 * can see pre-flight. Body is converted to string when possible; opaque
 * bodies (streams, FormData with files) are scanned by their keys only.
 */
function serializeRequestForScan(
  url: string,
  init?: any,
): string {
  const parts: string[] = [url];

  if (init?.headers) {
    try {
      if (typeof init.headers.entries === 'function') {
        for (const [k, v] of init.headers.entries()) parts.push(`${k}:${v}`);
      } else {
        parts.push(JSON.stringify(init.headers));
      }
    } catch {
      // Ignore header serialization failures — URL scan still applies.
    }
  }

  if (init?.body != null) {
    const body = init.body;
    if (typeof body === 'string') {
      parts.push(body);
    } else if (body instanceof ArrayBuffer) {
      try {
        parts.push(new TextDecoder('utf-8', { fatal: false }).decode(body));
      } catch {
        /* ignore binary body */
      }
    } else if (ArrayBuffer.isView(body)) {
      try {
        parts.push(new TextDecoder('utf-8', { fatal: false }).decode(body));
      } catch {
        /* ignore */
      }
    } else {
      // Last resort: best-effort JSON
      try {
        parts.push(JSON.stringify(body));
      } catch {
        /* non-serializable */
      }
    }
  }

  return parts.join('\n');
}

function extractUrl(input: string | { url: string } | any): string {
  if (typeof input === 'string') return input;
  if (typeof URL !== 'undefined' && input instanceof (URL as any)) return (input as any).toString();
  if (input && typeof input.url === 'string') return input.url;
  return String(input);
}

function handleViolation(
  violation: SecureFetchViolation,
  policy: ViolationPolicy,
  listener?: ViolationListener,
): void {
  try {
    listener?.(violation);
  } catch {
    // Never let an audit listener break the request path.
  }
  if (policy === 'throw') {
    throw new SecureFetchViolationError(violation);
  }
  if (policy === 'warn') {
    // eslint-disable-next-line no-console
    console.warn(`[veridex:secure-fetch] ${violation.kind}: ${violation.reason}`);
  }
}

/**
 * Create a hardened fetch. Call once at bootstrap, reuse everywhere.
 */
export function createSecureFetch(options: SecureFetchOptions = {}): FetchFn {
  const baseFetch: FetchFn =
    options.baseFetch ??
    ((globalThis as any).fetch as FetchFn | undefined) ??
    (() => {
      throw new Error(
        '[veridex:secure-fetch] No base fetch implementation available. ' +
          'Provide `baseFetch` or run in an environment with globalThis.fetch.',
      );
    });

  const policy: ViolationPolicy = options.onViolation ?? 'throw';
  const scanLimit = options.responseScanLimitBytes ?? DEFAULT_RESPONSE_SCAN_LIMIT;
  const allowlist = new Set((options.allowlistHosts ?? []).map((h) => h.toLowerCase()));

  return async function secureFetch(input, init) {
    const url = extractUrl(input);
    let hostname: string | null = null;
    try {
      hostname = new URL(url).hostname.toLowerCase();
    } catch {
      hostname = null;
    }

    // 1. TLS pin / hostname validation
    if (options.tlsValidator && hostname && !allowlist.has(hostname)) {
      const tls = options.tlsValidator(url);
      if (!tls.valid) {
        handleViolation(
          {
            kind: tls.provider === 'unknown' ? 'tls_unknown_host' : 'tls_pin_mismatch',
            url,
            detectedAt: Date.now(),
            reason: tls.reason ?? `TLS validation failed for ${hostname}`,
            tls,
          },
          policy,
          options.onViolationListener,
        );
      }
    }

    // 2. Canary scan of the outgoing request
    if (options.canaryScanner) {
      const requestText = serializeRequestForScan(url, init);
      const hits = options.canaryScanner(requestText);
      if (hits.length > 0) {
        handleViolation(
          {
            kind: 'canary_in_request',
            url,
            detectedAt: Date.now(),
            reason: `${hits.length} canary value(s) detected in outbound request to ${hostname ?? url}. Exfiltration-in-progress signal.`,
            canaryHits: hits,
          },
          policy,
          options.onViolationListener,
        );
        // If policy is 'throw' we already threw. If 'warn'/'silent', proceed.
      }
    }

    // 3. Perform the request
    const response = await baseFetch(input as any, init);

    // 4. Canary scan of the response (optional, size-bounded)
    if (options.canaryScanner && !options.skipResponseScan && response && typeof response.clone === 'function') {
      try {
        const cloned = response.clone();
        const contentType: string =
          (typeof cloned.headers?.get === 'function' && cloned.headers.get('content-type')) || '';
        // Only scan text-ish responses. Binary (image/*, application/octet-stream) is skipped.
        const looksTextual =
          !contentType ||
          contentType.startsWith('text/') ||
          contentType.includes('json') ||
          contentType.includes('xml') ||
          contentType.includes('javascript') ||
          contentType.includes('html');

        if (looksTextual) {
          const body = await cloned.text();
          const truncated = body.length > scanLimit ? body.slice(0, scanLimit) : body;
          const hits = options.canaryScanner(truncated);
          if (hits.length > 0) {
            handleViolation(
              {
                kind: 'canary_in_response',
                url,
                detectedAt: Date.now(),
                reason: `${hits.length} canary value(s) reflected in response from ${hostname ?? url}. Replay or server-side exfil signal.`,
                canaryHits: hits,
              },
              policy,
              options.onViolationListener,
            );
          }
        }
      } catch (err) {
        // A deliberate violation (fail-closed) must propagate. Accidental
        // scan failures (cannot clone, body already consumed, decode error)
        // must not break the caller.
        if (err instanceof SecureFetchViolationError) throw err;
      }
    }

    return response;
  };
}
