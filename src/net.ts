/**
 * Network: retries for transient failures and readable error messages.
 *
 * "fetch failed" (undici TypeError) hides the real reason in `err.cause`
 * (ENOTFOUND, ECONNRESET, ETIMEDOUT...). Such failures are common right after VS Code opens,
 * when the network/DNS is not ready yet (especially on WSL).
 */

const TRANSIENT_CODES = new Set([
  'ENOTFOUND',
  'EAI_AGAIN',
  'ECONNRESET',
  'ECONNREFUSED',
  'ECONNABORTED',
  'ETIMEDOUT',
  'EPIPE',
  'ENETUNREACH',
  'ENETDOWN',
  'EHOSTUNREACH',
  'UND_ERR_CONNECT_TIMEOUT',
  'UND_ERR_HEADERS_TIMEOUT',
  'UND_ERR_BODY_TIMEOUT',
  'UND_ERR_SOCKET',
  'UND_ERR_CLOSED',
]);

/** HTTP error carrying the status, to decide whether a retry is worthwhile. */
export class HttpError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
    this.name = 'HttpError';
  }
}

function causeCode(err: any): string | undefined {
  return err?.cause?.code ?? err?.cause?.cause?.code ?? err?.code;
}

/** true when the user cancelled (not a network failure; must not be retried). */
export function isUserAbort(err: any, signal?: AbortSignal): boolean {
  return !!signal?.aborted && err?.name !== 'TimeoutError';
}

export function isTransient(err: any): boolean {
  if (err instanceof HttpError) {
    return err.status === 408 || err.status === 429 || err.status >= 500;
  }
  if (err?.name === 'TimeoutError') {
    return true;
  }
  const code = causeCode(err);
  if (code && TRANSIENT_CODES.has(code)) {
    return true;
  }
  // "fetch failed" without a known code: in practice it is almost always the network
  return err instanceof TypeError && /fetch failed/i.test(err.message);
}

export interface RetryOptions {
  attempts: number;
  baseDelayMs: number;
  signal?: AbortSignal;
  onRetry?: (attempt: number, delayMs: number, err: unknown) => void;
}

/** Runs `fn` with retries and exponential backoff (1x, 2x, 4x... with random jitter). */
export async function withRetry<T>(fn: () => Promise<T>, opts: RetryOptions): Promise<T> {
  let lastErr: unknown;
  for (let attempt = 1; attempt <= opts.attempts; attempt++) {
    try {
      return await fn();
    } catch (err) {
      lastErr = err;
      if (isUserAbort(err, opts.signal) || !isTransient(err) || attempt === opts.attempts) {
        throw err;
      }
      const delay = opts.baseDelayMs * 2 ** (attempt - 1) * (0.8 + Math.random() * 0.4);
      opts.onRetry?.(attempt, Math.round(delay), err);
      await sleep(delay, opts.signal);
    }
  }
  throw lastErr;
}

function sleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason);
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener('abort', onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(signal!.reason);
    };
    signal?.addEventListener('abort', onAbort, { once: true });
  });
}

/** Short, actionable message with the real reason for the failure. */
export function describeError(err: any, host = 'api.osv.dev'): string {
  if (err instanceof HttpError) {
    if (err.status === 429) {
      return `${host} rate-limited the requests (HTTP 429); try again in a moment`;
    }
    return err.message;
  }
  if (err?.name === 'TimeoutError') {
    return `timed out talking to ${host}`;
  }
  const code = causeCode(err);
  switch (code) {
    case 'ENOTFOUND':
    case 'EAI_AGAIN':
      return `could not resolve ${host} (DNS). No internet, or is the network still starting up?`;
    case 'ECONNREFUSED':
      return `connection refused by ${host} (firewall or proxy?)`;
    case 'ECONNRESET':
    case 'EPIPE':
    case 'UND_ERR_SOCKET':
    case 'UND_ERR_CLOSED':
      return `the connection to ${host} was interrupted`;
    case 'ETIMEDOUT':
    case 'UND_ERR_CONNECT_TIMEOUT':
    case 'UND_ERR_HEADERS_TIMEOUT':
    case 'UND_ERR_BODY_TIMEOUT':
      return `timed out connecting to ${host}`;
    case 'ENETUNREACH':
    case 'ENETDOWN':
    case 'EHOSTUNREACH':
      return `network unavailable to reach ${host}`;
    case 'SELF_SIGNED_CERT_IN_CHAIN':
    case 'DEPTH_ZERO_SELF_SIGNED_CERT':
    case 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY':
    case 'UNABLE_TO_VERIFY_LEAF_SIGNATURE':
    case 'CERT_HAS_EXPIRED':
      return `invalid TLS certificate for ${host} (${code}); a corporate proxy may be intercepting HTTPS`;
  }
  const base = err?.message ?? String(err);
  const detail = err?.cause?.message;
  return detail && detail !== base ? `${base}: ${detail}` : base;
}
