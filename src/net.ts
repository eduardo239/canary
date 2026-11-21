/**
 * Rede: novas tentativas para falhas passageiras e mensagens de erro legíveis.
 *
 * "fetch failed" (TypeError do undici) esconde o motivo real em `err.cause`
 * (ENOTFOUND, ECONNRESET, ETIMEDOUT...). Falhas assim são comuns logo ao abrir o VS Code,
 * quando a rede/DNS ainda não está pronta (especialmente no WSL).
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

/** Erro HTTP com status, para decidir se vale tentar de novo. */
export class HttpError extends Error {
  constructor(readonly status: number, message: string) {
    super(message);
    this.name = 'HttpError';
  }
}

function causeCode(err: any): string | undefined {
  return err?.cause?.code ?? err?.cause?.cause?.code ?? err?.code;
}

/** true quando o usuário cancelou (não é falha de rede e não deve ser repetido). */
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
  // "fetch failed" sem código conhecido: na prática quase sempre é rede
  return err instanceof TypeError && /fetch failed/i.test(err.message);
}

export interface RetryOptions {
  attempts: number;
  baseDelayMs: number;
  signal?: AbortSignal;
  onRetry?: (attempt: number, delayMs: number, err: unknown) => void;
}

/** Executa `fn` com novas tentativas e espera exponencial (1x, 2x, 4x... com variação aleatória). */
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

/** Mensagem curta e acionável, com o motivo real da falha. */
export function describeError(err: any, host = 'api.osv.dev'): string {
  if (err instanceof HttpError) {
    if (err.status === 429) {
      return `${host} limitou as requisições (HTTP 429); tente de novo em instantes`;
    }
    return err.message;
  }
  if (err?.name === 'TimeoutError') {
    return `tempo esgotado ao falar com ${host}`;
  }
  const code = causeCode(err);
  switch (code) {
    case 'ENOTFOUND':
    case 'EAI_AGAIN':
      return `não foi possível resolver ${host} (DNS). Sem internet ou a rede ainda está iniciando?`;
    case 'ECONNREFUSED':
      return `conexão recusada por ${host} (firewall ou proxy?)`;
    case 'ECONNRESET':
    case 'EPIPE':
    case 'UND_ERR_SOCKET':
    case 'UND_ERR_CLOSED':
      return `a conexão com ${host} foi interrompida`;
    case 'ETIMEDOUT':
    case 'UND_ERR_CONNECT_TIMEOUT':
    case 'UND_ERR_HEADERS_TIMEOUT':
    case 'UND_ERR_BODY_TIMEOUT':
      return `tempo esgotado ao conectar a ${host}`;
    case 'ENETUNREACH':
    case 'ENETDOWN':
    case 'EHOSTUNREACH':
      return `rede indisponível para alcançar ${host}`;
    case 'SELF_SIGNED_CERT_IN_CHAIN':
    case 'DEPTH_ZERO_SELF_SIGNED_CERT':
    case 'UNABLE_TO_GET_ISSUER_CERT_LOCALLY':
    case 'UNABLE_TO_VERIFY_LEAF_SIGNATURE':
    case 'CERT_HAS_EXPIRED':
      return `certificado TLS inválido para ${host} (${code}); um proxy corporativo pode estar interceptando o HTTPS`;
  }
  const base = err?.message ?? String(err);
  const detail = err?.cause?.message;
  return detail && detail !== base ? `${base}: ${detail}` : base;
}
