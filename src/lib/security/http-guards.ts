/**
 * HTTP Security Guards:
 * - CSRF Origin / Host verification for state-changing requests (SEC-13)
 * - Safe relative callback URL validation against Open Redirects (A27)
 * - Error message sanitization to prevent internal path/driver leakage (SEC-16)
 */

export function verifyCsrfOrigin(request: Request): { valid: boolean; reason?: string } {
  const method = request.method.toUpperCase();
  if (method === 'GET' || method === 'HEAD' || method === 'OPTIONS') {
    return { valid: true };
  }

  const origin = request.headers.get('origin');
  // Non-browser API clients (e.g., server-to-server SDKs or Vitest unit tests) often omit Origin
  if (!origin) {
    return { valid: true };
  }

  try {
    const originUrl = new URL(origin);
    const hostHeader =
      request.headers.get('x-forwarded-host') ??
      request.headers.get('host') ??
      new URL(request.url).host;

    const allowedOrigins = (process.env.AI_FORGE_ALLOWED_ORIGINS ?? '')
      .split(',')
      .map((s) => s.trim())
      .filter(Boolean);

    if (allowedOrigins.includes(origin)) {
      return { valid: true };
    }

    if (hostHeader && originUrl.host === hostHeader) {
      return { valid: true };
    }

    // Allow localhost <-> 127.0.0.1 equivalence in local development / Playwright
    const isLocalOrigin =
      originUrl.hostname === 'localhost' || originUrl.hostname === '127.0.0.1';
    const isLocalHost =
      hostHeader.startsWith('localhost:') ||
      hostHeader.startsWith('127.0.0.1:') ||
      hostHeader === 'localhost' ||
      hostHeader === '127.0.0.1';

    if (isLocalOrigin && isLocalHost && process.env.NODE_ENV !== 'production') {
      return { valid: true };
    }

    return {
      valid: false,
      reason: `csrf_origin_mismatch: origin ${originUrl.host} does not match host ${hostHeader}`,
    };
  } catch {
    return { valid: false, reason: 'csrf_invalid_origin_header' };
  }
}

export function assertCsrfOrigin(request: Request): void {
  const res = verifyCsrfOrigin(request);
  if (!res.valid) {
    throw new Error(`Forbidden: ${res.reason}`);
  }
}

export function isSafeCallbackPath(rawUrl: string | null | undefined): string {
  if (!rawUrl || typeof rawUrl !== 'string') return '/';
  const trimmed = rawUrl.trim();
  if (trimmed.startsWith('/') && !trimmed.startsWith('//') && !trimmed.includes('\\')) {
    return trimmed;
  }
  try {
    const parsed = new URL(trimmed);
    if (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1') {
      return `${parsed.pathname}${parsed.search}`;
    }
  } catch {
    // Fall through
  }
  return '/';
}

const SAFE_ERROR_PATTERNS = [
  /^Forbidden/i,
  /^Unauthorized/i,
  /^Rate limit/i,
  /^Invalid/i,
  /^Missing/i,
  /^Approval/i,
  /^Agent/i,
  /^Workspace/i,
  /^Release/i,
  /^Run/i,
  /^Commit/i,
  /^ChangeProposal/i,
  /^kill_switch_active/i,
  /^four_eyes_violation/i,
  /^ssrf_/i,
  /^only_https_allowed/i,
  /^csrf_/i,
  /required/i,
  /not found/i,
];

export function sanitizeApiError(error: unknown, fallback = 'Request failed'): string {
  if (!(error instanceof Error)) return fallback;
  const msg = error.message;
  if (SAFE_ERROR_PATTERNS.some((re) => re.test(msg))) {
    return msg;
  }
  // Mask raw filesystem paths or SQL/Prisma stack snippets
  if (msg.includes('Prisma') || msg.includes('ECONNREFUSED') || /[A-Za-z]:\\|\/app\/\.data/.test(msg)) {
    return fallback;
  }
  return msg.slice(0, 240);
}

