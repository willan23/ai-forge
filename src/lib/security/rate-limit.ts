/**
 * Multi-dimensional rate limiter (SEC-09).
 * Enforces limits by userId, organizationId, and endpoint with automatic
 * expired-bucket pruning to prevent unbounded memory growth.
 */

export interface RateLimitConfig {
  windowMs: number;
  maxRequests: number;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
  resetAt: string;
  limitKey: string;
}

type Bucket = {
  count: number;
  resetTime: number;
};

const MAX_BUCKETS = 10_000;
const buckets = new Map<string, Bucket>();

const DEFAULT_CONFIG: RateLimitConfig = {
  windowMs: 60_000,
  maxRequests: 120,
};

function pruneExpiredBuckets(now: number): void {
  if (buckets.size < MAX_BUCKETS) return;
  for (const [k, v] of buckets.entries()) {
    if (now >= v.resetTime) {
      buckets.delete(k);
    }
  }
  if (buckets.size >= MAX_BUCKETS) {
    const oldestKey = buckets.keys().next().value;
    if (oldestKey) buckets.delete(oldestKey);
  }
}

export function checkRateLimit(
  params: {
    userId: string;
    organizationId: string;
    endpoint: string;
  },
  config: RateLimitConfig = DEFAULT_CONFIG
): RateLimitResult {
  const now = Date.now();
  pruneExpiredBuckets(now);

  const limitKey = `${params.organizationId}:${params.userId}:${params.endpoint}`;
  const existing = buckets.get(limitKey);

  if (!existing || now >= existing.resetTime) {
    const resetTime = now + config.windowMs;
    buckets.set(limitKey, { count: 1, resetTime });
    return {
      allowed: true,
      remaining: config.maxRequests - 1,
      resetAt: new Date(resetTime).toISOString(),
      limitKey,
    };
  }

  existing.count += 1;
  const allowed = existing.count <= config.maxRequests;
  return {
    allowed,
    remaining: Math.max(0, config.maxRequests - existing.count),
    resetAt: new Date(existing.resetTime).toISOString(),
    limitKey,
  };
}

export function resetRateLimits(): void {
  buckets.clear();
}
