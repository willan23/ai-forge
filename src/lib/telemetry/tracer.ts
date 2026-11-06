/**
 * OpenTelemetry-compatible tracing & metrics instrumentation (Section 14.3).
 *
 * Operations instrumented:
 * - `agent.release.create`
 * - `evaluation.run`
 * - `policy.decision`
 * - `capability.invoke`
 * - `agent.run`
 * - `evidence.bundle.finalize`
 */

export interface TelemetrySpan {
  spanId: string;
  traceId: string;
  parentSpanId?: string;
  name:
    | 'agent.release.create'
    | 'evaluation.run'
    | 'policy.decision'
    | 'capability.invoke'
    | 'agent.run'
    | 'evidence.bundle.finalize'
    | string;
  startedAt: string;
  endedAt: string;
  durationMs: number;
  status: 'ok' | 'error' | 'blocked';
  attributes: Record<string, string | number | boolean | undefined>;
}

const spanStore: TelemetrySpan[] = [];

function genId(prefix: string): string {
  return `${prefix}_${Math.random().toString(36).slice(2, 10)}${Date.now().toString(36)}`;
}

export function recordSpan(span: Omit<TelemetrySpan, 'spanId'> & { spanId?: string }): TelemetrySpan {
  const full: TelemetrySpan = {
    ...span,
    spanId: span.spanId ?? genId('span'),
  };
  spanStore.push(full);
  if (spanStore.length > 1000) {
    spanStore.shift();
  }
  return full;
}

export async function withSpan<T>(
  params: {
    traceId: string;
    parentSpanId?: string;
    name: TelemetrySpan['name'];
    attributes?: Record<string, string | number | boolean | undefined>;
  },
  fn: (spanId: string) => Promise<T> | T
): Promise<T> {
  const spanId = genId('span');
  const startMs = Date.now();
  const startedAt = new Date(startMs).toISOString();
  try {
    const res = await fn(spanId);
    const endMs = Date.now();
    recordSpan({
      spanId,
      traceId: params.traceId,
      parentSpanId: params.parentSpanId,
      name: params.name,
      startedAt,
      endedAt: new Date(endMs).toISOString(),
      durationMs: Math.max(1, endMs - startMs),
      status: 'ok',
      attributes: params.attributes ?? {},
    });
    return res;
  } catch (err) {
    const endMs = Date.now();
    recordSpan({
      spanId,
      traceId: params.traceId,
      parentSpanId: params.parentSpanId,
      name: params.name,
      startedAt,
      endedAt: new Date(endMs).toISOString(),
      durationMs: Math.max(1, endMs - startMs),
      status: 'error',
      attributes: {
        ...(params.attributes ?? {}),
        error: err instanceof Error ? err.message : String(err),
      },
    });
    throw err;
  }
}

export function listSpansByTraceId(traceId: string): TelemetrySpan[] {
  return spanStore.filter((s) => s.traceId === traceId);
}

export function clearSpans(): void {
  spanStore.length = 0;
}

