/**
 * Audit logger — writes administrative and security events.
 * Persistence is injected so domain logic stays DB-agnostic in unit tests.
 */

export interface AuditEvent {
  organizationId: string;
  actorType: 'user' | 'agent' | 'system';
  actorId: string;
  action: string;
  targetType?: string;
  targetId?: string;
  metadataJson?: Record<string, unknown>;
  timestamp?: string;
}

export interface AuditSink {
  write(event: AuditEvent): Promise<void> | void;
}

const SECRET_VALUE_PATTERNS = [
  /Bearer\s+[A-Za-z0-9\-._~+/]+=*/gi,
  /sk-[A-Za-z0-9]{20,}/g,
  /password\s*[:=]\s*\S+/gi,
  /api[_-]?key\s*[:=]\s*\S+/gi,
];

/**
 * Redact secret-like patterns from arbitrary string payloads before logging.
 */
export function redactSecrets(text: string): string {
  let result = text;
  for (const pattern of SECRET_VALUE_PATTERNS) {
    result = result.replace(pattern, '[REDACTED]');
  }
  return result;
}

export class AuditLogger {
  constructor(private readonly sink: AuditSink) {}

  async log(event: AuditEvent): Promise<void> {
    const safeMetadata = event.metadataJson
      ? JSON.parse(redactSecrets(JSON.stringify(event.metadataJson)))
      : undefined;

    await this.sink.write({
      ...event,
      metadataJson: safeMetadata,
      timestamp: event.timestamp ?? new Date().toISOString(),
    });
  }
}

/** In-memory sink for tests and demo without DB. */
export class InMemoryAuditSink implements AuditSink {
  readonly events: AuditEvent[] = [];

  write(event: AuditEvent): void {
    this.events.push(event);
  }
}
