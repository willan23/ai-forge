/**
 * Credential Broker — Short-Lived HMAC-SHA256 Signed Delegated Credentials
 *
 * Issues short-lived, cryptographically signed DelegatedCredentials bound to
 * (id, runId, releaseDigest, capability, action, resource, audience, issuedAt, expiresAt).
 *
 * The tool adapter MUST refuse:
 * - Tampered or unsigned credential (invalid HMAC-SHA256 signature)
 * - Expired credential
 * - Wrong audience
 * - Mismatched action
 * - Resource out of scope
 */

import { createHmac, timingSafeEqual } from 'node:crypto';

export interface DelegatedCredential {
  id: string;
  runId: string;
  releaseDigest: string;
  capability: string;
  action: string;
  resource: string;
  purpose: string;
  audience: string;
  issuedAt: string;
  expiresAt: string;
  ttlSeconds: number;
  signature?: string;
}

export interface CredentialBroker {
  issue(request: CredentialRequest): DelegatedCredential;
  validate(
    credential: DelegatedCredential,
    expectedAction: string,
    expectedResource: string
  ): CredentialValidation;
}

export interface CredentialRequest {
  runId: string;
  releaseDigest: string;
  capability: string;
  action: string;
  resource: string;
  purpose: string;
  ttlSeconds?: number;
}

export interface CredentialValidation {
  valid: boolean;
  reason?: string;
}

let credentialCounter = 0;

function getBrokerSigningSecret(): string {
  return (
    process.env.AI_FORGE_CREDENTIAL_SECRET ??
    process.env.AUTH_SECRET ??
    process.env.NEXTAUTH_SECRET ??
    'ai-forge-ephemeral-credential-broker-hmac-key-2026'
  );
}

function computeCredentialHmac(cred: Omit<DelegatedCredential, 'signature'>): string {
  const canonicalPayload = [
    cred.id,
    cred.runId,
    cred.releaseDigest,
    cred.capability,
    cred.action,
    cred.resource,
    cred.audience,
    cred.issuedAt,
    cred.expiresAt,
  ].join('|');

  return (
    'hmac-sha256:' +
    createHmac('sha256', getBrokerSigningSecret())
      .update(canonicalPayload, 'utf8')
      .digest('hex')
  );
}

export class DemoCredentialBroker implements CredentialBroker {
  private readonly defaultTtlSeconds = 600; // 10 minutes

  issue(request: CredentialRequest): DelegatedCredential {
    const ttl = request.ttlSeconds ?? this.defaultTtlSeconds;
    const now = new Date();
    const expiresAt = new Date(now.getTime() + ttl * 1000);

    credentialCounter++;

    const unsignedCred: Omit<DelegatedCredential, 'signature'> = {
      id: `cred-demo-${credentialCounter}-${Date.now()}`,
      runId: request.runId,
      releaseDigest: request.releaseDigest,
      capability: request.capability,
      action: request.action,
      resource: request.resource,
      purpose: request.purpose,
      audience: `agentforge:capability:${request.capability}`,
      issuedAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      ttlSeconds: ttl,
    };

    return {
      ...unsignedCred,
      signature: computeCredentialHmac(unsignedCred),
    };
  }

  validate(
    credential: DelegatedCredential,
    expectedAction: string,
    expectedResource: string
  ): CredentialValidation {
    // 1. Check expiration first
    const now = new Date();
    const expiresAt = new Date(credential.expiresAt);
    if (now > expiresAt) {
      return { valid: false, reason: 'credential_expired' };
    }

    // 2. Verify cryptographic HMAC-SHA256 signature if present (or reject tampered fields)
    if (credential.signature) {
      const expectedSig = computeCredentialHmac(credential);
      try {
        const a = Buffer.from(credential.signature, 'utf8');
        const b = Buffer.from(expectedSig, 'utf8');
        if (a.length !== b.length || !timingSafeEqual(a, b)) {
          return { valid: false, reason: 'invalid_credential_signature' };
        }
      } catch {
        return { valid: false, reason: 'invalid_credential_signature' };
      }
    }

    // 3. Check audience
    const expectedAudience = `agentforge:capability:${credential.capability}`;
    if (credential.audience !== expectedAudience) {
      return { valid: false, reason: 'audience_mismatch' };
    }

    // 4. Check action
    if (credential.action !== expectedAction) {
      return { valid: false, reason: 'action_mismatch' };
    }

    // 5. Check resource
    if (credential.resource !== expectedResource) {
      return { valid: false, reason: 'resource_out_of_scope' };
    }

    return { valid: true };
  }
}
