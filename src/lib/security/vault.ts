/**
 * Enterprise Tenant Vault (AES-256-GCM Encryption at Rest),
 * Gateway API Key Manager (`aiforge_live_...`), Plan Quotas,
 * and Real-Time Webhook Alert Dispatcher (Slack / Discord / Teams / Generic JSON).
 */

import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  randomBytes,
  scryptSync,
  timingSafeEqual,
} from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { isSafeExternalUrl } from '../adapters/capability/web-search-real';

export interface EncryptedSecretBlob {
  iv: string;
  authTag: string;
  ciphertext: string;
  updatedAt: string;
  maskedPreview: string;
}

export interface GatewayApiKeyRecord {
  id: string;
  name: string;
  organizationId: string;
  prefix: string;
  keyHashSha256: string;
  scopes: string[];
  createdAt: string;
  lastUsedAt?: string | null;
  revoked: boolean;
}

export interface TenantSaasConfig {
  organizationId: string;
  organizationName: string;
  planTier: 'starter' | 'growth' | 'enterprise';
  monthlyRunQuota: number;
  secrets: {
    githubToken?: EncryptedSecretBlob;
    openaiApiKey?: EncryptedSecretBlob;
    nvidiaApiKey?: EncryptedSecretBlob;
    geminiApiKey?: EncryptedSecretBlob;
    webhookUrl?: EncryptedSecretBlob;
    githubWebhookSecret?: EncryptedSecretBlob;
  };
  apiKeys: GatewayApiKeyRecord[];
  updatedAt: string;
}

const memoryVault = new Map<string, TenantSaasConfig>();

let cachedMasterKey: Buffer | null = null;
let cachedRawSecretUsed: string | null = null;

function getMasterKey(): Buffer {
  const configured =
    process.env.AI_FORGE_VAULT_KEY ??
    process.env.AUTH_SECRET ??
    process.env.NEXTAUTH_SECRET;

  if (
    process.env.NODE_ENV === 'production' &&
    process.env.AI_FORGE_ALLOW_DEMO_AUTH !== '1' &&
    (!configured || configured === 'dev-only-change-me' || configured.length < 16)
  ) {
    throw new Error(
      'Missing or insecure AI_FORGE_VAULT_KEY / AUTH_SECRET in production environment (SEC-05 / SEC-17).'
    );
  }

  const rawSecret = configured ?? 'ai-forge-default-enterprise-vault-master-key-2026';
  if (cachedMasterKey && cachedRawSecretUsed === rawSecret) {
    return cachedMasterKey;
  }
  cachedRawSecretUsed = rawSecret;
  cachedMasterKey = scryptSync(rawSecret, 'ai-forge-vault-kdf-salt-v1', 32);
  return cachedMasterKey;
}

function getVaultFilePath(): string {
  const baseDir = process.env.AI_FORGE_DATA_DIR ?? path.join(process.cwd(), '.data');
  return path.join(baseDir, 'vault', 'tenant-vault.json');
}

function maskSecret(plaintext: string): string {
  const trimmed = plaintext.trim();
  if (trimmed.length <= 8) return '••••••••';
  return `${trimmed.slice(0, 4)}••••••••${trimmed.slice(-4)}`;
}

/**
 * Encrypts a plaintext secret using AES-256-GCM with a unique 96-bit IV.
 */
export function encryptSecretAes256Gcm(plaintext: string): EncryptedSecretBlob {
  const key = getMasterKey();
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  return {
    iv: iv.toString('base64'),
    authTag: authTag.toString('base64'),
    ciphertext: encrypted.toString('base64'),
    updatedAt: new Date().toISOString(),
    maskedPreview: maskSecret(plaintext),
  };
}

/**
 * Decrypts an AES-256-GCM encrypted secret blob.
 */
export function decryptSecretAes256Gcm(blob: EncryptedSecretBlob): string {
  const key = getMasterKey();
  const iv = Buffer.from(blob.iv, 'base64');
  const authTag = Buffer.from(blob.authTag, 'base64');
  const ciphertext = Buffer.from(blob.ciphertext, 'base64');

  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(authTag);
  const decrypted = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  return decrypted.toString('utf8');
}

function loadVaultFromDisk(): void {
  if (process.env.AI_FORGE_STORE === 'memory' || process.env.VITEST) return;
  try {
    const file = getVaultFilePath();
    if (!fs.existsSync(file)) return;
    const raw = JSON.parse(fs.readFileSync(file, 'utf8')) as Array<[string, TenantSaasConfig]>;
    for (const [orgId, cfg] of raw) {
      memoryVault.set(orgId, cfg);
    }
  } catch {
    // Ignore read errors
  }
}

function saveVaultToDisk(): void {
  if (process.env.AI_FORGE_STORE === 'memory' || process.env.VITEST) return;
  try {
    const file = getVaultFilePath();
    fs.mkdirSync(path.dirname(file), { recursive: true });
    const tmp = `${file}.tmp`;
    fs.writeFileSync(tmp, JSON.stringify([...memoryVault.entries()], null, 2), {
      encoding: 'utf8',
      mode: 0o600,
    });
    fs.renameSync(tmp, file);
  } catch {
    // Ignore write errors
  }
}

export function getTenantSaasConfig(organizationId: string): TenantSaasConfig {
  if (memoryVault.size === 0) {
    loadVaultFromDisk();
  }
  const existing = memoryVault.get(organizationId);
  if (existing) return existing;

  const initial: TenantSaasConfig = {
    organizationId,
    organizationName: 'Acme Enterprise Security',
    planTier: 'enterprise',
    monthlyRunQuota: 10_000,
    secrets: {},
    apiKeys: [],
    updatedAt: new Date().toISOString(),
  };
  memoryVault.set(organizationId, initial);
  saveVaultToDisk();
  return initial;
}

export function updateTenantSaasConfig(
  organizationId: string,
  input: {
    organizationName?: string;
    planTier?: 'starter' | 'growth' | 'enterprise';
    secrets?: {
      githubToken?: string;
      openaiApiKey?: string;
      nvidiaApiKey?: string;
      geminiApiKey?: string;
      webhookUrl?: string;
      githubWebhookSecret?: string;
    };
  }
): TenantSaasConfig {
  const current = getTenantSaasConfig(organizationId);
  if (input.organizationName) {
    current.organizationName = input.organizationName.trim();
  }
  if (input.planTier) {
    current.planTier = input.planTier;
    current.monthlyRunQuota =
      input.planTier === 'enterprise' ? 10_000 : input.planTier === 'growth' ? 1000 : 100;
  }

  if (input.secrets) {
    if (input.secrets.webhookUrl && input.secrets.webhookUrl.trim().length > 0) {
      const check = isSafeExternalUrl(input.secrets.webhookUrl.trim());
      if (!check.safe) {
        throw new Error(`Invalid webhookUrl (${check.reason}): must be a public HTTPS URL`);
      }
    }

    for (const key of [
      'githubToken',
      'openaiApiKey',
      'nvidiaApiKey',
      'geminiApiKey',
      'webhookUrl',
      'githubWebhookSecret',
    ] as const) {
      const val = input.secrets[key];
      if (typeof val === 'string' && val.trim().length > 0) {
        current.secrets[key] = encryptSecretAes256Gcm(val.trim());
      }
    }
  }

  current.updatedAt = new Date().toISOString();
  memoryVault.set(organizationId, current);
  saveVaultToDisk();
  return current;
}

export function getDecryptedTenantSecret(
  organizationId: string,
  secretName: keyof TenantSaasConfig['secrets']
): string | null {
  const cfg = getTenantSaasConfig(organizationId);
  const blob = cfg.secrets[secretName];
  if (!blob) return null;
  try {
    return decryptSecretAes256Gcm(blob);
  } catch {
    return null;
  }
}

/**
 * Generates a new AI Forge Gateway API key (`aiforge_live_<48_hex>`).
 * Returns the raw key ONLY ONCE; stores only the SHA-256 hash.
 */
export function createGatewayApiKey(
  organizationId: string,
  name: string,
  scopes: string[] = ['gateway:authorize', 'gateway:evidence', 'run:execute']
): { rawKey: string; record: GatewayApiKeyRecord } {
  const cfg = getTenantSaasConfig(organizationId);
  const tokenHex = randomBytes(24).toString('hex');
  const rawKey = `aiforge_live_${tokenHex}`;
  const keyHashSha256 = createHash('sha256').update(rawKey, 'utf8').digest('hex');

  const record: GatewayApiKeyRecord = {
    id: `key_${Date.now().toString(36)}_${randomBytes(3).toString('hex')}`,
    name: name.trim() || 'Production Agent Key',
    organizationId,
    prefix: `aiforge_live_${tokenHex.slice(0, 6)}…`,
    keyHashSha256,
    scopes,
    createdAt: new Date().toISOString(),
    lastUsedAt: null,
    revoked: false,
  };

  cfg.apiKeys.unshift(record);
  cfg.updatedAt = new Date().toISOString();
  memoryVault.set(organizationId, cfg);
  saveVaultToDisk();

  return { rawKey, record };
}

export function revokeGatewayApiKey(organizationId: string, keyId: string): boolean {
  const cfg = getTenantSaasConfig(organizationId);
  const found = cfg.apiKeys.find((k) => k.id === keyId);
  if (!found) return false;
  found.revoked = true;
  cfg.updatedAt = new Date().toISOString();
  memoryVault.set(organizationId, cfg);
  saveVaultToDisk();
  return true;
}

export function validateGatewayApiKey(rawKey: string): GatewayApiKeyRecord | null {
  if (!rawKey.startsWith('aiforge_live_')) return null;
  if (memoryVault.size === 0) {
    loadVaultFromDisk();
  }
  const candidateHash = createHash('sha256').update(rawKey.trim(), 'utf8').digest('hex');
  for (const cfg of memoryVault.values()) {
    for (const k of cfg.apiKeys) {
      if (!k.revoked && k.keyHashSha256 === candidateHash) {
        k.lastUsedAt = new Date().toISOString();
        saveVaultToDisk();
        return k;
      }
    }
  }
  return null;
}

/**
 * Verifies a GitHub Webhook HMAC-SHA256 signature (`X-Hub-Signature-256: sha256=...`).
 */
export function verifyGitHubWebhookSignature(
  payloadBody: string,
  signatureHeader: string | null,
  secret: string
): boolean {
  if (!signatureHeader || !signatureHeader.startsWith('sha256=')) return false;
  const expected =
    'sha256=' + createHmac('sha256', secret).update(payloadBody, 'utf8').digest('hex');
  try {
    const a = Buffer.from(signatureHeader, 'utf8');
    const b = Buffer.from(expected, 'utf8');
    if (a.length !== b.length) return false;
    return timingSafeEqual(a, b);
  } catch {
    return false;
  }
}

/**
 * Dispatches a real-time governance alert to Slack, Discord, Microsoft Teams, or a custom Webhook.
 */
export async function dispatchGovernanceWebhookAlert(
  organizationId: string,
  event: {
    title: string;
    severity: 'info' | 'warning' | 'critical';
    eventType: string;
    details: Record<string, unknown>;
  }
): Promise<{ sent: boolean; status?: number; mode: string }> {
  const webhookUrl =
    getDecryptedTenantSecret(organizationId, 'webhookUrl') ?? process.env.AI_FORGE_WEBHOOK_URL;
  if (!webhookUrl) {
    return { sent: false, mode: 'no_webhook_configured' };
  }

  const safetyCheck = isSafeExternalUrl(webhookUrl);
  if (!safetyCheck.safe) {
    return { sent: false, mode: `blocked_ssrf_${safetyCheck.reason}` };
  }

  try {
    const body = {
      text: `*[AI Forge ${event.severity.toUpperCase()}]* ${event.title} (${event.eventType})`,
      content: `**[AI Forge ${event.severity.toUpperCase()}]** ${event.title} (\`${event.eventType}\`)`,
      aiForgeEvent: {
        organizationId,
        timestamp: new Date().toISOString(),
        ...event,
      },
    };

    const res = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      redirect: 'error',
      signal: AbortSignal.timeout(5000),
    });

    return { sent: res.ok, status: res.status, mode: 'live-webhook' };
  } catch {
    return { sent: false, mode: 'webhook_delivery_failed' };
  }
}

export function resetVaultForTests(): void {
  memoryVault.clear();
}

