import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject,
} from 'node:crypto';
import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  encryptSecretAes256Gcm,
  decryptSecretAes256Gcm,
  type EncryptedSecretBlob,
} from '../../security/vault';

export interface Ed25519KeypairRecord {
  keyId: string;
  algorithm: 'Ed25519';
  publicKeyPem: string;
  privateKeyPem: string;
  fingerprintSha256: string;
  createdAt: string;
}

interface StoredEncryptedKeypairFile {
  keyId: string;
  algorithm: 'Ed25519';
  publicKeyPem: string;
  encryptedPrivateKey?: EncryptedSecretBlob;
  privateKeyPem?: string; // Legacy backward compatibility
  fingerprintSha256: string;
  createdAt: string;
}

export interface PublicKeyMetadata {
  keyId: string;
  algorithm: 'Ed25519';
  publicKeyPem: string;
  fingerprintSha256: string;
  createdAt: string;
}

export interface Ed25519SignatureResult {
  signature: string;
  keyId: string;
  algorithm: 'Ed25519';
  publicKeyFingerprint: string;
  signedAt: string;
}

let cachedRecord: Ed25519KeypairRecord | null = null;
let cachedPrivateKey: KeyObject | null = null;
let cachedPublicKey: KeyObject | null = null;

function computeKeyFingerprint(publicKeyPem: string): string {
  const hash = createHash('sha256').update(publicKeyPem.trim(), 'utf8').digest('hex');
  return `sha256:${hash}`;
}

function getKeyFilePath(): string {
  const baseDir = process.env.AI_FORGE_DATA_DIR ?? path.join(process.cwd(), '.data');
  return path.join(baseDir, 'keys', 'ed25519-keypair.json');
}

function ensureKeypair(): Ed25519KeypairRecord {
  if (cachedRecord && cachedPrivateKey && cachedPublicKey) {
    return cachedRecord;
  }

  // 1. Check environment variables first
  const envPriv = process.env.AI_FORGE_ED25519_PRIVATE_KEY_PEM;
  const envPub = process.env.AI_FORGE_ED25519_PUBLIC_KEY_PEM;
  if (envPriv && envPub) {
    const fingerprintSha256 = computeKeyFingerprint(envPub);
    const keyId = `ed25519:${fingerprintSha256.slice(7, 23)}`;
    cachedPrivateKey = createPrivateKey(envPriv);
    cachedPublicKey = createPublicKey(envPub);
    cachedRecord = {
      keyId,
      algorithm: 'Ed25519',
      publicKeyPem: envPub,
      privateKeyPem: envPriv,
      fingerprintSha256,
      createdAt: new Date().toISOString(),
    };
    return cachedRecord;
  }

  // 2. Check persisted keypair on disk (.data/keys/ed25519-keypair.json) unless in pure memory test mode
  const keyFile = getKeyFilePath();
  if (process.env.AI_FORGE_STORE !== 'memory') {
    try {
      if (fs.existsSync(keyFile)) {
        const raw = JSON.parse(fs.readFileSync(keyFile, 'utf8')) as StoredEncryptedKeypairFile;
        const privPem = raw.encryptedPrivateKey
          ? decryptSecretAes256Gcm(raw.encryptedPrivateKey)
          : raw.privateKeyPem;
        if (privPem) {
          cachedPrivateKey = createPrivateKey(privPem);
          cachedPublicKey = createPublicKey(raw.publicKeyPem);
          cachedRecord = {
            keyId: raw.keyId,
            algorithm: 'Ed25519',
            publicKeyPem: raw.publicKeyPem,
            privateKeyPem: privPem,
            fingerprintSha256: raw.fingerprintSha256,
            createdAt: raw.createdAt,
          };
          return cachedRecord;
        }
      }
    } catch {
      // Fall through to generate fresh keypair
    }
  }

  // 3. Generate a real Ed25519 keypair via Node.js native crypto
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const publicKeyPem = publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const fingerprintSha256 = computeKeyFingerprint(publicKeyPem);
  const keyId = `ed25519:${fingerprintSha256.slice(7, 23)}`;

  cachedPrivateKey = privateKey;
  cachedPublicKey = publicKey;
  cachedRecord = {
    keyId,
    algorithm: 'Ed25519',
    publicKeyPem,
    privateKeyPem,
    fingerprintSha256,
    createdAt: new Date().toISOString(),
  };

  if (process.env.AI_FORGE_STORE !== 'memory') {
    try {
      fs.mkdirSync(path.dirname(keyFile), { recursive: true });
      const encryptedFilePayload: StoredEncryptedKeypairFile = {
        keyId: cachedRecord.keyId,
        algorithm: 'Ed25519',
        publicKeyPem: cachedRecord.publicKeyPem,
        encryptedPrivateKey: encryptSecretAes256Gcm(cachedRecord.privateKeyPem),
        fingerprintSha256: cachedRecord.fingerprintSha256,
        createdAt: cachedRecord.createdAt,
      };
      fs.writeFileSync(keyFile, JSON.stringify(encryptedFilePayload, null, 2), {
        encoding: 'utf8',
        mode: 0o600,
      });
    } catch {
      // Ignore write error in read-only filesystems
    }
  }

  return cachedRecord;
}

/**
 * Returns the public key metadata for external verification (JWKS / PEM).
 */
export function getSigningPublicKeyInfo(): PublicKeyMetadata {
  const rec = ensureKeypair();
  return {
    keyId: rec.keyId,
    algorithm: rec.algorithm,
    publicKeyPem: rec.publicKeyPem,
    fingerprintSha256: rec.fingerprintSha256,
    createdAt: rec.createdAt,
  };
}

/**
 * Cryptographically signs a canonical SHA-256 digest string using Ed25519.
 */
export function signDigestEd25519(digest: string): Ed25519SignatureResult {
  const rec = ensureKeypair();
  const sigBuffer = sign(null, Buffer.from(digest, 'utf8'), cachedPrivateKey!);
  return {
    signature: `ed25519:${sigBuffer.toString('base64')}`,
    keyId: rec.keyId,
    algorithm: 'Ed25519',
    publicKeyFingerprint: rec.fingerprintSha256,
    signedAt: new Date().toISOString(),
  };
}

/**
 * Verifies an Ed25519 signature over a canonical SHA-256 digest string.
 */
export function verifyDigestEd25519(
  digest: string,
  signatureWithPrefix: string,
  customPublicKeyPem?: string
): boolean {
  try {
    ensureKeypair();
    const cleanB64 = signatureWithPrefix.startsWith('ed25519:')
      ? signatureWithPrefix.slice('ed25519:'.length)
      : signatureWithPrefix;
    const sigBuffer = Buffer.from(cleanB64, 'base64');
    const pubKey = customPublicKeyPem ? createPublicKey(customPublicKeyPem) : cachedPublicKey!;
    return verify(null, Buffer.from(digest, 'utf8'), pubKey, sigBuffer);
  } catch {
    return false;
  }
}
