import { describe, it, expect } from 'vitest';
import {
  getSigningPublicKeyInfo,
  signDigestEd25519,
  verifyDigestEd25519,
} from '../../src/lib/domain/crypto/signing';
import { EvidenceBundleBuilder } from '../../src/lib/domain/evidence/bundle';
import { verifyEvidenceBundle } from '../../src/lib/domain/evidence/verify';
import {
  isSafeExternalUrl,
  WebAdvisorySearchAdapter,
} from '../../src/lib/adapters/capability/web-search-real';
import { OsvVulnerabilityLookupAdapter } from '../../src/lib/adapters/capability/osv-vuln-real';
import { DemoCredentialBroker } from '../../src/lib/domain/runtime/credential-broker';
import { getSystemHealthService } from '../../src/lib/services/platform';

describe('real Ed25519 asymmetric cryptographic signing', () => {
  it('generates Ed25519 keypair, signs digests, and verifies signatures', () => {
    const pubInfo = getSigningPublicKeyInfo();
    expect(pubInfo.algorithm).toBe('Ed25519');
    expect(pubInfo.keyId).toMatch(/^ed25519:[a-f0-9]{16}$/);
    expect(pubInfo.publicKeyPem).toContain('BEGIN PUBLIC KEY');

    const sampleDigest = 'sha256:' + 'a'.repeat(64);
    const sig = signDigestEd25519(sampleDigest);
    expect(sig.signature).toMatch(/^ed25519:/);

    expect(verifyDigestEd25519(sampleDigest, sig.signature)).toBe(true);
    expect(verifyDigestEd25519('sha256:' + 'b'.repeat(64), sig.signature)).toBe(false);
  });

  it('attaches and verifies Ed25519 signature on every EvidenceBundle', () => {
    const releaseDigest = 'sha256:' + 'c'.repeat(64);
    const now = new Date().toISOString();
    const bundle = new EvidenceBundleBuilder('run_ed25519_1', releaseDigest, now)
      .addCost(0.02, 50, 25)
      .build({ status: 'succeeded', endedAt: now });

    expect(bundle.integrity.signature).toMatch(/^ed25519:/);
    expect(bundle.integrity.algorithm).toBe('Ed25519');
    expect(bundle.integrity.keyId).toMatch(/^ed25519:/);

    const report = verifyEvidenceBundle(bundle);
    expect(report.valid).toBe(true);
    expect(
      report.checks.some((c) => c.check === 'ed25519_digital_signature' && c.passed)
    ).toBe(true);
  });
});

describe('SSRF protection & governed web intelligence adapter', () => {
  it('blocks private IPs, cloud metadata, loopback, and non-HTTPS URLs', () => {
    expect(isSafeExternalUrl('http://osv.dev').safe).toBe(false);
    expect(isSafeExternalUrl('https://localhost:3000/api').safe).toBe(false);
    expect(isSafeExternalUrl('https://127.0.0.1/admin').safe).toBe(false);
    expect(isSafeExternalUrl('https://169.254.169.254/latest/meta-data/').safe).toBe(false);
    expect(isSafeExternalUrl('https://10.0.0.1/internal').safe).toBe(false);
    expect(isSafeExternalUrl('https://192.168.1.1/router').safe).toBe(false);
    expect(isSafeExternalUrl('https://osv.dev').safe).toBe(true);
  });

  it('refuses SSRF URLs at runtime in WebAdvisorySearchAdapter', async () => {
    const broker = new DemoCredentialBroker();
    const cred = broker.issue({
      runId: 'r_ssrf',
      releaseDigest: 'sha256:' + 'd'.repeat(64),
      capability: 'security-web-intelligence',
      action: 'web:browse',
      resource: 'https://169.254.169.254/latest/meta-data/',
      purpose: 'test ssrf block',
    });

    const adapter = new WebAdvisorySearchAdapter();
    const res = await adapter.invoke({
      credential: cred,
      action: 'web:browse',
      resource: 'https://169.254.169.254/latest/meta-data/',
      payload: { url: 'https://169.254.169.254/latest/meta-data/' },
      traceId: 't_ssrf',
    });

    expect(res.status).toBe('failed');
    expect(res.error).toBe('ssrf_private_host_blocked');
  });
});

describe('live OSV.dev vulnerability lookup & system health', () => {
  it('queries live OSV.dev API for lodash@4.17.15 vulnerabilities', async () => {
    const broker = new DemoCredentialBroker();
    const cred = broker.issue({
      runId: 'r_osv',
      releaseDigest: 'sha256:' + 'e'.repeat(64),
      capability: 'dependency-vulnerability-db',
      action: 'vulnerability:lookup',
      resource: 'npm:lodash',
      purpose: 'test live osv lookup',
    });

    const adapter = new OsvVulnerabilityLookupAdapter();
    const res = await adapter.invoke({
      credential: cred,
      action: 'vulnerability:lookup',
      resource: 'npm:lodash',
      payload: { package: 'lodash', version: '4.17.15', ecosystem: 'npm' },
      traceId: 't_osv',
    });

    expect(res.provenance.mode).toBe('real-integration');
    if (res.status === 'succeeded') {
      const data = res.data as { totalFound: number; matches: Array<{ cve: string }> };
      expect(data.totalFound).toBeGreaterThan(0);
      expect(data.matches.length).toBeGreaterThan(0);
    }
  });

  it('returns complete health and cryptographic readiness status', async () => {
    const health = await getSystemHealthService();
    expect(health.status).toBe('healthy');
    expect(health.crypto.algorithm).toBe('Ed25519');
    expect(health.integrations.osvVulnerabilityApi).toContain('api.osv.dev');
  });
});

