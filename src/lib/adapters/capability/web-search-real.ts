/**
 * Real Web & Security Intelligence Search + Safe Browsing Adapter (`real-integration`).
 *
 * Capabilities:
 * - `advisory:search`: Queries GitHub Security Advisories API, OSV.dev, NPM Registry,
 *   and HackerNews Algolia Security Intelligence in real time.
 * - `web:browse`: Fetches and extracts sanitized text from an authorized HTTPS URL
 *   with strict SSRF protection (blocks RFC1918, loopback, link-local, metadata IPs).
 */

import type { CapabilityAdapter, CapabilityInvokeRequest, CapabilityInvokeResult } from './interface';
import { DemoCredentialBroker } from '../../domain/runtime/credential-broker';

export interface SearchIntelligenceItem {
  id: string;
  source: 'github-advisories' | 'osv-dev' | 'npm-registry' | 'hn-security';
  title: string;
  summary: string;
  url: string;
  severity?: string;
  cveId?: string;
  publishedAt?: string;
}

const BLOCKED_HOSTS_REGEX =
  /^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|169\.254\.|100\.100\.100\.200|0\.0\.0\.0|\[?::1\]?|\[?fc00:|\[?fd00:|\[?fe80:|metadata\.google\.internal|.*\.internal$|.*\.local$)/i;

export function isSafeExternalUrl(rawUrl: string): { safe: boolean; reason?: string; parsed?: URL } {
  try {
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== 'https:') {
      return { safe: false, reason: 'only_https_allowed' };
    }
    if (BLOCKED_HOSTS_REGEX.test(parsed.hostname)) {
      return { safe: false, reason: 'ssrf_private_host_blocked' };
    }
    return { safe: true, parsed };
  } catch {
    return { safe: false, reason: 'invalid_url' };
  }
}

export class WebAdvisorySearchAdapter implements CapabilityAdapter {
  readonly name = 'security-web-intelligence';
  private readonly broker = new DemoCredentialBroker();

  async invoke(request: CapabilityInvokeRequest): Promise<CapabilityInvokeResult> {
    const started = Date.now();
    const validation = this.broker.validate(request.credential, request.action, request.resource);

    if (!validation.valid) {
      return {
        status: 'failed',
        data: null,
        provenance: {
          adapter: this.name,
          mode: 'real-integration',
          timestamp: new Date().toISOString(),
        },
        latencyMs: Date.now() - started,
        error: validation.reason,
      };
    }

    if (request.action === 'web:browse') {
      const payload = (request.payload ?? {}) as { url?: string };
      const targetUrl = payload.url ?? request.resource;
      const check = isSafeExternalUrl(targetUrl);
      if (!check.safe) {
        return {
          status: 'failed',
          data: { url: targetUrl, reason: check.reason },
          provenance: {
            adapter: this.name,
            mode: 'real-integration',
            timestamp: new Date().toISOString(),
          },
          latencyMs: Date.now() - started,
          error: check.reason,
        };
      }

      try {
        const res = await fetch(targetUrl, {
          headers: {
            'User-Agent': 'AI-Forge-Enterprise-Browser/1.0',
            Accept: 'text/html,application/json,text/plain;q=0.9',
          },
          redirect: 'error',
          signal: AbortSignal.timeout(10_000),
        });
        const contentType = res.headers.get('content-type') ?? '';
        const rawText = await res.text();
        // Strip script/style tags and extract readable text safely
        const cleanText = rawText
          .replace(/<script[\s\S]*?<\/script>/gi, ' ')
          .replace(/<style[\s\S]*?<\/style>/gi, ' ')
          .replace(/<[^>]+>/g, ' ')
          .replace(/\s+/g, ' ')
          .trim()
          .slice(0, 6000);

        const titleMatch = rawText.match(/<title[^>]*>([^<]+)<\/title>/i);

        return {
          status: 'succeeded',
          data: {
            url: targetUrl,
            httpStatus: res.status,
            contentType,
            title: titleMatch?.[1]?.trim() ?? check.parsed!.hostname,
            excerpt: cleanText,
            untrustedEnvelope: true,
            mode: 'real-integration',
          },
          provenance: {
            adapter: this.name,
            mode: 'real-integration',
            timestamp: new Date().toISOString(),
          },
          latencyMs: Date.now() - started,
        };
      } catch (err) {
        return {
          status: 'failed',
          data: { url: targetUrl },
          provenance: {
            adapter: this.name,
            mode: 'real-integration',
            timestamp: new Date().toISOString(),
          },
          latencyMs: Date.now() - started,
          error: err instanceof Error ? err.message : 'web_browse_failed',
        };
      }
    }

    // Default action: `advisory:search`
    const payload = (request.payload ?? {}) as { query?: string; ecosystem?: string };
    const query = (payload.query ?? 'sql injection').trim();
    const items: SearchIntelligenceItem[] = [];

    const ghHeaders: Record<string, string> = {
      Accept: 'application/vnd.github+json',
      'User-Agent': 'AI-Forge-Enterprise-Governance/1.0',
    };
    if (process.env.GITHUB_TOKEN) {
      ghHeaders.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
    }

    const tasks = await Promise.allSettled([
      // 1. GitHub Global Security Advisories API
      fetch('https://api.github.com/advisories?per_page=8', {
        headers: ghHeaders,
        signal: AbortSignal.timeout(8000),
      }).then(async (r) => (r.ok ? r.json() : [])),

      // 2. OSV.dev API if query looks like a package name
      /^[a-z0-9@/_.-]+$/i.test(query) && !query.includes(' ')
        ? fetch('https://api.osv.dev/v1/query', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              package: { name: query, ecosystem: payload.ecosystem ?? 'npm' },
            }),
            signal: AbortSignal.timeout(8000),
          }).then(async (r) => (r.ok ? r.json() : { vulns: [] }))
        : Promise.resolve({ vulns: [] }),

      // 3. NPM Registry search
      fetch(
        `https://registry.npmjs.org/-/v1/search?text=${encodeURIComponent(query)}&size=5`,
        { signal: AbortSignal.timeout(8000) }
      ).then(async (r) => (r.ok ? r.json() : { objects: [] })),

      // 4. HackerNews Algolia Security & Engineering Intelligence
      fetch(
        `https://hn.algolia.com/api/v1/search?query=${encodeURIComponent(query)}&tags=story&hitsPerPage=5`,
        { signal: AbortSignal.timeout(8000) }
      ).then(async (r) => (r.ok ? r.json() : { hits: [] })),
    ]);

    // Parse GitHub Advisories
    if (tasks[0].status === 'fulfilled' && Array.isArray(tasks[0].value)) {
      const advisories = tasks[0].value as Array<{
        ghsa_id: string;
        cve_id?: string | null;
        summary?: string;
        html_url?: string;
        severity?: string;
        published_at?: string;
      }>;
      const qLower = query.toLowerCase();
      const filtered = advisories.filter(
        (a) =>
          !query ||
          (a.summary ?? '').toLowerCase().includes(qLower) ||
          (a.cve_id ?? '').toLowerCase().includes(qLower) ||
          a.ghsa_id.toLowerCase().includes(qLower)
      );
      const listToUse = filtered.length > 0 ? filtered : advisories.slice(0, 4);
      for (const adv of listToUse.slice(0, 5)) {
        items.push({
          id: adv.ghsa_id,
          source: 'github-advisories',
          title: `${adv.cve_id ?? adv.ghsa_id}: ${adv.summary ?? 'Security Advisory'}`,
          summary: adv.summary ?? 'GitHub Security Advisory',
          url: adv.html_url ?? `https://github.com/advisories/${adv.ghsa_id}`,
          severity: adv.severity ?? 'medium',
          cveId: adv.cve_id ?? adv.ghsa_id,
          publishedAt: adv.published_at,
        });
      }
    }

    // Parse OSV.dev
    if (tasks[1].status === 'fulfilled' && tasks[1].value?.vulns) {
      const vulns = tasks[1].value.vulns as Array<{
        id: string;
        aliases?: string[];
        summary?: string;
        details?: string;
        published?: string;
        database_specific?: { severity?: string };
      }>;
      for (const v of vulns.slice(0, 5)) {
        const cve = (v.aliases ?? []).find((a) => a.startsWith('CVE-')) ?? v.id;
        items.push({
          id: v.id,
          source: 'osv-dev',
          title: `[OSV] ${cve} — ${ (v.summary ?? v.details ?? query).slice(0, 100)}`,
          summary: (v.summary ?? v.details ?? '').slice(0, 260),
          url: `https://osv.dev/vulnerability/${v.id}`,
          severity: (v.database_specific?.severity ?? 'medium').toLowerCase(),
          cveId: cve,
          publishedAt: v.published,
        });
      }
    }

    // Parse NPM Registry
    if (tasks[2].status === 'fulfilled' && Array.isArray(tasks[2].value?.objects)) {
      const objs = tasks[2].value.objects as Array<{
        package: {
          name: string;
          version: string;
          description?: string;
          date?: string;
          links?: { npm?: string; repository?: string };
        };
      }>;
      for (const o of objs.slice(0, 4)) {
        items.push({
          id: `npm:${o.package.name}@${o.package.version}`,
          source: 'npm-registry',
          title: `npm package: ${o.package.name}@${o.package.version}`,
          summary: o.package.description ?? 'NPM registry package metadata',
          url: o.package.links?.npm ?? `https://www.npmjs.com/package/${o.package.name}`,
          publishedAt: o.package.date,
        });
      }
    }

    // Parse HN Security Intelligence
    if (tasks[3].status === 'fulfilled' && Array.isArray(tasks[3].value?.hits)) {
      const hits = tasks[3].value.hits as Array<{
        objectID: string;
        title?: string;
        url?: string;
        created_at?: string;
        points?: number;
      }>;
      for (const h of hits.slice(0, 4)) {
        if (!h.title) continue;
        items.push({
          id: `hn:${h.objectID}`,
          source: 'hn-security',
          title: h.title,
          summary: `Community security intelligence (${h.points ?? 0} pts)`,
          url: h.url ?? `https://news.ycombinator.com/item?id=${h.objectID}`,
          publishedAt: h.created_at,
        });
      }
    }

    return {
      status: 'succeeded',
      data: {
        query,
        totalResults: items.length,
        items,
        mode: 'real-integration',
      },
      provenance: {
        adapter: this.name,
        mode: 'real-integration',
        timestamp: new Date().toISOString(),
      },
      latencyMs: Date.now() - started,
    };
  }
}

