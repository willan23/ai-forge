import Link from 'next/link';

const CONTROL_LINKS = [
  { href: '/', label: 'Overview', badge: '5s Trust' },
  { href: '/scanner', label: 'Live Scanner', badge: 'Real API' },
  { href: '/agents', label: 'Agents', badge: 'Registry' },
  { href: '/approvals', label: 'Approvals', badge: 'HITL' },
  { href: '/capabilities', label: 'Capabilities', badge: 'Contracts' },
  { href: '/policies', label: 'Policy Center', badge: 'PEP · 9' },
  { href: '/evidence', label: 'Evidence', badge: 'SHA-256' },
  { href: '/reports', label: 'Audit Reports', badge: 'ISO · EU AI' },
  { href: '/settings', label: 'SaaS & Keys', badge: 'BYOK · SDK' },
];

export function Sidebar({ pathname = '/' }: { pathname?: string }) {
  const isActive = (href: string) =>
    href === '/' ? pathname === '/' : pathname === href || pathname.startsWith(`${href}/`);

  return (
    <aside className="sidebar">
      <div className="brand">
        <div className="brand-top">
          <div className="brand-name">
            <span className="brand-mark" />
            AI Forge
          </div>
          <span className="badge trust" style={{ fontSize: 10, padding: '2px 6px' }}>
            v0.2.0 · Hardened
          </span>
        </div>
        <div className="brand-sub">WGF · Trust · Release · Evidence</div>
      </div>

      <div>
        <div className="nav-section-label">Governance &amp; Runtime</div>
        <nav className="nav">
          {CONTROL_LINKS.map((link) => (
            <Link
              key={link.href}
              href={link.href}
              className={isActive(link.href) ? 'active' : undefined}
            >
              <span>{link.label}</span>
              <span
                style={{
                  fontSize: 10,
                  opacity: 0.75,
                  fontFamily: 'var(--font-mono)',
                }}
              >
                {link.badge}
              </span>
            </Link>
          ))}
        </nav>
      </div>

      <div>
        <div className="nav-section-label">Planes &amp; Security Posture</div>
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            gap: 6,
            padding: '6px 10px',
            fontSize: 11.5,
            color: 'var(--text-secondary)',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span>Control Plane</span>
            <span style={{ color: 'var(--trust)' }}>● enforced</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span>Execution PEP</span>
            <span style={{ color: 'var(--trust)' }}>● deny-default</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span>Evidence Plane</span>
            <span style={{ color: 'var(--trust)' }}>● append-only</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span>Audit Hash Chain</span>
            <span style={{ color: 'var(--trust)' }}>● SHA-256</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span>Security Audit</span>
            <span style={{ color: 'var(--trust)' }}>● REM-01..06</span>
          </div>
        </div>
      </div>

      <div style={{ marginTop: 'auto', display: 'flex', flexDirection: 'column', gap: 8 }}>
        <Link
          href="/login"
          className={`btn btn-secondary btn-sm ${pathname === '/login' ? 'active' : ''}`}
          style={{ justifyContent: 'space-between' }}
        >
          <span>Login</span>
          <span className="mono" style={{ fontSize: 10 }}>
            RBAC · OIDC
          </span>
        </Link>
        <div
          style={{
            display: 'flex',
            flexDirection: 'column',
            gap: 4,
            padding: '8px 10px',
            borderRadius: 6,
            border: '1px solid var(--trust-border)',
            background: 'var(--trust-bg)',
          }}
        >
          <span className="badge trust" style={{ border: 'none', padding: 0, background: 'none' }}>
            Hybrid Live + Governance
          </span>
          <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
            GitHub API · OSV.dev · Ed25519 · No external write without approval
          </span>
        </div>
      </div>
    </aside>
  );
}
