'use client';

import { usePathname } from 'next/navigation';
import { Sidebar } from './sidebar';

const AUTH_PATHS = new Set(['/login']);

export function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname() ?? '/';
  const isAuthPage = AUTH_PATHS.has(pathname);

  if (isAuthPage) {
    return <div className="auth-shell">{children}</div>;
  }

  return (
    <div className="app-shell">
      <Sidebar pathname={pathname} />
      <div className="main">{children}</div>
    </div>
  );
}
