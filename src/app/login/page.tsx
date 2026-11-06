'use client';

import { FormEvent, useMemo, useState } from 'react';
import { signIn } from 'next-auth/react';
import { useRouter, useSearchParams } from 'next/navigation';
import { Suspense } from 'react';
import { isSafeCallbackPath } from '../../lib/security/http-guards';

function LoginForm() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const callbackUrl = isSafeCallbackPath(searchParams.get('callbackUrl'));
  const authError = searchParams.get('error');

  const [mode, setMode] = useState<'login' | 'register'>('login');

  // Login state (clean production fields — no pre-filled demo credentials)
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(
    authError ? 'Credenciais inválidas ou sessão expirada.' : null
  );

  // Self-serve Registration state
  const [regName, setRegName] = useState('');
  const [regOrgName, setRegOrgName] = useState('');
  const [regEmail, setRegEmail] = useState('');
  const [regPassword, setRegPassword] = useState('');
  const [regPlanTier, setRegPlanTier] = useState<'starter' | 'growth' | 'enterprise'>('growth');
  const [regSuccess, setRegSuccess] = useState<string | null>(null);

  const oidcHint = useMemo(
    () => 'OIDC/SAML enterprise fica disponível quando OIDC_* estiver configurado.',
    []
  );

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    try {
      const result = await signIn('credentials', {
        email,
        password,
        redirect: false,
        callbackUrl,
      });
      if (!result || result.error) {
        setError('Email ou password incorrectos.');
        return;
      }
      router.push(callbackUrl);
      router.refresh();
    } catch {
      setError('Falha ao autenticar. Tente novamente.');
    } finally {
      setSubmitting(false);
    }
  }

  async function onRegisterSubmit(e: FormEvent) {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    setRegSuccess(null);
    try {
      const res = await fetch('/api/auth/register', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: regName,
          organizationName: regOrgName,
          email: regEmail,
          password: regPassword,
          planTier: regPlanTier,
        }),
      });
      const data = await res.json();
      if (!res.ok) {
        setError(data.error ?? 'Falha ao registar organização.');
        return;
      }
      setRegSuccess(
        `Organização "${data.organization.name}" provisionada com sucesso (${data.organization.id}). A autenticar…`
      );
      const signInRes = await signIn('credentials', {
        email: regEmail,
        password: regPassword,
        redirect: false,
        callbackUrl,
      });
      if (signInRes && !signInRes.error) {
        router.push(callbackUrl);
        router.refresh();
      } else {
        setEmail(regEmail);
        setPassword(regPassword);
        setMode('login');
      }
    } catch {
      setError('Erro de rede ao criar organização.');
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <div className="login-page">
      <div className="login-panel panel">
        <div className="brand" style={{ marginBottom: 16 }}>
          <div className="brand-name">AI Forge</div>
          <div className="brand-sub">Trust · Release · Evidence · Multi-Tenant SaaS</div>
        </div>

        <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
          <button
            type="button"
            className={`btn btn-sm ${mode === 'login' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => {
              setMode('login');
              setError(null);
            }}
          >
            Sessão Existente
          </button>
          <button
            type="button"
            className={`btn btn-sm ${mode === 'register' ? 'btn-primary' : 'btn-secondary'}`}
            onClick={() => {
              setMode('register');
              setError(null);
            }}
          >
            Criar Empresa (Self-Serve SaaS)
          </button>
        </div>

        {mode === 'login' ? (
          <>
            <h1 style={{ margin: '0 0 8px', fontSize: 24, letterSpacing: '-0.03em' }}>Entrar</h1>
            <p style={{ margin: '0 0 20px', color: 'var(--text-secondary)', fontSize: 14 }}>
              Autenticação protegida por KDF scrypt + cookies HttpOnly. Registe a sua própria
              empresa na aba acima ou use uma conta do workspace.
            </p>

            <form className="login-form" onSubmit={onSubmit}>
              <label className="field">
                <span>Email Corporativo</span>
                <input
                  type="email"
                  name="email"
                  autoComplete="username"
                  placeholder="nome@empresa.com"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  required
                />
              </label>
              <label className="field">
                <span>Password</span>
                <input
                  type="password"
                  name="password"
                  autoComplete="current-password"
                  placeholder="••••••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  required
                />
              </label>

              {error ? (
                <div className="login-error" role="alert">
                  {error}
                </div>
              ) : null}

              <button className="btn btn-primary" type="submit" disabled={submitting}>
                {submitting ? 'A autenticar…' : 'Entrar'}
              </button>
            </form>

            <div className="login-hints mono" style={{ marginTop: 20 }}>
              <div style={{ color: 'var(--trust)' }}>
                ● KDF scrypt (N=16384) + CSPRNG 16-Byte Salt · HttpOnly / SameSite=Lax
              </div>
              <div style={{ marginTop: 6, color: 'var(--text-secondary)' }}>{oidcHint}</div>
            </div>
          </>
        ) : (
          <>
            <h1 style={{ margin: '0 0 8px', fontSize: 24, letterSpacing: '-0.03em' }}>
              Registar Organização SaaS
            </h1>
            <p style={{ margin: '0 0 18px', color: 'var(--text-secondary)', fontSize: 14 }}>
              Cria um Tenant isolado com 3 ambientes (Dev/Staging/Prod), Cofre BYOK AES-256-GCM e
              agente Security PR Auditor pronto a usar.
            </p>

            <form className="login-form" onSubmit={onRegisterSubmit}>
              <label className="field">
                <span>Seu Nome Completo</span>
                <input
                  type="text"
                  name="fullName"
                  placeholder="Ana Silva (CISO)"
                  value={regName}
                  onChange={(e) => setRegName(e.target.value)}
                  required
                />
              </label>
              <label className="field">
                <span>Nome da Empresa / Organização</span>
                <input
                  type="text"
                  name="organizationName"
                  placeholder="Fintech Europeia S.A."
                  value={regOrgName}
                  onChange={(e) => setRegOrgName(e.target.value)}
                  required
                />
              </label>
              <label className="field">
                <span>Email Corporativo</span>
                <input
                  type="email"
                  name="registerEmail"
                  placeholder="ana.silva@fintech.pt"
                  value={regEmail}
                  onChange={(e) => setRegEmail(e.target.value)}
                  required
                />
              </label>
              <label className="field">
                <span>Password (mín. 8 caracteres · KDF scrypt)</span>
                <input
                  type="password"
                  name="registerPassword"
                  placeholder="••••••••••••"
                  value={regPassword}
                  onChange={(e) => setRegPassword(e.target.value)}
                  minLength={8}
                  required
                />
              </label>
              <label className="field">
                <span>Plano Inicial</span>
                <select
                  value={regPlanTier}
                  onChange={(e) =>
                    setRegPlanTier(e.target.value as 'starter' | 'growth' | 'enterprise')
                  }
                  style={{
                    background: 'var(--bg-elevated)',
                    border: '1px solid var(--border-strong)',
                    borderRadius: 6,
                    color: 'var(--text)',
                    padding: '10px 12px',
                  }}
                >
                  <option value="starter">Starter ($99/mês · 100 Governed Runs)</option>
                  <option value="growth">Growth ($499/mês · 1.000 Governed Runs)</option>
                  <option value="enterprise">Enterprise ($2.500/mês · 10.000 Runs + Ed25519)</option>
                </select>
              </label>

              {error ? (
                <div className="login-error" role="alert">
                  {error}
                </div>
              ) : null}

              {regSuccess ? (
                <div className="badge trust" style={{ padding: 10 }}>
                  {regSuccess}
                </div>
              ) : null}

              <button className="btn btn-primary" type="submit" disabled={submitting}>
                {submitting ? 'A provisionar Tenant…' : 'Criar Empresa & Entrar'}
              </button>
            </form>
          </>
        )}
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense
      fallback={
        <div className="login-page">
          <div className="login-panel panel">A carregar…</div>
        </div>
      }
    >
      <LoginForm />
    </Suspense>
  );
}
