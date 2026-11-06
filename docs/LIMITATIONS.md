# Estado de Produção & Integrações Reais (v0.2.0 Production-Ready)

Documento transparente sobre as capacidades **reais em produção (`real-integration`)** versus opções de infraestrutura enterprise adicionais.

## 1. Integrações Reais Ativas (`real-integration`)

- **GitHub REST API Live (`src/lib/adapters/capability/github-pr-real.ts`)**:
  - Consulta diretamente `https://api.github.com/repos/{owner}/{repo}/pulls` e `/commits` para obter metadados, diffs reais e patches de ficheiros de qualquer repositório público (e repositórios privados quando `GITHUB_TOKEN` está definido).
- **Base de Dados de Vulnerabilidades OSV.dev Live (`src/lib/adapters/capability/osv-vuln-real.ts`)**:
  - Consulta `POST https://api.osv.dev/v1/query` em tempo real para descobrir CVEs e GHSAs reais em pacotes `npm`, `PyPI`, `Go`, `Maven` e `Cargo`.
- **Pesquisa Multi-Fonte de Inteligência & Navegação Segura Anti-SSRF (`src/lib/adapters/capability/web-search-real.ts`)**:
  - Pesquisa em paralelo **GitHub Global Security Advisories**, **OSV.dev**, **NPM Registry** e **HackerNews Algolia Security**.
  - Navegador HTTPS (`web:browse`) com bloqueio determinístico de SSRF (bloqueia `localhost`, `127.0.0.1`, `10.*`, `192.168.*`, `169.254.169.254` e protocolos não-HTTPS) e isolamento em envelope de dados não-confiáveis.
- **Modelo LLM Live Multi-Provider (`src/lib/adapters/model/live-llm.ts`)**:
  - Suporta **NVIDIA NIM** (`NVIDIA_API_KEY`, ex: `meta/llama-3.3-70b-instruct`), **OpenAI** (`OPENAI_API_KEY`, ex: `gpt-4o-mini`) e **Google Gemini** (`GEMINI_API_KEY`), com isolamento `<UNTRUSTED_REPOSITORY_DATA>` e fallback determinístico offline.
- **Assinatura Criptográfica Assimétrica Ed25519 (`src/lib/domain/crypto/signing.ts`)**:
  - Gera e persiste um par de chaves organizacional **Ed25519** (`.data/keys/ed25519-keypair.json`), assinando cada `EvidenceBundle` (`ed25519:...`) além do digest canónico `SHA-256`.
  - A chave pública é exposta em `/api/health` e na consola `/scanner` para verificação independente.
- **Persistência Durável em Disco & PostgreSQL (`src/lib/store/`)**:
  - Suporta **PostgreSQL via Prisma** (`DATABASE_URL`) e persistência atómica em disco (`.data/ai-forge-store.json`) fora de testes unitários, preservando agentes, commits, releases, runs, aprovações, trilha de auditoria encadeada (`SHA-256`) e evidências entre reinícios.
- **SaaS Multi-Tenant Self-Serve & Team RBAC (`src/lib/auth/users.ts`)**:
  - Registo de novas organizações (`/api/auth/register`) com provisionamento automático de 3 ambientes (`development`, `staging`, `production`), hashing `scrypt` + salt CSPRNG individual e controlo de acesso por papéis (`admin`, `operator`, `auditor`, `viewer`) com proteção do último administrador (`/api/team`).
- **Cofre BYOK (`AES-256-GCM`) & Escrita Pós-Aprovação em PRs GitHub (`src/lib/security/tenant-vault.ts`, `src/lib/services/platform.ts`)**:
  - Segredos por Tenant encriptados em repouso com `AES-256-GCM` e chave derivada via `scrypt`. Quando uma aprovação humana (`Four-Eyes Separation of Duties`) é concedida em `/approvals`, o motor emite um token delegado assinado (`HMAC-SHA256`), desencripta o `githubToken` do Tenant e publica a revisão de segurança atestada no PR.
- **Billing Stripe & Webhook Assinado (`src/lib/billing/stripe.ts`)**:
  - Criação de sessões de Checkout (`/api/billing/checkout`) e receção de webhooks (`/api/webhooks/stripe`) com verificação criptográfica `Stripe-Signature` (`t=...,v1=HMAC-SHA256`), janela de tolerância de `300s` e cache anti-replay.
- **Universal Agent Governance Gateway & SDKs Oficiais (`src/sdk/typescript/index.ts`, `sdk/python/aiforge_sdk.py`)**:
  - Governa agentes externos (LangChain, CrewAI, AutoGen, OpenAI/Anthropic SDKs) via `/api/v1/gateway/authorize` e `/api/v1/gateway/evidence`.

## 2. Configuração para Cloud Produção

- **SSO OIDC/SAML Enterprise**: Ativado automaticamente ao definir `OIDC_ISSUER`, `OIDC_CLIENT_ID`, `OIDC_CLIENT_SECRET`.
- **Stripe Live Mode**: Ativado automaticamente ao definir `STRIPE_SECRET_KEY` e `STRIPE_WEBHOOK_SECRET` (com modo sandbox assinado incluído para validação local).
- **Infraestrutura Cloud**: `Dockerfile` multi-stage de produção, `docker-compose.yml` completo (`postgres` + `ai-forge`) e pipeline `.github/workflows/ci.yml` incluídos para deploy imediato em Cloud Run, ECS, Fly.io ou Kubernetes.
