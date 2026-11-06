# AI Forge — Enterprise Agent Governance, Delivery & Cryptographic Evidence Plane

Plataforma empresarial para **criar, avaliar, aprovar, publicar e operar agentes de IA** com governança determinística e evidência criptográfica verificável.

> **Proposta de Valor:** *AI Forge é a camada de entrega, confiança e evidência para agentes de IA empresariais — o que Git + CI/CD + Terraform + OPA + Datadog + Vanta fizeram por software e cloud, aplicado a sistemas agentic.*

---

## Diferenciadores de Mercado (Why CTOs, CISOs & AI Platform Engineers Choose AI Forge)

1. **Zero Autorização via LLM (PEP Determinístico)**: Nenhuma chamada de ferramenta depende de "pedir por favor" ao prompt. O motor de políticas (`src/lib/domain/policy/engine.ts`) avalia 9 regras determinísticas (escopo, classificação de dados, egress, orçamento, profundidade de delegação e aprovação humana) **antes** de cada invocação.
2. **Releases Imutáveis por Digest SHA-256 (`AgentLockfile`)**: Nenhum agente corre em produção a partir de prompts mutáveis. Cada release congela `manifestDigest`, `capabilityDigests`, `policyDigest` e `evalSuiteDigest` num `releaseDigest` verificável.
3. **Verificador Criptográfico de Evidência & Simulador Anti-Adulteração**: Cada execução gera um `EvidenceBundle` com `bundleDigest` SHA-256 canónico. Qualquer tentativa de alterar custos, achados ou decisões pós-execução é imediatamente detectada por `verifyEvidenceBundle` (`src/lib/domain/evidence/verify.ts`).
4. **Diff Semântico de Manifesto & Calculadora de Blast-Radius**: Alterações ao manifesto calculam automaticamente o impacto de risco (`LOW | MEDIUM | HIGH | CRITICAL`) e geram `ChangeProposal` auditáveis.
5. **7 Cenários Adversariais & Gates de Release Obrigatórios**: Inclui `SQLI-001`, `FALSE-POSITIVE-001`, `INJECTION-001` (Indirect Prompt Injection), `SCOPE-001`, `BUDGET-001`, `RESOURCE-001` e `WRITE-001`, bloqueando candidatos vulneráveis antes da publicação.
6. **Execução Closed-Loop Pós-Aprovação Humana (HITL) Ligada ao Cofre BYOK (`AES-256-GCM`)**: Acções de escrita (`pull-request:draft-comment`) pausam e criam `ApprovalRequest`; exigem **Four-Eyes Separation of Duties (`REM-04`)**, emitem credencial efémera assinada via **`HMAC-SHA256` (`REM-03`)**, desencriptam o `githubToken` do cofre do Tenant e publicam o comentário de revisão assinado com `Ed25519` + `SHA-256`.
7. **Postura de Segurança Integral (`REM-01` a `REM-06`) & Trilha de Auditoria Encadeada (`SHA-256`)**: Autenticação fail-closed com KDF `scrypt` + salt CSPRNG por utilizador, proteção CSRF same-origin, rate limiting por IP, validação anti-SSRF em webhooks de saída e encadeamento criptográfico `previousHash -> entryHash` em cada `AuditLog`.
8. **SaaS Multi-Tenant Self-Serve, Team RBAC, Billing Stripe & SDKs Oficiais**: Registo imediato de novas empresas (`/api/auth/register`), gestão de equipa com proteção do último admin (`/api/team`), subscrições Stripe com validação criptográfica `Stripe-Signature` (`/api/billing/checkout` e `/api/webhooks/stripe`), e SDKs oficiais para **TypeScript** (`src/sdk/typescript/index.ts`) e **Python** (`sdk/python/aiforge_sdk.py`).

---

## Quickstart (Zero-Dependency Memory Store)

```bash
cd ai-forge
cp .env.example .env
npm install
npm run dev
```

Abra `http://localhost:3000`:
1. Na **Overview**, veja a cadeia de confiança em 5 segundos e escolha qualquer um dos **7 cenários** ou aceda ao **Live Scanner (`/scanner`)**.
2. Em **Live Scanner (`/scanner`)**, audite qualquer repositório público real do GitHub (`lodash/lodash`, `expressjs/express`, `axios/axios`, etc.) com consulta em tempo real à API do GitHub + base de dados de CVEs **OSV.dev** + análise **LLM Live (NVIDIA NIM / OpenAI / Gemini)** + assinatura criptográfica **Ed25519**, ou faça pesquisas de segurança multi-fonte e navegação HTTPS com proteção anti-SSRF.
3. Navegue por **Agents** (`/agents/agent_security_pr_auditor` com as 8 abas obrigatórias), **Manifest Editor** (com presets adversariais e diff semântico), **Policy Center** (suite de regressão das 9 regras), **Approvals** (aprovação HITL com execução real do draft comment) e **Evidence Explorer** (verificador `SHA-256` + `Ed25519` e simulador anti-adulteração).

## Quickstart (PostgreSQL + Prisma)

```bash
cd ai-forge
docker compose up -d
cp .env.example .env   # Configure DATABASE_URL para localhost:5432/ai_forge
npm install
npx prisma generate
npx prisma db push
npm run db:seed
npm run dev
```

---

## Comandos de Verificação & Qualidade

| Comando | Descrição |
|---|---|
| `npm run dev` | Inicia o servidor Next.js em `http://localhost:3000` |
| `npm run typecheck` | Validação estrita TypeScript (`tsc --noEmit`) |
| `npm run lint` | Análise estática ESLint |
| `npm test` | Executa as 11 suites / 57 testes Vitest (unit + integration + security + SaaS + SDK) |
| `npm run test:e2e` | Executa os 7 testes E2E Playwright em Chromium |
| `npm run build` | Build de produção Next.js |
| `npm run verify` | Executa `typecheck` + `vitest run` |
| `npm run db:seed` | Popula a base de dados com o agente `Security PR Auditor`, contratos, políticas e release |

---

## Documentação Técnica (`docs/`)

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — Arquitectura dos 3 planos (Control, Execution, Evidence), rotas de API e páginas da consola.
- [`docs/ENTITY_DIAGRAM.md`](docs/ENTITY_DIAGRAM.md) — Diagrama ER Mermaid das 18+ entidades Prisma e instruções de migração.
- [`docs/POLICY_REASON_CODES.md`](docs/POLICY_REASON_CODES.md) — Tabela completa das 9 regras determinísticas do PEP e códigos de razão.
- [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) — Matriz de mitigação OWASP Agentic Top 10 (2026), NIST AI RMF e análise STRIDE.
- [`docs/INCIDENT_RUNBOOK.md`](docs/INCIDENT_RUNBOOK.md) — Runbook operacional de resposta a incidentes (Kill Switch, revogação de credenciais, preservação de evidência e rollback).
- [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) — Relatório transparente do modo `demo-simulation` vs. integrações externas de produção.
