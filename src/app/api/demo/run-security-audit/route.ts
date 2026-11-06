import { NextResponse } from 'next/server';
import { getAuthContext } from '../../../../lib/auth/session';
import { startRunService } from '../../../../lib/services/platform';
import { getStore } from '../../../../lib/store';
import type { AuditFixtureScenario } from '../../../../lib/domain/runtime/orchestrator';

/**
 * Full vertical demo that PERSISTS via the active store (Prisma or memory).
 * Mode remains demo-simulation for adapters/LLM.
 */
export async function POST(request: Request) {
  try {
    const ctx = await getAuthContext();
    const store = await getStore();
    await store.ensureSeed();

    const body = await request.json().catch(() => ({}));
    const scenario: AuditFixtureScenario = body.scenario ?? body.fixture ?? 'sqli';
    const resource: string =
      body.resource ??
      (scenario === 'out-of-scope' ? 'evil-org/secrets' : 'org-approved/payments-api');
    const prNumber: number = Number(body.prNumber ?? 123);

    const agents = await store.listAgents();
    const agent = agents.find((a) => a.slug === 'security-pr-auditor') ?? agents[0];
    if (!agent) {
      return NextResponse.json({ error: 'Demo agent missing' }, { status: 500 });
    }

    const result = await startRunService(ctx, agent.id, {
      fixture: scenario,
      resource,
      prNumber,
    });

    return NextResponse.json({
      mode: 'demo-simulation',
      storeMode: store.mode,
      scenario,
      resource,
      agentId: agent.id,
      status: result.result.status,
      runId: result.run.id,
      releaseId: result.release.id,
      releaseDigest: result.release.releaseDigest,
      scorecard: result.release.scorecardJson ?? null,
      inputHash: result.result.inputHash,
      outputHash: result.result.outputHash,
      policyDecisions: result.result.policyDecisions,
      toolInvocations: result.result.toolInvocations,
      events: result.result.events,
      approvalRequest: result.approval,
      output: result.result.output,
      evidenceBundle: result.result.evidenceBundle,
      evidenceJson: result.evidenceJson,
      links: {
        run: `/agents/${agent.id}/runs/${result.run.id}`,
        release: `/agents/${agent.id}/releases/${result.release.id}`,
        evidence: `/api/agents/${agent.id}/runs/${result.run.id}/evidence`,
      },
    });
  } catch (e) {
    return NextResponse.json(
      { error: e instanceof Error ? e.message : 'Run failed' },
      { status: 500 }
    );
  }
}
