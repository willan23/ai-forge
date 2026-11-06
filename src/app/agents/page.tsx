'use client';

import { useEffect, useState } from 'react';
import Link from 'next/link';

interface AgentRow {
  id: string;
  name: string;
  slug: string;
  status: string;
  ownerId: string;
  workspaceId: string;
  workspaceName?: string;
  environment?: string;
  autonomyLevel?: number;
  approvalPolicy?: string;
  killSwitch: boolean;
  lastReleaseDigest?: string | null;
  lastReleaseVersion?: string | null;
  runCount?: number;
}

interface WorkspaceOption {
  id: string;
  name: string;
  environment: string;
}

export default function AgentsPage() {
  const [agents, setAgents] = useState<AgentRow[]>([]);
  const [workspaces, setWorkspaces] = useState<WorkspaceOption[]>([]);
  const [selectedWs, setSelectedWs] = useState<string>('all');
  const [storeMode, setStoreMode] = useState('—');
  const [error, setError] = useState<string | null>(null);
  const [message, setMessage] = useState<string | null>(null);

  // Create agent form state
  const [showCreate, setShowCreate] = useState(false);
  const [newName, setNewName] = useState('Security PR Auditor (Staging)');
  const [newSlug, setNewSlug] = useState('security-pr-auditor-staging');
  const [newWorkspaceId, setNewWorkspaceId] = useState('ws_demo_staging');
  const [creating, setCreating] = useState(false);

  async function loadAgents(wsFilter?: string) {
    try {
      const url =
        wsFilter && wsFilter !== 'all'
          ? `/api/agents?workspaceId=${encodeURIComponent(wsFilter)}`
          : '/api/agents';
      const r = await fetch(url);
      const data = await r.json();
      if (data.error) setError(data.error);
      else {
        setAgents(data.agents ?? []);
        if (data.workspaces) setWorkspaces(data.workspaces);
        setStoreMode(data.storeMode ?? '—');
      }
    } catch (e) {
      setError(String(e));
    }
  }

  useEffect(() => {
    fetch('/api/agents')
      .then((r) => r.json())
      .then((data) => {
        if (data.error) setError(data.error);
        else {
          setAgents(data.agents ?? []);
          if (data.workspaces) setWorkspaces(data.workspaces);
          setStoreMode(data.storeMode ?? '—');
        }
      })
      .catch((e) => setError(String(e)));
  }, []);

  async function toggleKill(agentId: string, current: boolean) {
    setError(null);
    setMessage(null);
    const res = await fetch(`/api/agents/${agentId}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ killSwitch: !current }),
    });
    const data = await res.json();
    if (res.ok) {
      setAgents((prev) =>
        prev.map((a) => (a.id === agentId ? { ...a, killSwitch: data.agent.killSwitch } : a))
      );
      setMessage(
        `Kill switch ${data.agent.killSwitch ? 'ATIVADO (novas runs bloqueadas)' : 'DESATIVADO'} para ${agentId}.`
      );
    } else {
      setError(data.error ?? 'Failed');
    }
  }

  async function handleCreateAgent(e: React.FormEvent) {
    e.preventDefault();
    setCreating(true);
    setError(null);
    setMessage(null);
    try {
      const res = await fetch('/api/agents', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          name: newName,
          slug: newSlug,
          workspaceId: newWorkspaceId,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error ?? 'Failed to create agent');
      setShowCreate(false);
      setMessage(
        `Agente "${data.agent.name}" criado no workspace ${newWorkspaceId} com commit inicial.`
      );
      await loadAgents(selectedWs);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Error creating agent');
    } finally {
      setCreating(false);
    }
  }

  return (
    <>
      <div className="page-header">
        <div>
          <h1>Agents</h1>
          <p>
            Registo central de agentes lógicos versionados por manifesto, com isolamento por
            workspace/ambiente, nível de autonomia graduado (L0–L5) e kill switch imediato.
          </p>
        </div>
        <div className="header-actions">
          <select
            aria-label="Workspace filter"
            className="select"
            style={{ width: 220 }}
            value={selectedWs}
            onChange={(e) => {
              setSelectedWs(e.target.value);
              loadAgents(e.target.value);
            }}
          >
            <option value="all">Todos os Workspaces</option>
            {workspaces.map((w) => (
              <option key={w.id} value={w.id}>
                {w.name} ({w.environment})
              </option>
            ))}
          </select>
          <span className="badge">store: {storeMode}</span>
          <button className="btn btn-primary" onClick={() => setShowCreate((v) => !v)}>
            {showCreate ? 'Cancelar' : 'Create Agent'}
          </button>
        </div>
      </div>

      {error && (
        <div className="panel">
          <span className="badge danger">{error}</span>
        </div>
      )}
      {message && (
        <div className="panel">
          <span className="badge trust">{message}</span>
        </div>
      )}

      {showCreate && (
        <div className="panel">
          <div className="panel-header">
            <h2>Criar Agente Security PR Auditor em Workspace Isolado</h2>
            <span className="badge trust">Auto-seeds valid v0.1.0 Manifest</span>
          </div>
          <form onSubmit={handleCreateAgent} className="grid-3" style={{ alignItems: 'end' }}>
            <label className="field">
              <span>Agent Name</span>
              <input
                className="input"
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                required
              />
            </label>
            <label className="field">
              <span>Agent Slug</span>
              <input
                className="input"
                value={newSlug}
                onChange={(e) => setNewSlug(e.target.value)}
                required
              />
            </label>
            <label className="field">
              <span>Isolated Workspace / Environment</span>
              <select
                className="select"
                value={newWorkspaceId}
                onChange={(e) => setNewWorkspaceId(e.target.value)}
              >
                {workspaces.map((w) => (
                  <option key={w.id} value={w.id}>
                    {w.name} ({w.environment})
                  </option>
                ))}
              </select>
            </label>
            <div>
              <button type="submit" className="btn btn-primary" disabled={creating}>
                {creating ? 'Creating…' : 'Confirm Create Agent'}
              </button>
            </div>
          </form>
        </div>
      )}

      <div className="panel">
        <table className="table">
          <thead>
            <tr>
              <th>Name / Slug</th>
              <th>Workspace &amp; Env</th>
              <th>Status</th>
              <th>Autonomy Level</th>
              <th>Owner</th>
              <th>Last Release</th>
              <th>Runs</th>
              <th>Kill Switch</th>
            </tr>
          </thead>
          <tbody>
            {agents.map((agent) => (
              <tr key={agent.id}>
                <td>
                  <Link className="link-accent" href={`/agents/${agent.id}`} style={{ fontWeight: 600 }}>
                    {agent.name}
                  </Link>
                  <div className="mono">{agent.slug}</div>
                </td>
                <td>
                  <div>{agent.workspaceName ?? 'Platform Security'}</div>
                  <span className="mono">{agent.environment ?? 'development'}</span>
                </td>
                <td>
                  <span className="badge trust">{agent.status}</span>
                </td>
                <td>
                  <span className="badge">
                    L{agent.autonomyLevel ?? 2} · {agent.approvalPolicy ?? 'risk-based'}
                  </span>
                </td>
                <td className="mono">{agent.ownerId}</td>
                <td>
                  {agent.lastReleaseDigest ? (
                    <>
                      <span className="badge trust" style={{ marginRight: 6 }}>
                        v{agent.lastReleaseVersion ?? '0.1.0'}
                      </span>
                      <span className="mono">{agent.lastReleaseDigest.slice(0, 18)}…</span>
                    </>
                  ) : (
                    <span className="mono">sem release</span>
                  )}
                </td>
                <td className="mono">{agent.runCount ?? 0}</td>
                <td>
                  <button
                    className="btn btn-secondary btn-sm"
                    onClick={() => toggleKill(agent.id, agent.killSwitch)}
                  >
                    <span className={`badge ${agent.killSwitch ? 'danger' : 'trust'}`}>
                      {agent.killSwitch ? 'ON' : 'OFF'}
                    </span>
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  );
}
