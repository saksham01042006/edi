import { useEffect, useMemo, useState } from 'react';
import ReactFlow, { Background, Controls, MiniMap, MarkerType } from 'reactflow';
import 'reactflow/dist/style.css';
import './App.css';

const API_URL = 'http://localhost:8000';

type Project = {
  id: string;
  name: string;
  description: string;
};

type Analysis = {
  id: string;
  status: string;
  summary: string;
  findings_count: number;
  created_at: string;
};

type Finding = {
  id: string;
  title: string;
  severity: string;
  status: string;
  policy_name: string;
  data_category: string;
  source: string;
  destination: string;
  intermediate_path: string[];
  file_path: string;
  line_numbers: number[];
  explanation: string;
  remediation: string;
  limitations: string;
};

const demoCode = `def login(request):
    password = request.get("password")
    attempted_value = password
    logger.info("Login attempt: %s", attempted_value)
`;

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_URL}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(init?.headers ?? {}) },
    ...init,
  });

  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.detail || 'Request failed');
  }

  return response.json() as Promise<T>;
}

function App() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProjectId, setSelectedProjectId] = useState<string>('');
  const [projectName, setProjectName] = useState('PrivTrace Demo');
  const [sourceCode, setSourceCode] = useState(demoCode);
  const [analyses, setAnalyses] = useState<Analysis[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [graphNodes, setGraphNodes] = useState<any[]>([]);
  const [graphEdges, setGraphEdges] = useState<any[]>([]);
  const [selectedFindingId, setSelectedFindingId] = useState<string>('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>('');
  const [health, setHealth] = useState<string>('Checking...');

  const selectedFinding = useMemo(
    () => findings.find((item) => item.id === selectedFindingId) || findings[0],
    [findings, selectedFindingId],
  );

  useEffect(() => {
    void loadProjects();
    void checkHealth();
  }, []);

  useEffect(() => {
    if (!selectedProjectId && projects[0]) {
      setSelectedProjectId(projects[0].id);
    }
  }, [projects, selectedProjectId]);

  useEffect(() => {
    if (!selectedProjectId) return;
    void loadAnalyses(selectedProjectId);
  }, [selectedProjectId]);

  async function checkHealth() {
    try {
      const result = await apiFetch<{ status: string; service: string }>('/api/health');
      setHealth(`${result.status} • ${result.service}`);
    } catch {
      setHealth('Backend unavailable');
    }
  }

  async function loadProjects() {
    try {
      const data = await apiFetch<Project[]>('/api/projects');
      setProjects(data);
      if (!selectedProjectId && data[0]) {
        setSelectedProjectId(data[0].id);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unable to load projects');
    }
  }

  async function createProject() {
    if (!projectName.trim()) return;
    try {
      setLoading(true);
      const project = await apiFetch<Project>('/api/projects', {
        method: 'POST',
        body: JSON.stringify({ name: projectName, description: 'PrivTrace demo project' }),
      });
      setProjects((prev) => [project, ...prev]);
      setSelectedProjectId(project.id);
      setProjectName('');
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Project creation failed');
    } finally {
      setLoading(false);
    }
  }

  async function loadAnalyses(projectId: string) {
    try {
      const response = await apiFetch<{ analyses: Analysis[] }>(`/api/projects/${projectId}/analyses`);
      setAnalyses(response.analyses || []);
      if (!response.analyses?.length) {
        setFindings([]);
        return;
      }
      for (const analysis of response.analyses) {
        try {
          const payload = await apiFetch<{ findings: Finding[] }>(`/api/analyses/${analysis.id}/findings`);
          const findingsList = payload.findings || [];
          if (findingsList.length) {
            setFindings(findingsList);
            break;
          }
        } catch {
          // Ignore per-analysis loading issues.
        }
      }
    } catch {
      setFindings([]);
    }
  }

  async function runAnalysis() {
    if (!selectedProjectId) {
      setError('Create or select a project first.');
      return;
    }

    try {
      setLoading(true);
      setError('');
      const response = await apiFetch<{ analysis_id: string; findings: Finding[] }>(
        `/api/projects/${selectedProjectId}/analyze`,
        {
          method: 'POST',
          body: JSON.stringify({
            source_code: sourceCode,
            file_name: 'demo_login.py',
            policies: ['no-password-logging'],
            approved_destinations: ['api.example.com'],
          }),
        },
      );

      const analysisId = response.analysis_id;
      const result = await apiFetch<{ findings: Finding[] }>(`/api/analyses/${analysisId}/findings`);
      const graph = await apiFetch<{ nodes: any[]; edges: any[] }>(`/api/analyses/${analysisId}/graph`);
      const findingsList = result.findings || [];
      setFindings(findingsList);
      setSelectedFindingId(findingsList[0]?.id || '');
      setGraphNodes(graph.nodes || []);
      setGraphEdges(graph.edges || []);
      await loadAnalyses(selectedProjectId);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed');
    } finally {
      setLoading(false);
    }
  }

  const flowNodes = useMemo(
    () =>
      graphNodes.map((node, index) => ({
        id: String(node.id ?? index),
        data: { label: node.label ?? node.id },
        position: { x: 120 * (index % 4), y: 100 * Math.floor(index / 4) },
        style: {
          background: node.kind === 'sink' ? '#ef4444' : node.kind === 'source' ? '#22d3ee' : '#60a5fa',
          color: '#fff',
          border: '1px solid rgba(255,255,255,0.15)',
          borderRadius: 12,
          padding: 10,
        },
      })),
    [graphNodes],
  );

  const flowEdges = useMemo(
    () =>
      graphEdges.map((edge, index) => ({
        id: String(edge.id ?? `edge-${index}`),
        source: String(edge.source),
        target: String(edge.target),
        type: 'smoothstep',
        markerEnd: { type: MarkerType.ArrowClosed },
      })),
    [graphEdges],
  );

  const totalFindings = findings.length;
  const highSeverity = findings.filter((item) => item.severity === 'high').length;
  const mediumSeverity = findings.filter((item) => item.severity === 'medium').length;

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand-block">
          <div className="brand-mark">P</div>
          <div>
            <div className="brand-name">PrivTrace</div>
            <div className="brand-subtitle">Policy-aware leakage analysis</div>
          </div>
        </div>

        <nav className="nav-list">
          <button className="nav-item active">Dashboard</button>
          <button className="nav-item">Projects</button>
          <button className="nav-item">Code Analyzer</button>
          <button className="nav-item">Privacy Policies</button>
          <button className="nav-item">Findings</button>
          <button className="nav-item">Analysis History</button>
          <button className="nav-item">Settings</button>
        </nav>
      </aside>

      <main className="content-panel">
        <header className="topbar">
          <div>
            <div className="eyebrow">System status</div>
            <h1>PrivTrace security dashboard</h1>
          </div>
          <div className="status-badge">{health}</div>
        </header>

        <section className="stats-grid">
          <div className="stat-card">
            <div className="stat-label">Projects</div>
            <div className="stat-value">{projects.length}</div>
          </div>
          <div className="stat-card">
            <div className="stat-label">Analyses</div>
            <div className="stat-value">{analyses.length}</div>
          </div>
          <div className="stat-card danger">
            <div className="stat-label">High severity</div>
            <div className="stat-value">{highSeverity}</div>
          </div>
          <div className="stat-card medium">
            <div className="stat-label">Medium severity</div>
            <div className="stat-value">{mediumSeverity}</div>
          </div>
        </section>

        <section className="panel-grid">
          <div className="panel large-panel">
            <div className="panel-header">
              <h2>Code Analyzer</h2>
            </div>
            <div className="project-picker-row">
              <input
                value={projectName}
                onChange={(event) => setProjectName(event.target.value)}
                placeholder="Project name"
              />
              <button className="primary" onClick={createProject} disabled={loading}>Create project</button>
              <select value={selectedProjectId} onChange={(event) => setSelectedProjectId(event.target.value)}>
                {projects.map((project) => (
                  <option key={project.id} value={project.id}>
                    {project.name}
                  </option>
                ))}
              </select>
              <button className="primary" onClick={runAnalysis} disabled={loading || !selectedProjectId}>
                {loading ? 'Analyzing...' : 'Analyze'}
              </button>
            </div>

            <textarea
              className="code-editor"
              value={sourceCode}
              onChange={(event) => setSourceCode(event.target.value)}
            />

            {error && <div className="error-banner">{error}</div>}
          </div>

          <div className="panel">
            <div className="panel-header">
              <h2>Recent analysis history</h2>
            </div>
            <div className="history-list">
              {analyses.length === 0 ? (
                <div className="empty-state">No analysis history yet.</div>
              ) : (
                analyses.map((item) => (
                  <div key={item.id} className="history-item">
                    <div>
                      <strong>{item.status}</strong>
                      <div>{item.summary || 'No summary'}</div>
                    </div>
                    <span>{item.findings_count} findings</span>
                  </div>
                ))
              )}
            </div>
          </div>
        </section>

        <section className="panel-grid lower-grid">
          <div className="panel graph-panel">
            <div className="panel-header">
              <h2>Graph explorer</h2>
            </div>
            <div className="graph-wrap">
              {graphNodes.length || graphEdges.length ? (
                <ReactFlow nodes={flowNodes} edges={flowEdges} fitView minZoom={0.2} maxZoom={1.5}>
                  <MiniMap />
                  <Controls />
                  <Background gap={18} size={1} />
                </ReactFlow>
              ) : (
                <div className="empty-state">No graph data yet. Run an analysis to visualize the flow.</div>
              )}
            </div>
          </div>

          <div className="panel findings-panel">
            <div className="panel-header">
              <h2>Findings</h2>
            </div>
            <div className="finding-list">
              {findings.length === 0 ? (
                <div className="empty-state">No findings detected.</div>
              ) : (
                findings.map((finding) => (
                  <button
                    key={finding.id}
                    className={`finding-item ${selectedFinding?.id === finding.id ? 'selected' : ''}`}
                    onClick={() => setSelectedFindingId(finding.id)}
                  >
                    <div className="finding-topline">
                      <span className={`severity-pill ${finding.severity}`}>{finding.severity}</span>
                      <span>{finding.policy_name}</span>
                    </div>
                    <strong>{finding.title}</strong>
                    <div>{finding.source} → {finding.destination}</div>
                  </button>
                ))
              )}
            </div>
          </div>
        </section>

        {selectedFinding && (
          <section className="panel detail-panel">
            <div className="panel-header">
              <h2>Finding detail</h2>
            </div>
            <div className="detail-grid">
              <div>
                <div className="detail-row"><span>Title</span><strong>{selectedFinding.title}</strong></div>
                <div className="detail-row"><span>Severity</span><strong>{selectedFinding.severity}</strong></div>
                <div className="detail-row"><span>Policy</span><strong>{selectedFinding.policy_name}</strong></div>
                <div className="detail-row"><span>Category</span><strong>{selectedFinding.data_category}</strong></div>
              </div>
              <div>
                <div className="detail-row"><span>Source</span><strong>{selectedFinding.source}</strong></div>
                <div className="detail-row"><span>Destination</span><strong>{selectedFinding.destination}</strong></div>
                <div className="detail-row"><span>Line(s)</span><strong>{selectedFinding.line_numbers.join(', ') || 'n/a'}</strong></div>
                <div className="detail-row"><span>Path</span><strong>{selectedFinding.intermediate_path.join(' → ')}</strong></div>
              </div>
            </div>
            <p className="detail-text">{selectedFinding.explanation}</p>
            <p className="detail-text"><strong>Remediation:</strong> {selectedFinding.remediation}</p>
            <p className="detail-text"><strong>Limitations:</strong> {selectedFinding.limitations}</p>
          </section>
        )}

        <section className="panel summary-panel">
          <div className="panel-header">
            <h2>Analysis summary</h2>
          </div>
          <div className="summary-box">
            <div>Total findings: <strong>{totalFindings}</strong></div>
            <div>High: <strong>{highSeverity}</strong></div>
            <div>Medium: <strong>{mediumSeverity}</strong></div>
          </div>
        </section>
      </main>
    </div>
  );
}

export default App;
