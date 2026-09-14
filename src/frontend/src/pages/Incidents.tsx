import { useEffect, useState } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import { getIncidents, getIncident, updateIncidentStatus } from '../api/client';
import type { Incident } from '../types';
import {
  SeverityBadge, StatusBadge, RiskBar, Spinner, ErrorBox, DemoBanner,
} from '../components/shared';
import {
  FolderOpen, ArrowLeft, Shield, Server, Lightbulb, FileText, AlertTriangle, CheckCircle2,
} from 'lucide-react';

// ── Incident List ─────────────────────────────────────────────────────────────

export function IncidentList() {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    getIncidents()
      .then(setIncidents)
      .catch(() => setError('Failed to load incidents.'))
      .finally(() => setLoading(false));
  }, []);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <FolderOpen className="w-5 h-5 text-blue-400" />
          <h1 className="text-xl font-bold text-white">Security Incidents</h1>
          <span className="badge bg-slate-800 text-slate-400 border border-slate-700">{incidents.length}</span>
        </div>
        <DemoBanner />
      </div>

      {loading && <Spinner />}
      {error && <ErrorBox msg={error} />}

      {!loading && !error && (
        <div className="space-y-3">
          {incidents.map(inc => (
            <div
              key={inc.id}
              className="card cursor-pointer hover:border-blue-700/50 transition-colors"
              onClick={() => navigate(`/incidents/${inc.id}`)}
            >
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <h3 className="text-sm font-semibold text-white">{inc.title}</h3>
                    <SeverityBadge severity={inc.severity} />
                    <StatusBadge status={inc.status} />
                  </div>
                  {inc.description && (
                    <p className="text-xs text-slate-400 mt-1 truncate">{inc.description}</p>
                  )}
                  <div className="flex flex-wrap items-center gap-3 mt-2">
                    <RiskBar score={inc.risk_score} />
                    <span className="text-xs text-slate-500">
                      Confidence: {(inc.confidence * 100).toFixed(0)}%
                    </span>
                    {inc.attack_vector && (
                      <span className="text-xs text-slate-500 truncate max-w-[200px]">
                        {inc.attack_vector}
                      </span>
                    )}
                  </div>
                </div>
                <div className="text-right shrink-0">
                  <p className="text-xs text-slate-500">{new Date(inc.detected_at).toLocaleDateString()}</p>
                </div>
              </div>
            </div>
          ))}
          {incidents.length === 0 && (
            <p className="text-center py-16 text-slate-500">No incidents found.</p>
          )}
        </div>
      )}
    </div>
  );
}

// ── Incident Detail ───────────────────────────────────────────────────────────

export function IncidentDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [inc, setInc] = useState<Incident | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [updating, setUpdating] = useState(false);

  useEffect(() => {
    if (!id) return;
    getIncident(Number(id))
      .then(setInc)
      .catch(() => setError('Incident not found.'))
      .finally(() => setLoading(false));
  }, [id]);

  const setStatus = async (status: string) => {
    if (!inc) return;
    setUpdating(true);
    try {
      const updated = await updateIncidentStatus(inc.id, status);
      setInc(updated);
    } finally {
      setUpdating(false);
    }
  };

  if (loading) return <Spinner />;
  if (error) return <ErrorBox msg={error} />;
  if (!inc) return null;

  const scoreColour =
    inc.risk_score >= 80 ? 'text-red-400' :
    inc.risk_score >= 60 ? 'text-orange-400' :
    inc.risk_score >= 35 ? 'text-yellow-400' : 'text-green-400';

  return (
    <div className="space-y-5 max-w-4xl">
      {/* Header */}
      <div className="flex flex-wrap items-start gap-3">
        <button onClick={() => navigate('/incidents')} className="btn-secondary text-xs px-2.5 py-1.5">
          <ArrowLeft className="w-3.5 h-3.5" /> Back
        </button>
        <div className="flex-1 min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-lg font-bold text-white">{inc.title}</h1>
            <SeverityBadge severity={inc.severity} />
            <StatusBadge status={inc.status} />
          </div>
          <p className="text-xs text-slate-500 mt-0.5">
            Incident #{inc.id} · Detected {new Date(inc.detected_at).toLocaleString()}
          </p>
        </div>
        <div className="flex gap-2 flex-wrap">
          {['open', 'investigating', 'contained', 'resolved'].filter(s => s !== inc.status).map(s => (
            <button key={s} onClick={() => setStatus(s)} disabled={updating} className="btn-secondary text-xs capitalize">
              {s}
            </button>
          ))}
        </div>
      </div>

      {/* Score row */}
      <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
        <div className="card">
          <p className="text-xs text-slate-500 uppercase tracking-wide mb-1">Risk Score</p>
          <p className={`text-4xl font-bold font-mono ${scoreColour}`}>{inc.risk_score.toFixed(0)}</p>
          <p className="text-xs text-slate-500">/ 100</p>
          <div className="mt-2"><RiskBar score={inc.risk_score} /></div>
        </div>
        <div className="card">
          <p className="text-xs text-slate-500 uppercase tracking-wide mb-1">Confidence</p>
          <p className="text-4xl font-bold text-white">{(inc.confidence * 100).toFixed(0)}%</p>
        </div>
        <div className="card">
          <p className="text-xs text-slate-500 uppercase tracking-wide mb-1">Attack Vector</p>
          <p className="text-sm text-slate-200 leading-relaxed">{inc.attack_vector ?? 'Unknown'}</p>
        </div>
      </div>

      {/* BLUF */}
      {inc.bluf_summary && (
        <div className="card space-y-2">
          <div className="flex items-center gap-2">
            <FileText className="w-4 h-4 text-blue-400" />
            <h2 className="text-sm font-semibold text-slate-200">AI Threat Summary (BLUF)</h2>
          </div>
          <p className="text-sm text-slate-300 leading-relaxed bg-slate-800/50 p-3 rounded-lg">
            {inc.bluf_summary}
          </p>
        </div>
      )}

      {/* Description */}
      {inc.description && (
        <div className="card space-y-2">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-4 h-4 text-orange-400" />
            <h2 className="text-sm font-semibold text-slate-200">Incident Description</h2>
          </div>
          <p className="text-sm text-slate-300 leading-relaxed">{inc.description}</p>
        </div>
      )}

      {/* MITRE */}
      {inc.mitre_techniques.length > 0 && (
        <div className="card space-y-2">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-purple-400" />
            <h2 className="text-sm font-semibold text-slate-200">MITRE ATT&CK Techniques</h2>
          </div>
          <div className="flex flex-wrap gap-2">
            {inc.mitre_techniques.map(t => (
              <span key={t} className="badge bg-purple-900/40 text-purple-300 border border-purple-700/60 font-mono">{t}</span>
            ))}
          </div>
        </div>
      )}

      {/* Affected assets */}
      {inc.affected_assets.length > 0 && (
        <div className="card space-y-2">
          <div className="flex items-center gap-2">
            <Server className="w-4 h-4 text-cyan-400" />
            <h2 className="text-sm font-semibold text-slate-200">Affected Assets</h2>
          </div>
          <div className="flex flex-wrap gap-2">
            {inc.affected_assets.map(a => (
              <span key={a} className="badge bg-slate-800 text-slate-300 border border-slate-600 font-mono">{a}</span>
            ))}
          </div>
        </div>
      )}

      {/* Recommended actions */}
      {inc.recommended_actions.length > 0 && (
        <div className="card space-y-2">
          <div className="flex items-center gap-2">
            <Lightbulb className="w-4 h-4 text-yellow-400" />
            <h2 className="text-sm font-semibold text-slate-200">Recommended Actions</h2>
          </div>
          <ul className="space-y-2">
            {inc.recommended_actions.map((a, i) => (
              <li key={i} className="flex gap-2.5 text-sm text-slate-300">
                <CheckCircle2 className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
                {a}
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Containment steps */}
      {inc.containment_steps.length > 0 && (
        <div className="card space-y-2">
          <div className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-red-400" />
            <h2 className="text-sm font-semibold text-slate-200">Containment Steps</h2>
          </div>
          <ol className="space-y-2">
            {inc.containment_steps.map((s, i) => (
              <li key={i} className="flex gap-2.5 text-sm text-slate-300">
                <span className="text-red-400 font-bold shrink-0">{i + 1}.</span>
                {s}
              </li>
            ))}
          </ol>
        </div>
      )}
    </div>
  );
}
