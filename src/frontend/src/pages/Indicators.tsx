import { useEffect, useState } from 'react';
import { getIndicators } from '../api/client';
import type { Indicator } from '../types';
import { SeverityBadge, RiskBar, TypeBadge, Spinner, ErrorBox, DemoBanner } from '../components/shared';
import { Activity, Filter } from 'lucide-react';

const SEVERITIES = ['', 'critical', 'high', 'medium', 'low', 'info'];
const TYPES = ['', 'ip', 'domain', 'url', 'hash', 'email'];

export default function Indicators() {
  const [indicators, setIndicators] = useState<Indicator[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [severity, setSeverity] = useState('');
  const [type, setType] = useState('');

  useEffect(() => {
    setLoading(true);
    const params: Record<string, string | number> = { limit: 200 };
    if (severity) params.severity = severity;
    if (type) params.indicator_type = type;
    getIndicators(params)
      .then(setIndicators)
      .catch(() => setError('Failed to load indicators.'))
      .finally(() => setLoading(false));
  }, [severity, type]);

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <Activity className="w-5 h-5 text-blue-400" />
          <h1 className="text-xl font-bold text-white">Threat Indicators</h1>
          <span className="badge bg-slate-800 text-slate-400 border border-slate-700">
            {indicators.length} results
          </span>
        </div>
        <DemoBanner />
      </div>

      {/* Filters */}
      <div className="card flex flex-wrap items-center gap-3">
        <Filter className="w-4 h-4 text-slate-500" />
        <select value={severity} onChange={e => setSeverity(e.target.value)} className="input w-auto text-xs py-1.5">
          {SEVERITIES.map(s => <option key={s} value={s}>{s || 'All Severities'}</option>)}
        </select>
        <select value={type} onChange={e => setType(e.target.value)} className="input w-auto text-xs py-1.5">
          {TYPES.map(t => <option key={t} value={t}>{t || 'All Types'}</option>)}
        </select>
      </div>

      {loading && <Spinner />}
      {error && <ErrorBox msg={error} />}

      {!loading && !error && (
        <div className="card p-0 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-slate-800">
                {['Type', 'Value', 'Severity', 'Risk Score', 'Category', 'Hits', 'Last Seen'].map(h => (
                  <th key={h} className="text-left px-4 py-3 text-slate-500 font-medium text-xs uppercase">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {indicators.map(ind => (
                <tr key={ind.id} className={`table-row ${ind.is_false_positive ? 'opacity-50' : ''}`}>
                  <td className="px-4 py-2.5"><TypeBadge type={ind.indicator_type} /></td>
                  <td className="px-4 py-2.5 font-mono text-xs text-slate-300 max-w-[220px] truncate"
                      title={ind.value}>{ind.value}</td>
                  <td className="px-4 py-2.5"><SeverityBadge severity={ind.severity} /></td>
                  <td className="px-4 py-2.5 w-36"><RiskBar score={ind.risk_score} /></td>
                  <td className="px-4 py-2.5 text-slate-400 text-xs">{ind.category ?? '—'}</td>
                  <td className="px-4 py-2.5 text-slate-400 text-xs">{ind.hit_count}</td>
                  <td className="px-4 py-2.5 text-slate-500 text-xs whitespace-nowrap">
                    {new Date(ind.last_seen).toLocaleDateString()}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          {indicators.length === 0 && (
            <p className="text-center py-10 text-slate-500 text-sm">No indicators found.</p>
          )}
        </div>
      )}
    </div>
  );
}
