import { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip,
  ResponsiveContainer,
} from 'recharts';
import { getDashboard } from '../api/client';
import type { DashboardStats } from '../types';
import {
  SeverityBadge, StatusBadge, RiskBar, Spinner, ErrorBox, DemoBanner, TypeBadge,
} from '../components/shared';
import { Activity, AlertTriangle, ShieldAlert, TrendingUp, FolderOpen } from 'lucide-react';

const SEV_COLORS: Record<string, string> = {
  critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e', info: '#6b7280',
};

function StatCard({ label, value, accent, sub }: {
  label: string; value: number | string; accent?: string; sub?: string;
}) {
  return (
    <div className="card flex flex-col gap-1">
      <p className="text-xs text-slate-500 uppercase tracking-wide">{label}</p>
      <p className={`text-3xl font-bold ${accent ?? 'text-white'}`}>{value}</p>
      {sub && <p className="text-xs text-slate-500">{sub}</p>}
    </div>
  );
}

export default function Dashboard() {
  const [stats, setStats] = useState<DashboardStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const navigate = useNavigate();

  useEffect(() => {
    getDashboard()
      .then(setStats)
      .catch(() => setError('Could not load dashboard. Make sure the backend is running on port 9000.'))
      .finally(() => setLoading(false));
  }, []);

  if (loading) return <Spinner />;
  if (error) return <ErrorBox msg={error} />;
  if (!stats) return null;

  const sevData = Object.entries(stats.severity_distribution).map(([k, v]) => ({
    name: k, value: v, fill: SEV_COLORS[k] ?? '#6b7280',
  }));

  const catData = stats.top_categories.slice(0, 8).map(c => ({
    name: c.category.replace(/-/g, ' ').slice(0, 18),
    count: c.count,
  }));

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <Activity className="w-5 h-5 text-blue-400" />
          <h1 className="text-xl font-bold text-white">Threat Intelligence Dashboard</h1>
        </div>
        <DemoBanner />
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <StatCard label="Total IOCs"     value={stats.total_indicators} />
        <StatCard label="Active"         value={stats.active_indicators} />
        <StatCard label="Critical"       value={stats.critical_count} accent="text-red-400" />
        <StatCard label="High"           value={stats.high_count} accent="text-orange-400" />
        <StatCard label="False Positives" value={stats.false_positive_count} accent="text-green-400" />
        <StatCard label="Open Incidents" value={stats.open_incidents} accent="text-blue-400" />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <div className="card">
          <div className="flex items-center gap-2 mb-3">
            <AlertTriangle className="w-4 h-4 text-orange-400" />
            <h2 className="text-sm font-semibold text-slate-200">Severity Distribution</h2>
          </div>
          <ResponsiveContainer width="100%" height={220}>
            <PieChart>
              <Pie
                data={sevData} cx="50%" cy="50%"
                innerRadius={55} outerRadius={85}
                paddingAngle={3} dataKey="value"
                label={({ name, value }) => value > 0 ? `${name} (${value})` : ''}
                labelLine={false}
              >
                {sevData.map(e => <Cell key={e.name} fill={e.fill} />)}
              </Pie>
              <Tooltip
                contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8 }}
                itemStyle={{ color: '#f1f5f9' }}
              />
            </PieChart>
          </ResponsiveContainer>
        </div>

        <div className="card">
          <div className="flex items-center gap-2 mb-3">
            <TrendingUp className="w-4 h-4 text-purple-400" />
            <h2 className="text-sm font-semibold text-slate-200">Top Threat Categories</h2>
          </div>
          <ResponsiveContainer width="100%" height={220}>
            <BarChart data={catData} layout="vertical" margin={{ left: 0, right: 16 }}>
              <XAxis type="number" tick={{ fill: '#64748b', fontSize: 11 }} />
              <YAxis type="category" dataKey="name" tick={{ fill: '#94a3b8', fontSize: 11 }} width={100} />
              <Tooltip
                contentStyle={{ background: '#1e293b', border: '1px solid #334155', borderRadius: 8 }}
                itemStyle={{ color: '#f1f5f9' }}
              />
              <Bar dataKey="count" fill="#6366f1" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Recent */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Recent indicators */}
        <div className="card">
          <div className="flex items-center gap-2 mb-3">
            <ShieldAlert className="w-4 h-4 text-red-400" />
            <h2 className="text-sm font-semibold text-slate-200">Recent Threat Indicators</h2>
          </div>
          <div className="space-y-1.5">
            {stats.recent_indicators.slice(0, 8).map(ind => (
              <div
                key={ind.id}
                className="flex items-center justify-between py-1.5 border-b border-slate-800/60 last:border-0 cursor-pointer hover:bg-slate-800/30 rounded px-1 transition-colors"
                onClick={() => navigate('/indicators')}
              >
                <div className="flex items-center gap-2 min-w-0">
                  <TypeBadge type={ind.indicator_type} />
                  <span className="text-xs font-mono text-slate-300 truncate max-w-[180px]">{ind.value}</span>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <SeverityBadge severity={ind.severity} />
                  <RiskBar score={ind.risk_score} />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Recent incidents */}
        <div className="card">
          <div className="flex items-center gap-2 mb-3">
            <FolderOpen className="w-4 h-4 text-blue-400" />
            <h2 className="text-sm font-semibold text-slate-200">Recent Incidents</h2>
          </div>
          <div className="space-y-2">
            {stats.recent_incidents.map(inc => (
              <div
                key={inc.id}
                className="p-3 bg-slate-800/50 border border-slate-700/60 rounded-lg cursor-pointer hover:border-blue-700/50 transition-colors"
                onClick={() => navigate(`/incidents/${inc.id}`)}
              >
                <div className="flex items-start justify-between gap-2">
                  <p className="text-sm text-slate-200 font-medium truncate">{inc.title}</p>
                  <SeverityBadge severity={inc.severity} />
                </div>
                <div className="flex items-center gap-3 mt-1.5">
                  <StatusBadge status={inc.status} />
                  <RiskBar score={inc.risk_score} />
                </div>
              </div>
            ))}
            {stats.recent_incidents.length === 0 && (
              <p className="text-sm text-slate-500 text-center py-4">No incidents yet.</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
