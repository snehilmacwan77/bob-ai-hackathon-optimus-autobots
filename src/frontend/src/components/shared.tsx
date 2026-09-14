import type { Severity } from '../types';

const SEV_BADGE: Record<string, string> = {
  critical: 'badge-critical',
  high:     'badge-high',
  medium:   'badge-medium',
  low:      'badge-low',
  info:     'badge-info',
};

const STATUS_BADGE: Record<string, string> = {
  open:         'badge bg-blue-900/60 text-blue-300 border border-blue-700/60',
  investigating:'badge bg-purple-900/60 text-purple-300 border border-purple-700/60',
  contained:    'badge bg-yellow-900/60 text-yellow-300 border border-yellow-700/60',
  resolved:     'badge-info',
};

export function SeverityBadge({ severity }: { severity: string }) {
  return <span className={SEV_BADGE[severity] ?? 'badge-info'}>{severity.toUpperCase()}</span>;
}

export function StatusBadge({ status }: { status: string }) {
  return (
    <span className={STATUS_BADGE[status] ?? 'badge-info'}>
      {status.charAt(0).toUpperCase() + status.slice(1)}
    </span>
  );
}

export function RiskBar({ score }: { score: number }) {
  const colour =
    score >= 80 ? 'bg-red-500' :
    score >= 60 ? 'bg-orange-500' :
    score >= 35 ? 'bg-yellow-500' : 'bg-green-500';
  const textColour =
    score >= 80 ? 'text-red-400' :
    score >= 60 ? 'text-orange-400' :
    score >= 35 ? 'text-yellow-400' : 'text-green-400';
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 bg-slate-800 rounded-full h-1.5 w-20">
        <div className={`h-1.5 rounded-full ${colour}`} style={{ width: `${score}%` }} />
      </div>
      <span className={`text-xs font-mono font-bold ${textColour} w-6 text-right`}>
        {score.toFixed(0)}
      </span>
    </div>
  );
}

export function Spinner() {
  return (
    <div className="flex items-center justify-center py-16">
      <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
    </div>
  );
}

export function ErrorBox({ msg }: { msg: string }) {
  return (
    <div className="bg-red-900/30 border border-red-700 text-red-300 rounded-xl p-4 text-sm">
      {msg}
    </div>
  );
}

export function DemoBanner() {
  return (
    <div className="bg-amber-900/30 border border-amber-700/60 text-amber-300 text-xs px-3 py-2 rounded-lg flex items-center gap-2">
      <span className="font-bold">DEMO DATA</span>
      <span>All threat intelligence shown is entirely synthetic. No real feeds are queried.</span>
    </div>
  );
}

export function TypeBadge({ type }: { type: string }) {
  const cls: Record<string, string> = {
    ip:     'badge bg-cyan-900/50 text-cyan-300 border border-cyan-700/60',
    domain: 'badge bg-indigo-900/50 text-indigo-300 border border-indigo-700/60',
    url:    'badge bg-teal-900/50 text-teal-300 border border-teal-700/60',
    hash:   'badge bg-violet-900/50 text-violet-300 border border-violet-700/60',
    email:  'badge bg-pink-900/50 text-pink-300 border border-pink-700/60',
    unknown:'badge-info',
  };
  return <span className={cls[type] ?? 'badge-info'}>{type.toUpperCase()}</span>;
}
