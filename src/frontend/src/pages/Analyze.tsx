import { useState } from 'react';
import { analyzeIndicator } from '../api/client';
import type { AnalysisResult } from '../types';
import {
  SeverityBadge, RiskBar, DemoBanner, TypeBadge, Spinner, ErrorBox,
} from '../components/shared';
import { Search, Shield, Lightbulb, FileText, CheckCircle2, AlertCircle } from 'lucide-react';

const EXAMPLES = [
  '185.220.101.45',
  'update.microsofft.com',
  'http://secure-login.paypa1.com/login',
  '44d88612fea8a8f36de82e1278abb02f',
  '192.168.1.1',
];

function MitreTag({ id }: { id: string }) {
  return (
    <span className="badge bg-purple-900/40 text-purple-300 border border-purple-700/60 font-mono">
      {id}
    </span>
  );
}

export default function Analyze() {
  const [value, setValue] = useState('');
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [error, setError] = useState('');

  const submit = async (val?: string) => {
    const v = (val ?? value).trim();
    if (!v) return;
    setValue(v);
    setLoading(true);
    setError('');
    setResult(null);
    try {
      const r = await analyzeIndicator(v);
      setResult(r);
    } catch (e: any) {
      setError(e?.response?.data?.detail ?? 'Analysis failed. Is the backend running on port 9000?');
    } finally {
      setLoading(false);
    }
  };

  const handleKey = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') submit();
  };

  const scoreColour = !result ? '' :
    result.risk_score >= 80 ? 'text-red-400' :
    result.risk_score >= 60 ? 'text-orange-400' :
    result.risk_score >= 35 ? 'text-yellow-400' : 'text-green-400';

  return (
    <div className="space-y-5 max-w-3xl">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <Search className="w-5 h-5 text-blue-400" />
          <h1 className="text-xl font-bold text-white">Analyze Indicator of Compromise</h1>
        </div>
        <DemoBanner />
      </div>

      {/* Input */}
      <div className="card space-y-3">
        <p className="text-sm text-slate-400">
          Enter an IP address, domain, URL, or file hash to receive an AI-powered threat analysis.
        </p>
        <div className="flex gap-2">
          <input
            type="text"
            value={value}
            onChange={e => setValue(e.target.value)}
            onKeyDown={handleKey}
            placeholder="e.g. 185.220.101.45 or update.microsofft.com"
            className="input flex-1"
          />
          <button onClick={() => submit()} className="btn-primary" disabled={loading || !value.trim()}>
            {loading ? <Spinner /> : <Search className="w-4 h-4" />}
            {loading ? 'Analyzing…' : 'Analyze'}
          </button>
        </div>
        <div className="flex flex-wrap gap-2">
          <span className="text-xs text-slate-500">Try:</span>
          {EXAMPLES.map(ex => (
            <button
              key={ex}
              onClick={() => submit(ex)}
              className="text-xs text-blue-400 hover:text-blue-300 font-mono transition-colors"
            >
              {ex.length > 35 ? ex.slice(0, 35) + '…' : ex}
            </button>
          ))}
        </div>
      </div>

      {error && <ErrorBox msg={error} />}

      {result && (
        <div className="space-y-4">
          {/* Header */}
          <div className="card">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div className="min-w-0">
                <p className="text-xs text-slate-500 mb-1">Analyzed Indicator</p>
                <p className="text-lg font-mono font-bold text-white break-all">{result.value}</p>
                <div className="flex flex-wrap items-center gap-2 mt-2">
                  <TypeBadge type={result.indicator_type} />
                  <SeverityBadge severity={result.severity} />
                  <span className="text-xs text-slate-500">
                    Confidence: {(result.confidence * 100).toFixed(0)}%
                  </span>
                </div>
              </div>
              <div className="text-right">
                <p className="text-xs text-slate-500 mb-1">Risk Score</p>
                <p className={`text-5xl font-bold font-mono ${scoreColour}`}>
                  {result.risk_score.toFixed(0)}
                </p>
                <p className="text-xs text-slate-500">/ 100</p>
              </div>
            </div>
            <div className="mt-3">
              <RiskBar score={result.risk_score} />
            </div>
          </div>

          {/* Tags */}
          {result.tags.length > 0 && (
            <div className="flex flex-wrap gap-2">
              {result.tags.map(t => (
                <span key={t} className="badge bg-slate-800 text-slate-400 border border-slate-700">
                  {t}
                </span>
              ))}
            </div>
          )}

          {/* AI Analysis */}
          <div className="card space-y-2">
            <div className="flex items-center gap-2">
              <FileText className="w-4 h-4 text-blue-400" />
              <h2 className="text-sm font-semibold text-slate-200">AI Threat Analysis</h2>
            </div>
            <p className="text-sm text-slate-300 leading-relaxed bg-slate-800/50 p-3 rounded-lg">
              {result.analysis_summary}
            </p>
          </div>

          {/* MITRE */}
          {result.mitre_techniques.length > 0 && (
            <div className="card space-y-2">
              <div className="flex items-center gap-2">
                <Shield className="w-4 h-4 text-purple-400" />
                <h2 className="text-sm font-semibold text-slate-200">MITRE ATT&CK Techniques</h2>
              </div>
              <div className="flex flex-wrap gap-2">
                {result.mitre_techniques.map(t => <MitreTag key={t} id={t} />)}
              </div>
            </div>
          )}

          {/* Recommendations */}
          {result.recommendations.length > 0 && (
            <div className="card space-y-2">
              <div className="flex items-center gap-2">
                <Lightbulb className="w-4 h-4 text-yellow-400" />
                <h2 className="text-sm font-semibold text-slate-200">Security Recommendations</h2>
              </div>
              <ul className="space-y-2">
                {result.recommendations.map((rec, i) => (
                  <li key={i} className="flex gap-2.5 text-sm text-slate-300">
                    <CheckCircle2 className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
                    {rec}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {result.is_demo_data && (
            <div className="flex items-start gap-2 p-3 bg-amber-900/20 border border-amber-700/60 rounded-lg text-xs text-amber-300">
              <AlertCircle className="w-4 h-4 shrink-0 mt-0.5" />
              This analysis is based entirely on synthetic demonstration data. The results are not real threat intelligence.
            </div>
          )}
        </div>
      )}
    </div>
  );
}
