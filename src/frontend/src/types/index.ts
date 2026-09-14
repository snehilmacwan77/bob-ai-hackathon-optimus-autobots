export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';
export type IndicatorType = 'ip' | 'domain' | 'url' | 'hash' | 'email' | 'unknown';
export type IncidentStatus = 'open' | 'investigating' | 'contained' | 'resolved';

export interface AnalysisResult {
  value: string;
  indicator_type: IndicatorType;
  risk_score: number;
  severity: Severity;
  confidence: number;
  category: string;
  analysis_summary: string;
  recommendations: string[];
  mitre_techniques: string[];
  tags: string[];
  is_demo_data: boolean;
}

export interface Indicator {
  id: number;
  value: string;
  indicator_type: IndicatorType;
  risk_score: number;
  severity: Severity;
  confidence: number;
  category: string | null;
  tags: string[];
  source: string;
  analysis_summary: string | null;
  recommendations: string[];
  mitre_techniques: string[];
  is_demo_data: boolean;
  is_false_positive: boolean;
  is_active: boolean;
  first_seen: string;
  last_seen: string;
  hit_count: number;
  investigation_count: number;
}

export interface Incident {
  id: number;
  title: string;
  description: string | null;
  severity: Severity;
  status: IncidentStatus;
  risk_score: number;
  confidence: number;
  mitre_techniques: string[];
  attack_vector: string | null;
  bluf_summary: string | null;
  recommended_actions: string[];
  containment_steps: string[];
  affected_assets: string[];
  is_demo_data: boolean;
  detected_at: string;
  updated_at: string;
  resolved_at: string | null;
}

export interface DashboardStats {
  total_indicators: number;
  active_indicators: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  false_positive_count: number;
  total_incidents: number;
  open_incidents: number;
  severity_distribution: Record<Severity, number>;
  top_categories: Array<{ category: string; count: number }>;
  recent_indicators: Indicator[];
  recent_incidents: Incident[];
  is_demo_data: boolean;
}
