import axios from 'axios';
import type { AnalysisResult, DashboardStats, Incident, Indicator } from '../types';

const api = axios.create({ baseURL: '/api/v1' });

export const getDashboard = () =>
  api.get<DashboardStats>('/dashboard').then(r => r.data);

export const analyzeIndicator = (value: string, indicator_type?: string) =>
  api.post<AnalysisResult>('/indicators/analyze', { value, indicator_type }).then(r => r.data);

export const getIndicators = (params?: {
  severity?: string; indicator_type?: string; is_active?: boolean; limit?: number;
}) => api.get<Indicator[]>('/indicators/', { params }).then(r => r.data);

export const getIndicator = (id: number) =>
  api.get<Indicator>(`/indicators/${id}`).then(r => r.data);

export const markFalsePositive = (id: number) =>
  api.patch<Indicator>(`/indicators/${id}/false-positive`).then(r => r.data);

export const getIncidents = (params?: { status?: string; severity?: string }) =>
  api.get<Incident[]>('/incidents/', { params }).then(r => r.data);

export const getIncident = (id: number) =>
  api.get<Incident>(`/incidents/${id}`).then(r => r.data);

export const updateIncidentStatus = (id: number, status: string) =>
  api.patch<Incident>(`/incidents/${id}/status`, null, { params: { status } }).then(r => r.data);

export const seedDemo = () =>
  api.post<{ status: string; detail: string }>('/demo/seed').then(r => r.data);
