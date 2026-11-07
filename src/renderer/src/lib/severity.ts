// Severity scale shared by every findings table.
export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info'

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info']

export const severityPill: Record<Severity, string> = {
  critical: 'pill-crit',
  high: 'pill-high',
  medium: 'pill-warn',
  low: 'pill-info',
  info: 'pill-muted'
}
