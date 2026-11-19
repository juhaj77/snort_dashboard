// Snort priority -> severity. Snort uses 1 (high) … 4 (very low); alerts from rules
// without a priority (e.g. local test rules) carry 0, shown here as "unset".
// Colours live in App.css (--p1 … --p4, --p0) so tables, badges and charts agree.
export const SEVERITIES = [
  { p: 1, label: 'High' },
  { p: 2, label: 'Medium' },
  { p: 3, label: 'Low' },
  { p: 4, label: 'Very low' },
  { p: 0, label: 'Unset' },
]

export const sevColor = p => `var(--p${p})`
export const sevLabel = p => (SEVERITIES.find(s => s.p === p) || SEVERITIES[4]).label
export const emptySevCounts = () => ({ 1: 0, 2: 0, 3: 0, 4: 0, 0: 0 })
