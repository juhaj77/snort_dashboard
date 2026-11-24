// Pure functions that turn raw log records into chart-ready summaries.
// Everything here works only from fields that are present in the logs;
// missing values are counted as missing, never guessed.
import { emptySevCounts } from './severity'

const VALID_PRIORITIES = [1, 2, 3, 4]

/** Host part of Snort's "addr:port" string (works for IPv6 too: split at the last ':'). */
export const hostOf = ap => {
  if (typeof ap !== 'string') return null
  const i = ap.lastIndexOf(':')
  const host = i === -1 ? ap : ap.slice(0, i)
  return host === '' ? null : host
}

const portOf = (port, ap) => {
  if (Number.isFinite(Number(port)) && port !== null && port !== '') return Number(port)
  if (typeof ap !== 'string') return null
  const p = Number(ap.slice(ap.lastIndexOf(':') + 1))
  return Number.isFinite(p) && p > 0 ? p : null
}

/**
 * Validate and normalise one alert_json record. Returns null for records that
 * cannot be placed on a timeline (no numeric `seconds`).
 */
export const normalizeAlert = (a, index = 0) => {
  if (!a || typeof a !== 'object') return null
  const seconds = Number(a.seconds)
  if (a.seconds === undefined || a.seconds === null || !Number.isFinite(seconds)) return null
  const p = parseInt(a.priority, 10)
  return {
    raw: a,
    // stable across refreshes: several rules can fire on one packet, so include the rule
    id: `${a.timestamp || seconds}#${a.pkt_num ?? 'i' + index}#${a.rule || ''}`,
    seconds,
    timestamp: a.timestamp || null,
    priority: VALID_PRIORITIES.includes(p) ? p : 0,
    proto: a.proto || null,
    srcIp: a.src_addr || hostOf(a.src_ap),
    dstIp: a.dst_addr || hostOf(a.dst_ap),
    srcPort: portOf(a.src_port, a.src_ap),
    dstPort: portOf(a.dst_port, a.dst_ap),
    msg: a.msg || null,
    rule: a.rule || (a.gid !== undefined && a.sid !== undefined ? `${a.gid}:${a.sid}:${a.rev ?? '?'}` : null),
    cls: a.class && a.class !== 'none' ? a.class : null,
  }
}

/** Normalise a list, dropping bad records. Returns { alerts (oldest first), dropped }. */
export const normalizeAlerts = list => {
  if (!Array.isArray(list)) return { alerts: [], dropped: 0 }
  const alerts = []
  list.forEach((a, i) => {
    const n = normalizeAlert(a, i)
    if (n) alerts.push(n)
  })
  alerts.sort((a, b) => a.seconds - b.seconds)
  return { alerts, dropped: list.length - alerts.length }
}

/**
 * Alerts of a time window fetched with `?since=` and a limit of cap + 1.
 * - Filters by `since` here too, so a server that ignores `since` (older version)
 *   cannot inflate the window.
 * - truncated: the server hit the limit while every returned alert was still
 *   inside the window, i.e. older alerts of the window were not loaded.
 * Without `since` this is plain normalisation.
 */
export const windowAlerts = (data, since, cap) => {
  const { alerts, dropped } = normalizeAlerts(data)
  if (since === undefined || since === null) return { alerts, dropped, truncated: false }
  const inWindow = alerts.filter(a => a.seconds >= since)
  const truncated = Array.isArray(data) && data.length > cap && inWindow.length === alerts.length
  return { alerts: inWindow.length > cap ? inWindow.slice(-cap) : inWindow, dropped, truncated }
}

export const severityCounts = alerts => {
  const c = emptySevCounts()
  alerts.forEach(a => { c[a.priority] += 1 })
  return c
}

const STEPS = [1, 5, 10, 30, 60, 120, 300, 600, 900, 1800, 3600, 7200, 10800, 21600, 43200, 86400]

/** Pick a "nice" bin width so the span gives at most `target` bins. */
export const pickStep = (span, target = 60) =>
  STEPS.find(s => span / s <= target) || Math.ceil(span / target / 86400) * 86400

/** Stacked-by-severity histogram over time. Empty bins are kept (gaps are information). */
export const timeBins = (alerts, target = 60, range) => {
  if (alerts.length === 0) return { step: 0, bins: [] }
  const min = range ? range[0] : alerts[0].seconds
  const max = range ? range[1] : alerts[alerts.length - 1].seconds
  const step = pickStep(Math.max(max - min, 1), target)
  const start = Math.floor(min / step) * step
  const n = Math.floor((max - start) / step) + 1
  const bins = Array.from({ length: n }, (_, i) => ({ t: start + i * step, total: 0, counts: emptySevCounts() }))
  alerts.forEach(a => {
    const i = Math.floor((a.seconds - start) / step)
    if (i < 0 || i >= n) return
    bins[i].total += 1
    bins[i].counts[a.priority] += 1
  })
  return { step, bins }
}

/**
 * Activity bins from the server's per-rule counts (`/alerts_stats`), which cover the whole
 * window however many alerts it has. Severity and rule filters can be applied to those
 * counts; for any other filter this returns null and the loaded alerts are used instead.
 */
export const STATS_FIELDS = ['sev', 'rule']
export const statsBins = (stats, focus = []) => {
  if (!stats || !Array.isArray(stats.rules) || focus.some(f => !STATS_FIELDS.includes(f.field))) return null
  const want = Object.fromEntries(focus.map(f => [f.field, f.value]))
  const bins = Array.from({ length: stats.bins }, (_, i) => ({ t: stats.since + i * stats.step, total: 0, counts: emptySevCounts() }))
  let total = 0
  stats.rules.forEach(r => {
    const p = VALID_PRIORITIES.includes(r.priority) ? r.priority : 0
    if ('sev' in want && p !== want.sev) return
    if ('rule' in want && r.rule !== want.rule) return
    r.counts.forEach((n, i) => { if (n && bins[i]) { bins[i].total += n; bins[i].counts[p] += n; total += n } })
  })
  return { step: stats.step, bins, total }
}

/**
 * Rank values of `keyFn` by count, with a per-severity breakdown.
 * Returns { rows: [{ key, total, counts, sample }], other, missing, distinct }.
 */
export const topN = (alerts, keyFn, n = 8) => {
  const map = new Map()
  let missing = 0
  alerts.forEach(a => {
    const k = keyFn(a)
    if (k === null || k === undefined || k === '') { missing += 1; return }
    let row = map.get(k)
    if (!row) { row = { key: k, total: 0, counts: emptySevCounts(), sample: a }; map.set(k, row) }
    row.total += 1
    row.counts[a.priority] += 1
  })
  const all = [...map.values()].sort((a, b) => b.total - a.total || String(a.key).localeCompare(String(b.key)))
  const rows = all.slice(0, n)
  const other = all.slice(n).reduce((s, r) => s + r.total, 0)
  return { rows, other, missing, distinct: all.length }
}

export const distinctCount = (alerts, keyFn) => {
  const s = new Set()
  alerts.forEach(a => { const k = keyFn(a); if (k !== null && k !== undefined) s.add(k) })
  return s.size
}

/** Address scope derived only from the address itself. */
export const addrScope = ip => {
  if (!ip) return null
  const v = ip.toLowerCase()
  if (v === '255.255.255.255') return 'broadcast'
  if (/^2(2[4-9]|3\d)\./.test(v) || v.startsWith('ff')) return 'multicast'
  if (v.startsWith('fe80:') || v.startsWith('169.254.')) return 'link-local'
  if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(v) || /^f[cd]/.test(v)) return 'private'
  if (v.startsWith('127.') || v === '::1') return 'loopback'
  return null
}

// ---------- AppID ----------

const APP_FIELDS = ['service', 'client', 'payload']

/**
 * appid.json has several lines per session as AppID learns more about it.
 * Keep the last known value of each app field per session.
 */
export const appIdSessions = events => {
  if (!Array.isArray(events)) return []
  const sessions = new Map()
  events.forEach((e, i) => {
    if (!e || typeof e !== 'object') return
    const key = e.session_num ?? `#${i}`
    const s = sessions.get(key) || { session: key, service: null, client: null, payload: null, proto: e.proto || null }
    APP_FIELDS.forEach(f => {
      const v = e.apps && e.apps[f]
      if (v) s[f] = v
    })
    sessions.set(key, s)
  })
  return [...sessions.values()]
}

/** Count sessions per value of one AppID field; null = AppID has not decided yet. */
export const appDistribution = (sessions, field, n = 10) => {
  const map = new Map()
  let pending = 0
  sessions.forEach(s => {
    const v = s[field]
    if (!v) { pending += 1; return }
    map.set(v, (map.get(v) || 0) + 1)
  })
  const all = [...map.entries()].map(([key, total]) => ({ key, total })).sort((a, b) => b.total - a.total)
  return {
    rows: all.slice(0, n),
    other: all.slice(n).reduce((s, r) => s + r.total, 0),
    pending,
    sessions: sessions.length,
  }
}
