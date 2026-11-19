// Model for perf_monitor_base.csv rows (as returned by GET /perf: header first).
//
// perf_monitor "base" counters are per-interval: each row holds what happened since
// the previous row. Rows are written when both the time and packet thresholds are
// reached (defaults 60 s and 10,000 packets), so intervals vary and raw numbers are
// not comparable between rows; rates (count / interval) are. The first row's
// interval is unknown (it starts at Snort start-up), so it has no rate.
// A few columns are instantaneous gauges (current flows, memory, ...), not counts.

const GAUGE = /(^|\.)(current_|concurrent_|max_concurrent|bytes_in_use|items_in_use|memory$|max$|max_)/

export const isGauge = name => GAUGE.test(name)

/** Parse header + rows. Malformed rows (wrong width / bad timestamp) are dropped. */
export const parsePerf = lines => {
  const empty = { columns: [], t: [], cols: new Map(), dropped: 0 }
  if (!Array.isArray(lines) || lines.length === 0 || typeof lines[0] !== 'string') return empty
  const columns = lines[0].replace(/^#/, '').split(',')
  if (columns[0] !== 'timestamp') return empty
  const rows = []
  let dropped = 0
  lines.slice(1).forEach(l => {
    const r = typeof l === 'string' ? l.split(',') : []
    const t = Number(r[0])
    if (r.length !== columns.length || !Number.isFinite(t)) { dropped += 1; return }
    rows.push(r.map(v => (v === '' ? null : Number(v))))
  })
  rows.sort((a, b) => a[0] - b[0])
  const cols = new Map()
  columns.forEach((c, i) => {
    if (i === 0) return
    cols.set(c, rows.map(r => (Number.isFinite(r[i]) ? r[i] : null)))
  })
  return { columns, t: rows.map(r => r[0]), cols, dropped }
}

/** Convenience accessors over a parsed model. All return null for missing columns. */
export const perfModel = lines => {
  const p = parsePerf(lines)
  const n = p.t.length
  const get = name => p.cols.get(name) || null
  const has = name => p.cols.has(name)
  const intervals = p.t.map((t, i) => (i === 0 ? null : t - p.t[i - 1]))

  /** per-interval rate (value / seconds * per); null for the first row */
  const rate = (name, per = 1) => {
    const v = get(name)
    if (!v) return null
    return v.map((x, i) => (i === 0 || x === null || !(intervals[i] > 0) ? null : (x * per) / intervals[i]))
  }
  /** sum over the run (counters only) */
  const total = name => {
    const v = get(name)
    return v ? v.reduce((s, x) => s + (x || 0), 0) : null
  }
  const latest = name => {
    const v = get(name)
    if (!v) return null
    for (let i = v.length - 1; i >= 0; i--) if (v[i] !== null) return v[i]
    return null
  }
  const latestOf = arr => {
    if (!arr) return null
    for (let i = arr.length - 1; i >= 0; i--) if (arr[i] !== null) return arr[i]
    return null
  }
  /** a / b per row as a percentage (e.g. dropped / received) */
  const ratio = (a, b) => {
    const va = get(a), vb = get(b)
    if (!va || !vb) return null
    return va.map((x, i) => (vb[i] > 0 && x !== null ? (x / vb[i]) * 100 : null))
  }
  /** columns with any non-zero value */
  const nonZero = () => [...p.cols.entries()].filter(([, v]) => v.some(x => x)).map(([k]) => k)

  return { ...p, n, intervals, get, has, rate, total, latest, latestOf, ratio, nonZero }
}

/** Sum several columns row by row (missing columns are ignored; null if none exist). */
export const sumCols = (model, names) => {
  const present = names.map(n => model.get(n)).filter(Boolean)
  if (present.length === 0) return null
  return model.t.map((_, i) => present.reduce((s, v) => s + (v[i] || 0), 0))
}
