// Aggregation and filtering of alert_json.txt, read backwards from the end of the
// file with constant memory, so long windows never have to be sent to the browser.
const fs = require('fs')
const { eachLineBackwards } = require('./readTail')

// Snort appends in time order, but alerts of one packet batch can be a little out of
// order: keep reading until this many consecutive lines are older than `since`.
const OLDER_RUN = 200
const TOP = 3          // top sources / destinations kept per rule and bin
const KEEP_KEYS = 64   // distinct addresses counted per rule and bin before folding

const parse = line => {
  try {
    const a = JSON.parse(line)
    const s = Number(a.seconds)
    return Number.isFinite(s) ? { a, s } : null
  } catch (e) {
    return null // half-written line while Snort is appending
  }
}

const hostOf = ap => {
  if (typeof ap !== 'string') return null
  const i = ap.lastIndexOf(':')
  return i === -1 ? ap : ap.slice(0, i) || null
}

const ruleOf = a => a.rule || (a.gid !== undefined && a.sid !== undefined ? `${a.gid}:${a.sid}:${a.rev ?? '?'}` : null)

/** Visit alerts with since <= seconds <= until, newest first. `visit` returning false stops. */
const scanAlerts = async (file, since, until, visit) => {
  const { size } = await fs.promises.stat(file)
  let older = 0
  await eachLineBackwards(file, size, 0, line => {
    const p = parse(line)
    if (!p) return true
    if (p.s < since) { older += 1; return older < OLDER_RUN }
    older = 0
    if (p.s > until) return true
    return visit(p.a, p.s, line)
  })
}

const bump = (map, key) => {
  if (!key) return
  if (map.has(key)) map.set(key, map.get(key) + 1)
  else if (map.size < KEEP_KEYS) map.set(key, 1)
  else map.set('(other)', (map.get('(other)') || 0) + 1)
}
const top = map => [...map.entries()].sort((x, y) => y[1] - x[1]).slice(0, TOP)

/**
 * Alert counts per rule and time bin over [since, until).
 * Returns { since, until, step, bins, total, rules: [{ rule, msg, priority, cls, total,
 *   counts: number[bins], cells: { [bin]: { src: [[ip, n]], dst: [[ip, n]] } } }] }
 */
const alertStats = async (file, { since, until, step }) => {
  const bins = Math.max(1, Math.ceil((until - since) / step))
  const rules = new Map()
  let total = 0
  await scanAlerts(file, since, until - 1e-6, a => {
    const s = Number(a.seconds)
    const b = Math.min(bins - 1, Math.floor((s - since) / step))
    const key = ruleOf(a) || '(no rule)'
    let r = rules.get(key)
    if (!r) {
      r = { rule: key, msg: a.msg || null, priority: parseInt(a.priority, 10) || 0,
        cls: a.class && a.class !== 'none' ? a.class : null, total: 0,
        counts: new Array(bins).fill(0), cells: new Map() }
      rules.set(key, r)
    }
    r.total += 1
    r.counts[b] += 1
    let c = r.cells.get(b)
    if (!c) r.cells.set(b, c = { src: new Map(), dst: new Map() })
    bump(c.src, a.src_addr || hostOf(a.src_ap))
    bump(c.dst, a.dst_addr || hostOf(a.dst_ap))
    total += 1
    return true
  })
  return {
    since, until, step, bins, total,
    rules: [...rules.values()].map(r => ({
      ...r,
      cells: Object.fromEntries([...r.cells.entries()].map(([b, c]) => [b, { src: top(c.src), dst: top(c.dst) }])),
    })).sort((x, y) => y.total - x.total),
  }
}

/** Alerts in [since, until] (optionally of one rule), newest `cap`, returned oldest first. */
const alertsBetween = async (file, { since, until, rule, cap }) => {
  const out = []
  await scanAlerts(file, since, until, (a, s, line) => {
    if (rule && ruleOf(a) !== rule) return true
    out.push(a)
    return out.length < cap
  })
  return out.reverse()
}

module.exports = { alertStats, alertsBetween, scanAlerts }
