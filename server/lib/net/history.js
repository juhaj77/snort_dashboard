// Per-address history of the Snort alert log and the AppID log over a time window.
//
// The Network view needs, for every address, how many alerts of each priority it had, which
// signatures, when it was first and last seen, and how that changed over time. Fetching the raw
// alerts to the browser does not scale (one hour can be more than 5000 alerts), so the logs are
// read here: backwards from the end, only down to the start of the window, through rotated
// alert files when the window reaches into them. Results are cached for a short time.
//
// Everything is a count of log lines. Nothing is estimated: when the logs do not reach back to
// the start of the window, `coverage` says where they start.
const fs = require('fs')
const path = require('path')
const { eachLineBackwards } = require('../readTail')

const ALERT_FILE = '/var/log/snort/alert_json.txt'
const APPID_FILE = '/var/log/snort/appid.json'
const BINS = 30
const RECENT = 600 // "last 10 minutes" for the rising and new signals
const TOP_SIGS = 8

/** The current alert file followed by its rotated copies (alert_json.txt.<epoch>), newest first. */
const alertFiles = async file => {
  const dir = path.dirname(file), base = path.basename(file)
  let names = []
  try { names = await fs.promises.readdir(dir) } catch (e) { return [] }
  const rotated = names.map(n => n.startsWith(base + '.') && /^\d+$/.test(n.slice(base.length + 1)) ? Number(n.slice(base.length + 1)) : null)
    .filter(n => n !== null).sort((a, b) => b - a).map(n => path.join(dir, `${base}.${n}`))
  return [file, ...rotated]
}

/** Read JSON lines newest first across files until `stop` returns true. Returns files read. */
const readBack = async (files, onEntry) => {
  const used = []
  for (const f of files) {
    let st
    try { st = await fs.promises.stat(f) } catch (e) { continue }
    used.push(path.basename(f))
    let stopped = false
    await eachLineBackwards(f, st.size, 0, line => {
      let e
      try { e = JSON.parse(line) } catch (err) { return true } // half-written / malformed
      if (onEntry(e) === false) { stopped = true; return false }
      return true
    })
    if (stopped) break
  }
  return used
}

// "2026-11-21 04:42:38.973711" (local time, as appid_listener writes it) → epoch seconds
const appidTime = s => {
  if (typeof s !== 'string') return null
  const t = Date.parse(s.replace(' ', 'T').replace(/(\.\d{3})\d+/, '$1'))
  return Number.isFinite(t) ? t / 1000 : null
}

const entryOf = (hosts, ip) => {
  let h = hosts.get(ip)
  if (!h) { h = { alerts: null, appid: null }; hosts.set(ip, h) }
  return h
}

/**
 * @param {number} window seconds
 * @param {{now?: number, alertFile?: string, appidFile?: string}} opts
 */
const history = async (window, opts = {}) => {
  const until = opts.now ?? Date.now() / 1000
  const since = until - window
  const step = window / BINS
  const bin = t => Math.min(BINS - 1, Math.max(0, Math.floor((t - since) / step)))
  const hosts = new Map()

  // --- Snort alerts
  let alertOldest = null, alertTotal = 0, reachedStart = false
  const alertsUsed = await readBack(await alertFiles(opts.alertFile || ALERT_FILE), a => {
    const t = Number(a.seconds)
    if (!Number.isFinite(t)) return true
    if (t < since) { reachedStart = true; return false } // the log is in time order
    if (t > until) return true
    alertOldest = t
    alertTotal += 1
    const p = [1, 2, 3, 4].includes(Number(a.priority)) ? Number(a.priority) : 0
    const msg = a.msg || a.rule || 'unknown'
    for (const ip of new Set([a.src_addr, a.dst_addr].filter(Boolean))) {
      const h = entryOf(hosts, ip)
      const x = h.alerts || (h.alerts = { n: 0, sev: { 0: 0, 1: 0, 2: 0, 3: 0, 4: 0 }, first: t, last: t, recent: 0, bins: new Array(BINS).fill(0), sigs: new Map() })
      x.n += 1; x.sev[p] += 1
      x.first = Math.min(x.first, t); x.last = Math.max(x.last, t)
      if (t >= until - RECENT) x.recent += 1
      x.bins[bin(t)] += 1
      const s = x.sigs.get(msg) || { msg, priority: p, count: 0, last: 0 }
      s.count += 1; s.last = Math.max(s.last, t)
      x.sigs.set(msg, s)
    }
    return true
  })

  // --- AppID sessions
  let appOldest = null, appTotal = 0, appReached = false
  await readBack([opts.appidFile || APPID_FILE], e => {
    const t = appidTime(e.pkt_time)
    if (t === null) return true
    if (t < since) { appReached = true; return false }
    if (t > until) return true
    const c = e.client_info && e.client_info.ip, s = e.service_info && e.service_info.ip
    if (!c || !s) return true
    appOldest = t
    appTotal += 1
    const app = (e.apps && (e.apps.service || e.apps.client || e.apps.payload)) || null
    for (const [ip, role] of [[c, 'client'], [s, 'service']]) {
      const h = entryOf(hosts, ip)
      const x = h.appid || (h.appid = { n: 0, first: t, last: t, recent: 0, bins: new Array(BINS).fill(0), apps: {}, services: {}, names: new Set() })
      x.n += 1
      x.first = Math.min(x.first, t); x.last = Math.max(x.last, t)
      if (t >= until - RECENT) x.recent += 1
      x.bins[bin(t)] += 1
      if (app) x.apps[app] = (x.apps[app] || 0) + 1
      if (role === 'service') {
        // what AppID called the service this address offered, on which port
        const port = e.service_info.port
        if (app && app !== 'unknown' && Number.isInteger(port) && port > 0) {
          const k = `${app}|${port}|${e.proto || ''}`
          x.services[k] = (x.services[k] || 0) + 1
        }
        if (e.tls_host) x.names.add(e.tls_host)
        if (e.http && e.http.host) x.names.add(e.http.host)
      }
    }
    return true
  })

  const out = {}
  hosts.forEach((h, ip) => {
    const o = {}
    if (h.alerts) {
      const { sigs, ...rest } = h.alerts
      o.alerts = { ...rest, sigs: [...sigs.values()].sort((a, b) => (a.priority || 5) - (b.priority || 5) || b.count - a.count).slice(0, TOP_SIGS), sigCount: sigs.size }
    }
    if (h.appid) {
      const { names, services, ...rest } = h.appid
      o.appid = {
        ...rest, names: [...names].slice(0, 8),
        services: Object.entries(services).map(([k, count]) => { const [app, port, proto] = k.split('|'); return { app, port: Number(port), proto, count } }),
      }
    }
    out[ip] = o
  })

  return {
    window, since, until, bins: BINS, step, recent: RECENT,
    coverage: {
      // where the logs start, when that is later than `since` (Snort restarted, log truncated, …)
      alerts: { total: alertTotal, from: reachedStart ? since : alertOldest, files: alertsUsed },
      appid: { total: appTotal, from: appReached ? since : appOldest },
    },
    hosts: out,
  }
}

// short-lived cache, one computation per window at a time
const cache = new Map()
const cachedHistory = (window, ttl) => {
  const now = Date.now()
  const c = cache.get(window)
  if (c && (c.pending || now - c.at < ttl * 1000)) return c.promise
  const promise = history(window).finally(() => { const e = cache.get(window); if (e) e.pending = false })
  cache.set(window, { at: now, promise, pending: true })
  promise.catch(() => cache.delete(window))
  return promise
}

module.exports = { history, cachedHistory, appidTime, alertFiles, BINS }
