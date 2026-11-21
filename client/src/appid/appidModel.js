// Turns raw appid.json lines into per-host statistics for the AppID diagrams.
// Pure functions only, so they can be unit-tested without React.

/** pkt_time "2026-11-21 12:05:16.532221" (local time) -> epoch ms, or NaN. */
export const pktMs = s => (typeof s === 'string' ? new Date(s.replace(' ', 'T')).getTime() : NaN)

const KINDS = ['dns', 'tls', 'other']
export const KIND_LABEL = { dns: 'DNS lookup', tls: 'TLS / HTTPS', other: 'Other' }
export { KINDS }

// Second-level labels under which a country TLD hands out names (bbc.co.uk, yle.com.fi …).
const SLD = new Set(['co', 'com', 'net', 'org', 'gov', 'ac', 'edu', 'ne', 'or', 'go'])
const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/

export const isIp = s => IPV4.test(s) || (typeof s === 'string' && s.includes(':'))

/** "content-autofill.googleapis.com" -> "googleapis.com"; IP addresses -> null. */
export const baseDomain = name => {
  if (!name || isIp(name)) return null
  const parts = name.toLowerCase().replace(/\.$/, '').split('.').filter(Boolean)
  if (parts.length <= 2) return parts.join('.')
  const tld = parts[parts.length - 1]
  const sld = parts[parts.length - 2]
  const n = tld.length === 2 && SLD.has(sld) ? 3 : 2
  return parts.slice(-n).join('.')
}

// Address prefix used to put unnamed addresses next to named ones from the same
// network (IPv4 /24, IPv6 /48).
export const prefixOf = ip => {
  if (!ip) return null
  if (IPV4.test(ip)) return ip.split('.').slice(0, 3).join('.')
  const full = expand6(ip)
  return full ? full.slice(0, 3).join(':') : null
}

const expand6 = ip => {
  if (!ip.includes(':')) return null
  const [head, tail = ''] = ip.toLowerCase().split('%')[0].split('::')
  const h = head ? head.split(':') : []
  const t = ip.includes('::') ? (tail ? tail.split(':') : []) : []
  const fill = ip.includes('::') ? Array(Math.max(0, 8 - h.length - t.length)).fill('0') : []
  return [...h, ...fill, ...t].map(x => x.replace(/^0+(?=.)/, ''))
}

/** Private, link-local, multicast and own-/64 addresses. */
export const isLocalIp = (ip, ownPrefixes = new Set()) => {
  if (!ip) return false
  if (IPV4.test(ip)) {
    const [a, b] = ip.split('.').map(Number)
    return a === 10 || a === 127 || (a === 172 && b >= 16 && b < 32) || (a === 192 && b === 168) ||
      (a === 169 && b === 254) || (a >= 224 && a < 240) || a === 255
  }
  const x = expand6(ip)
  if (!x) return false
  return /^fe[89ab]/.test(x[0]) || /^ff/.test(x[0]) || /^f[cd]/.test(x[0]) ||
    ip === '::1' || ownPrefixes.has(x.slice(0, 4).join(':'))
}

export const LOCAL_GROUP = 'local network'
export const NONAME_GROUP = '(no name)'

/**
 * One record per AppID session (appid logs several lines per session).
 * Names learnt from TLS SNI / HTTP Host are also used for later unnamed sessions
 * to the same address, so bare IPs fold into the host they belong to.
 */
export const toSessions = events => {
  const byKey = new Map()
  for (const e of events) {
    if (!e || !e.session_num || !e.service_info) continue
    const t = pktMs(e.pkt_time)
    if (!Number.isFinite(t)) continue
    const key = e.session_num + '|' + (e.client_info ? e.client_info.port : '')
    let s = byKey.get(key)
    if (!s) {
      s = {
        key, t, last: t, proto: e.proto,
        ip: e.service_info.ip, port: e.service_info.port,
        client: e.client_info && e.client_info.ip,
        name: null, tls: false, dnsName: null,
        service: null, app: null, lines: 0,
      }
      byKey.set(key, s)
    }
    s.lines += 1
    if (t < s.t) s.t = t
    if (t > s.last) s.last = t
    if (e.tls_host || (e.http && e.http.host)) { s.name = e.tls_host || e.http.host; s.tls = !!e.tls_host }
    if (e.dns_host && !s.dnsName) s.dnsName = e.dns_host
    const apps = e.apps || {}
    if (apps.service && apps.service !== 'unknown') s.service = apps.service
    else if (apps.service === 'unknown' && !s.service) s.service = 'unknown'
    const app = apps.client || apps.payload || apps.misc
    if (app) s.app = app
  }
  const sessions = [...byKey.values()].sort((a, b) => a.t - b.t)

  const ipName = new Map()
  for (const s of sessions) {
    s.kind = s.port === 53 ? 'dns' : s.tls || s.port === 443 ? 'tls' : 'other'
    // a DNS session is "about" the name it looked up, not the resolver
    if (s.kind === 'dns') s.name = s.dnsName || s.name
    else if (!s.name) s.name = s.dnsName
    if (s.kind !== 'dns') {
      if (s.name) ipName.set(s.ip, s.name)
      else if (ipName.has(s.ip)) { s.name = ipName.get(s.ip); s.inferred = true }
    }
    s.host = s.name || s.ip
    // DNS sessions whose query name AppID did not log: one bucket per resolver
    if (s.kind === 'dns' && !s.name) { s.host = 'DNS via ' + s.ip; s.unnamedDns = true }
  }
  // second pass: sessions seen before the name was learnt
  for (const s of sessions) {
    if (s.kind !== 'dns' && !s.name && ipName.has(s.ip)) {
      s.name = ipName.get(s.ip); s.inferred = true; s.host = s.name
    }
  }
  // group: base domain of the name; unnamed addresses join the domain seen on the
  // same network prefix, local addresses form their own group
  const own = new Set(sessions.map(s => s.client && expand6(s.client)).filter(Boolean).map(x => x.slice(0, 4).join(':')))
  const prefixGroup = new Map()
  for (const s of sessions) {
    if (s.kind !== 'dns' && s.name) prefixGroup.set(prefixOf(s.ip), baseDomain(s.name))
  }
  for (const s of sessions) {
    s.group = baseDomain(s.name) ||
      (isLocalIp(s.ip, own) ? LOCAL_GROUP : prefixGroup.get(prefixOf(s.ip)) || NONAME_GROUP)
    if (!s.name && s.group !== LOCAL_GROUP && s.group !== NONAME_GROUP) s.groupGuessed = true
  }
  return sessions
}

/** Start times closer than `gap` ms (A + AAAA lookups, parallel connections) count as one burst. */
const bursts = (times, gap = 1500) => {
  const out = []
  for (const t of times) if (!out.length || t - out[out.length - 1] > gap) out.push(t)
  return out
}

/**
 * Detect a steady rhythm (polling, keep-alives, beacons): at least 6 bursts and
 * 70 % of the gaps within ±25 % of the median gap. Returns the period in ms or null.
 */
export const regularity = times => {
  const b = bursts([...times].sort((x, y) => x - y))
  if (b.length < 6) return null
  const gaps = b.slice(1).map((t, i) => t - b[i]).sort((x, y) => x - y)
  const median = gaps[Math.floor(gaps.length / 2)]
  if (median < 2000) return null
  const close = gaps.filter(g => Math.abs(g - median) <= median * 0.25).length
  return close / gaps.length >= 0.7 ? median : null
}

/** Per-host aggregate over sessions in [from, to]. Sorted by session count, most first. */
export const hostStats = (sessions, from = -Infinity, to = Infinity) => {
  const hosts = new Map()
  for (const s of sessions) {
    if (s.t < from || s.t > to) continue
    let h = hosts.get(s.host)
    if (!h) {
      h = {
        host: s.host, named: !!s.name, unnamedDns: !!s.unnamedDns, inferred: !!s.inferred, group: s.group, groupGuessed: !!s.groupGuessed,
        count: 0, kinds: { dns: 0, tls: 0, other: 0 }, times: [], sessionKinds: [], ips: new Set(),
        ports: new Set(), services: new Set(), first: s.t, last: s.t,
      }
      hosts.set(s.host, h)
    }
    h.count += 1
    h.kinds[s.kind] += 1
    h.times.push(s.t)
    h.sessionKinds.push(s.kind)
    if (s.kind !== 'dns') h.ips.add(s.ip)
    h.ports.add(s.proto + ' ' + s.port)
    if (s.service) h.services.add(s.service)
    if (s.app) h.services.add(s.app)
    if (s.t < h.first) h.first = s.t
    if (s.t > h.last) h.last = s.t
  }
  const list = [...hosts.values()]
  for (const h of list) {
    h.kind = KINDS.reduce((a, k) => (h.kinds[k] > h.kinds[a] ? k : a), 'dns')
    h.period = regularity(h.times)
  }
  return list.sort((a, b) => b.count - a.count || a.host.localeCompare(b.host))
}

/** Hosts grouped by base domain, biggest group first. */
export const groupHosts = hosts => {
  const groups = new Map()
  for (const h of hosts) {
    let g = groups.get(h.group)
    if (!g) groups.set(h.group, g = { group: h.group, count: 0, hosts: [] })
    g.count += h.count
    g.hosts.push(h)
  }
  return [...groups.values()].sort((a, b) => b.count - a.count || a.group.localeCompare(b.group))
}

/**
 * Greedy circle packing: circles (biggest first) are placed at the first free spot
 * on a spiral around the origin. Mutates and returns items with x, y; also returns
 * the radius of the enclosing circle.
 */
export const packCircles = (items, pad = 2) => {
  const placed = []
  for (const c of items) {
    if (!placed.length) { c.x = 0; c.y = 0; placed.push(c); continue }
    const step = Math.max(1, c.r / 3)
    for (let a = 0, rr = 0; ; a += 0.35, rr = step * a / (2 * Math.PI) * 2) {
      const x = rr * Math.cos(a)
      const y = rr * Math.sin(a) * 0.8 // slightly flattened: screens are wider than tall
      if (placed.every(p => Math.hypot(p.x - x, p.y - y) >= p.r + c.r + pad)) {
        c.x = x; c.y = y; placed.push(c); break
      }
    }
  }
  // re-centre on the bounding box
  if (placed.length) {
    const minX = Math.min(...placed.map(p => p.x - p.r)), maxX = Math.max(...placed.map(p => p.x + p.r))
    const minY = Math.min(...placed.map(p => p.y - p.r)), maxY = Math.max(...placed.map(p => p.y + p.r))
    const cx = (minX + maxX) / 2, cy = (minY + maxY) / 2
    for (const p of placed) { p.x -= cx; p.y -= cy }
  }
  const radius = placed.reduce((m, p) => Math.max(m, Math.hypot(p.x, p.y) + p.r), 0)
  const width = placed.length ? Math.max(...placed.map(p => p.x + p.r)) * 2 : 0
  const height = placed.length ? Math.max(...placed.map(p => p.y + p.r)) * 2 : 0
  return { items: placed, radius, width, height }
}

/** "~30 s", "~2 min", "~1.5 h" */
export const fmtPeriod = ms => {
  const s = ms / 1000
  if (s < 90) return `~${Math.round(s)} s`
  if (s < 5400) return `~${+(s / 60).toFixed(s < 600 ? 1 : 0)} min`
  return `~${+(s / 3600).toFixed(1)} h`
}
