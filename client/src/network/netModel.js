// Builds the connection graph: this machine in the centre, every remote address it talks
// to (or that Snort / AppID saw it talk to) as a node, grouped by process, service or scope.
// Pure functions; inputs are the server's /network/snapshot and /network/history.

export const PORT_NAMES = {
  20: 'FTP data', 21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS', 67: 'DHCP', 68: 'DHCP',
  80: 'HTTP', 110: 'POP3', 123: 'NTP', 137: 'NetBIOS', 138: 'NetBIOS', 139: 'NetBIOS', 143: 'IMAP',
  161: 'SNMP', 389: 'LDAP', 443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 587: 'SMTP', 636: 'LDAPS',
  853: 'DNS over TLS', 993: 'IMAPS', 995: 'POP3S', 1883: 'MQTT', 1900: 'SSDP', 3389: 'RDP', 3478: 'STUN',
  5222: 'XMPP', 5228: 'Google push', 5353: 'mDNS', 5355: 'LLMNR', 8080: 'HTTP alt', 8443: 'HTTPS alt', 8883: 'MQTT TLS',
}
export const portLabel = p => (p === null || p === undefined ? '—' : PORT_NAMES[p] ? `${p} ${PORT_NAMES[p]}` : String(p))

const UNSPEC = new Set(['0.0.0.0', '::', '*'])

export const scopeOf = ip => {
  if (!ip) return 'unknown'
  const v = ip.toLowerCase()
  if (v.startsWith('127.') || v === '::1') return 'loopback'
  if (v === '255.255.255.255' || /^2(2[4-9]|3\d)\./.test(v) || v.startsWith('ff')) return 'multicast'
  if (v.startsWith('169.254.') || /^fe[89ab]/.test(v)) return 'link-local'
  if (/^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(v) || /^f[cd]/.test(v)) return 'lan'
  if (/^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(v)) return 'lan' // CGNAT / Tailscale
  return 'internet'
}
export const SCOPE_LABEL = { lan: 'Local network', 'link-local': 'Link-local', internet: 'Internet', multicast: 'Multicast / broadcast', loopback: 'This machine (loopback)', unknown: 'Unknown' }

const add = (map, key, n = 1) => map.set(key, (map.get(key) || 0) + n)
const topKey = map => [...map.entries()].sort((a, b) => b[1] - a[1] || String(a[0]).localeCompare(String(b[0])))[0]?.[0]

// ---------------------------------------------------------------------------
// IPv6 helpers

/** "2001:db8::1" → [0x2001, 0xdb8, 0, 0, 0, 0, 0, 1]; null for anything else */
export const expand6 = ip => {
  if (!ip || !ip.includes(':') || ip.includes('.')) return null
  const v = ip.replace(/%.*$/, '').toLowerCase()
  const halves = v.split('::')
  if (halves.length > 2) return null
  const part = h => (h ? h.split(':') : [])
  const head = part(halves[0]), tail = part(halves[1])
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0
  if (fill < 0 || (halves.length === 1 && head.length !== 8)) return null
  const groups = [...head, ...Array(fill).fill('0'), ...tail]
  if (groups.length !== 8 || groups.some(g => !/^[0-9a-f]{1,4}$/.test(g))) return null
  return groups.map(g => parseInt(g, 16))
}
const prefix64 = ip => { const g = expand6(ip); return g ? g.slice(0, 4).join(':') : null }

/** MAC address embedded in an EUI-64 interface id (…:xxff:fexx:…), or null */
export const eui64Mac = ip => {
  const g = expand6(ip)
  if (!g) return null
  const b = g.slice(4).flatMap(x => [x >> 8, x & 255])
  if (b[3] !== 0xff || b[4] !== 0xfe) return null
  return [b[0] ^ 2, b[1], b[2], b[5], b[6], b[7]].map(x => x.toString(16).padStart(2, '0')).join(':')
}

const SCOPE_RANK = { lan: 4, 'link-local': 3, internet: 2, loopback: 1 }
// which address names a device: IPv4 first, then global IPv6, then link-local
const addrRank = (ip, scope) => (!ip.includes(':') ? 0 : scope === 'link-local' ? 2 : 1)

const emptyNode = (ip, scope) => ({
  ip, addrs: new Set([ip]), scope, conns: [], processes: new Map(), remotePorts: new Map(),
  inbound: 0, outbound: 0, names: new Set(),
  alertCount: 0, sev: { 1: 0, 2: 0, 3: 0, 4: 0, 0: 0 }, sigs: [], sigCount: 0, alertHist: null,
  maxSev: null, appid: new Map(), appSessions: 0, appHist: null, services: [],
  neighbor: null, gateway: false, discovered: null, signals: [],
})

const addBins = (a, b) => (a || []).map((x, i) => x + ((b || [])[i] || 0))
// one device can have several addresses: add up what the logs say about each of them
const mergeAlerts = (a, b) => {
  if (!a) return b
  const sigs = new Map(a.sigs.map(x => [x.msg, { ...x }]))
  b.sigs.forEach(x => { const y = sigs.get(x.msg); if (y) { y.count += x.count; y.last = Math.max(y.last, x.last) } else sigs.set(x.msg, { ...x }) })
  const sev = { ...a.sev }
  Object.entries(b.sev || {}).forEach(([k, v]) => { sev[k] = (sev[k] || 0) + v })
  return {
    n: a.n + b.n, sev, first: Math.min(a.first, b.first), last: Math.max(a.last, b.last), recent: a.recent + b.recent,
    bins: addBins(a.bins, b.bins), sigs: [...sigs.values()].sort((x, y) => (x.priority || 5) - (y.priority || 5) || y.count - x.count),
    sigCount: Math.max(a.sigCount || 0, b.sigCount || 0, sigs.size),
  }
}
const mergeAppid = (a, b) => {
  if (!a) return b
  const apps = { ...a.apps }
  Object.entries(b.apps || {}).forEach(([k, v]) => { apps[k] = (apps[k] || 0) + v })
  return {
    n: a.n + b.n, first: Math.min(a.first, b.first), last: Math.max(a.last, b.last), recent: a.recent + b.recent,
    bins: addBins(a.bins, b.bins), apps, names: [...new Set([...(a.names || []), ...(b.names || [])])],
    services: [...(a.services || []), ...(b.services || [])],
  }
}

/**
 * @param snapshot  /network/snapshot response
 * @param hist      /network/history response: per-address alert and AppID counts for the window
 * @param opts      { seen: include peers only Snort/AppID saw, lan: include ARP neighbours,
 *                    loopback, discovered: nmap ping-sweep hosts }
 *
 * Addresses of one device (same MAC in the neighbour table, or a MAC embedded in an IPv6
 * EUI-64 address) become one node, named by its IPv4 address when it has one. IPv6 addresses
 * in the same /64 as one of this machine's addresses are on the local network.
 */
export const buildPeers = (snapshot, hist = null, opts = {}) => {
  const hostAddrs = (snapshot?.host?.addrs || []).map(a => a.ip)
  const local = new Set(hostAddrs)
  const isLocal = ip => !ip || local.has(ip) || UNSPEC.has(ip)
  const prefixes = new Set(hostAddrs.filter(ip => scopeOf(ip) === 'internet').map(prefix64).filter(Boolean))
  const scopeAt = ip => { const s = scopeOf(ip); return s === 'internet' && prefixes.has(prefix64(ip)) ? 'lan' : s }

  // device = MAC address; its addresses come from the neighbour tables and EUI-64 addresses
  const neighbors = (snapshot?.neighbors || []).filter(x => scopeOf(x.ip) !== 'multicast')
  const macOf = new Map()
  neighbors.forEach(x => { if (x.mac) macOf.set(x.ip, x.mac.toLowerCase()) })
  const macFor = ip => {
    if (macOf.has(ip)) return macOf.get(ip)
    const s = scopeAt(ip)
    return s === 'lan' || s === 'link-local' ? eui64Mac(ip) : null
  }
  const seenIps = new Set([
    ...(snapshot?.connections || []).map(c => c.remoteIp), ...Object.keys((hist && hist.hosts) || {}),
    ...neighbors.map(x => x.ip), ...(opts.discovered || []).map(h => h.ip),
  ].filter(ip => ip && !isLocal(ip)))
  const primary = new Map() // mac → address that names the device
  seenIps.forEach(ip => {
    const mac = macFor(ip)
    if (!mac) return
    const cur = primary.get(mac)
    const rank = x => addrRank(x, scopeAt(x))
    if (!cur || rank(ip) < rank(cur) || (rank(ip) === rank(cur) && ip.localeCompare(cur) < 0)) primary.set(mac, ip)
  })
  const canon = ip => { const mac = macFor(ip); return (mac && primary.get(mac)) || ip }

  const peers = new Map()
  const get = ip => {
    const key = canon(ip)
    if (!peers.has(key)) peers.set(key, emptyNode(key, scopeAt(key)))
    const n = peers.get(key)
    n.addrs.add(ip)
    return n
  }
  const allowed = ip => {
    if (UNSPEC.has(ip)) return false
    const s = scopeOf(ip)
    if (s === 'loopback' || local.has(ip)) return !!opts.loopback
    return true
  }

  ;(snapshot?.connections || []).forEach(c => {
    const ip = local.has(c.remoteIp) ? '127.0.0.1' : c.remoteIp
    if (!allowed(ip) && !(opts.loopback && ip === '127.0.0.1')) return
    const n = get(ip)
    n.conns.push(c)
    if (c.process) add(n.processes, c.process)
    if (c.direction === 'in') n.inbound += 1
    else { n.outbound += 1; add(n.remotePorts, c.remotePort) }
  })
  const live = new Set(peers.keys())

  // what Snort and AppID logged about each other address during the window
  Object.entries((hist && hist.hosts) || {}).forEach(([ip, h]) => {
    if (isLocal(ip) || !allowed(ip) || scopeOf(ip) === 'multicast') return
    if (!live.has(canon(ip)) && !opts.seen) return
    if (!h || (!h.alerts && !h.appid)) return
    const n = get(ip)
    if (h.alerts) n.alertHist = mergeAlerts(n.alertHist, h.alerts)
    if (h.appid) n.appHist = mergeAppid(n.appHist, h.appid)
  })

  const neigh = new Map(neighbors.map(x => [x.ip, x]))
  if (opts.lan) neigh.forEach((x, ip) => { if (allowed(ip)) get(ip) })
  ;(opts.discovered || []).forEach(h => { if (allowed(h.ip)) { const n = get(h.ip); n.discovered = h; if (h.name) n.names.add(h.name) } })

  const wire = snapshot?.names || {}
  const gw = snapshot?.host?.gateway
  peers.forEach(n => {
    const addrs = [...n.addrs].sort((a, b) => addrRank(a, scopeAt(a)) - addrRank(b, scopeAt(b)) || a.localeCompare(b))
    n.addrs = addrs
    n.scope = addrs.map(scopeAt).sort((a, b) => (SCOPE_RANK[b] || 0) - (SCOPE_RANK[a] || 0))[0] || n.scope
    if (n.addrs.length > 1 && n.scope === 'link-local') n.scope = 'lan'
    n.neighbor = addrs.map(ip => neigh.get(ip)).find(Boolean) || (macFor(n.ip) ? { mac: macFor(n.ip), state: 'from the IPv6 address' } : null)
    n.gateway = !!gw && addrs.includes(gw)
    if (n.alertHist) {
      n.alertCount = n.alertHist.n || 0
      n.sev = { 0: 0, 1: 0, 2: 0, 3: 0, 4: 0, ...n.alertHist.sev }
      n.sigs = n.alertHist.sigs || []
      n.sigCount = n.alertHist.sigCount || n.sigs.length
    }
    if (n.appHist) {
      n.appSessions = n.appHist.n || 0
      Object.entries(n.appHist.apps || {}).forEach(([k, v]) => { if (k !== 'unknown') add(n.appid, k, v) })
      ;(n.appHist.names || []).forEach(x => n.names.add(x))
      n.services = n.appHist.services || []
    }
    // names: TLS SNI / HTTP Host first, then what tshark saw on the wire
    addrs.forEach(ip => (wire[ip] || []).forEach(x => n.names.add(x)))
    const sevs = [1, 2, 3, 4].filter(p => n.sev[p])
    n.maxSev = sevs.length ? sevs[0] : n.alertCount ? 0 : null
    n.live = n.conns.length > 0
    n.process = topKey(n.processes) || null
    n.port = topKey(n.remotePorts) ?? null
    n.app = topKey(n.appid) || null
    n.name = [...n.names][0] || (n.discovered && n.discovered.name) || null
    const seen = [n.alertHist, n.appHist].filter(Boolean)
    n.firstSeen = seen.length ? Math.min(...seen.map(x => x.first)) : null
    n.lastSeen = seen.length ? Math.max(...seen.map(x => x.last)) : null
    n.weight = n.conns.length + Math.min(n.alertCount, 200) / 2 + Math.min(n.appSessions, 20) / 4
    n.signals = signalsOf(n, hist)
  })
  return [...peers.values()]
}

// ---------------------------------------------------------------------------
// Signals: why a host may need a look. Each is a plain rule over counts from the logs and the
// connection snapshot, shown with its reason. There is deliberately no combined score.

export const LEVELS = { high: 3, warn: 2, info: 1 }

// ports where AppID's service name is expected; anything else is reported as unexpected
const EXPECTED_PORTS = {
  http: [80, 8080, 8000, 8008, 8081, 8888, 3128], ssh: [22], dns: [53, 5353], ftp: [21], telnet: [23],
  smtp: [25, 465, 587], rdp: [3389], smb: [445, 139], netbios: [137, 138, 139], ntp: [123], imap: [143, 993],
  pop3: [110, 995], ldap: [389, 636], snmp: [161, 162], mysql: [3306], postgresql: [5432], vnc: [5900, 5901],
}
// remote ports that are common for outbound traffic but missing from PORT_NAMES
const COMMON_OUT = new Set([1194, 3479, 3480, 3481, 4070, 5223, 19302, 19305, 51820, 4500, 500])

export const RULES = [
  ['P1 / P2 alerts', 'Snort raised priority 1 (high) or 2 (medium) alerts involving the address in the window.'],
  ['Alerts rising', 'At least 5 alerts in the last 10 minutes and at least 3 times the rate of the rest of the window (needs 20 min of earlier log).'],
  ['Inbound from the internet', 'An open TCP connection that a public address made to a listening port of this machine.'],
  ['Service on unexpected port', 'AppID named a service (HTTP, SSH, DNS, …) on a port that service does not normally use.'],
  ['New', 'First appeared in the logs in the last 10 minutes, after at least 30 minutes of log without it.'],
  ['Uncommon remote port', 'An open outbound connection to a public address on a port that is not a well-known service port.'],
]

const plural = (n, w) => `${n.toLocaleString('en-US')} ${w}${n === 1 ? '' : 's'}`

export const signalsOf = (n, hist) => {
  const out = []
  const a = n.alertHist
  if (a) {
    const top = p => n.sigs.find(s => s.priority === p)
    if (n.sev[1]) out.push({ id: 'p1', level: 'high', label: 'P1 alerts', detail: `${plural(n.sev[1], 'alert')}${top(1) ? ` · ${top(1).msg}` : ''}` })
    if (n.sev[2]) out.push({ id: 'p2', level: 'warn', label: 'P2 alerts', detail: `${plural(n.sev[2], 'alert')}${top(2) ? ` · ${top(2).msg}` : ''}` })
    // rate in the last 10 minutes vs the rest of the window the alert log covers
    const recentWin = hist?.recent || 600
    const logFrom = hist?.coverage?.alerts?.from ?? hist?.since
    const earlierSpan = hist && logFrom !== null && logFrom !== undefined ? hist.until - recentWin - logFrom : 0
    if (a.recent >= 5 && earlierSpan >= 1200) {
      const before = ((a.n - a.recent) / earlierSpan) * recentWin // per 10 min
      if (a.recent >= 3 * before) {
        out.push({ id: 'rising', level: 'warn', label: 'Alerts rising', detail: `${plural(a.recent, 'alert')} in the last 10 min, ${before < 1 ? 'under 1' : '≈ ' + Math.round(before)} per 10 min before` })
      }
    }
  }
  // TCP only: every bound UDP socket looks like a listener, so UDP direction is a guess
  const tcpIn = n.conns.filter(c => c.direction === 'in' && /^tcp/i.test(c.proto || ''))
  if (tcpIn.length && n.scope === 'internet') {
    const ports = [...new Set(tcpIn.map(c => c.localPort))].slice(0, 3).join(', ')
    out.push({ id: 'inbound', level: 'warn', label: 'Inbound from the internet', detail: `${plural(tcpIn.length, 'TCP connection')} to local port ${ports}${n.process ? ` (${n.process})` : ''}` })
  }
  const odd = n.services.filter(s => { const exp = EXPECTED_PORTS[String(s.app).toLowerCase()]; return exp && !exp.includes(s.port) })
  if (odd.length) {
    out.push({ id: 'mismatch', level: 'warn', label: 'Service on unexpected port', detail: odd.slice(0, 3).map(s => `${s.app} on ${s.port}/${s.proto || '?'}`).join(', ') + ' (AppID)' })
  }
  if (hist && n.firstSeen !== null) {
    const recentWin = hist.recent || 600
    const froms = [hist.coverage?.alerts?.from, hist.coverage?.appid?.from].filter(x => x !== null && x !== undefined)
    const logFrom = froms.length ? Math.min(...froms) : hist.since
    if (n.firstSeen >= hist.until - recentWin && n.firstSeen - logFrom >= 1800) {
      out.push({ id: 'new', level: 'info', label: 'New', detail: `first in the logs at ${clock(n.firstSeen)}` })
    }
  }
  if (n.scope === 'internet' && n.outbound > 0) {
    const ports = [...n.remotePorts.keys()].filter(p => p !== null && p !== undefined && !PORT_NAMES[p] && !COMMON_OUT.has(p))
    if (ports.length) out.push({ id: 'port', level: 'info', label: 'Uncommon remote port', detail: `outbound to port ${ports.slice(0, 4).join(', ')}` })
  }
  return out
}

const clock = s => new Date(s * 1000).toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' })

export const topLevel = n => Math.max(0, ...n.signals.map(s => LEVELS[s.level]))
export const attentionCount = n => n.signals.filter(s => s.level !== 'info').length

/** Hosts with signals: most serious first, then the number of signals, then alert volume. */
export const attention = peers => peers.filter(n => n.signals.length)
  .sort((a, b) => topLevel(b) - topLevel(a) || attentionCount(b) - attentionCount(a) ||
    b.signals.length - a.signals.length || b.alertCount - a.alertCount || a.ip.localeCompare(b.ip))

export const GROUP_BY = [['process', 'Process'], ['service', 'Service'], ['scope', 'Network']]

// hosts without an open connection, by what saw them
const notConnected = n => (n.scope === 'lan' || n.scope === 'link-local' ? 'Local devices'
  : n.alertCount ? 'Snort alerts, not connected' : 'AppID only, not connected')

export const groupKey = (n, by) => {
  if (by === 'scope') return SCOPE_LABEL[n.scope] || n.scope
  if (by === 'service') {
    if (n.live && n.outbound) return PORT_NAMES[n.port] || `port ${n.port}`
    if (n.live && n.inbound) return 'Inbound'
    if (n.app) return n.app
    return notConnected(n)
  }
  if (n.process) return n.process
  if (n.live) return 'unknown process'
  return notConnected(n)
}

/**
 * Radial layout: groups get angular sectors (by size), a hub on the inner ring and their
 * nodes fanned out in rows behind the hub. Deterministic, so nodes don't jump on refresh.
 */
export const layout = (peers, by, { hubR = 150, firstR = 245, rowGap = 26, spacing = 20 } = {}) => {
  const groups = new Map()
  peers.forEach(n => { const k = groupKey(n, by); if (!groups.has(k)) groups.set(k, []); groups.get(k).push(n) })
  const list = [...groups.entries()].map(([key, nodes]) => ({
    key, nodes: nodes.sort((a, b) => (a.maxSev === null) - (b.maxSev === null) || b.weight - a.weight || a.ip.localeCompare(b.ip)),
  })).sort((a, b) => b.nodes.length - a.nodes.length || a.key.localeCompare(b.key))
  const total = list.reduce((s, g) => s + Math.sqrt(g.nodes.length) + 1.2, 0) || 1
  let angle = -Math.PI / 2
  const hubs = [], nodes = []
  let maxR = firstR
  list.forEach(g => {
    const span = (2 * Math.PI * (Math.sqrt(g.nodes.length) + 1.2)) / total
    const mid = angle + span / 2
    hubs.push({ key: g.key, count: g.nodes.length, x: Math.cos(mid) * hubR, y: Math.sin(mid) * hubR, a: mid, alerts: g.nodes.filter(n => n.maxSev !== null).length })
    // fill rows outward; each row holds as many as fit in the sector at that radius
    const usable = Math.max(span * 0.82, 0.05)
    for (let i = 0, r = firstR; i < g.nodes.length; r += rowGap) {
      const radius = r
      const cap = Math.max(1, Math.floor((usable * radius) / spacing))
      const row = g.nodes.slice(i, i + cap)
      for (let j = 0; j < row.length; j++) {
        const a = mid - usable / 2 + usable * (row.length === 1 ? 0.5 : j / (row.length - 1))
        nodes.push({ n: row[j], hub: g.key, x: Math.cos(a) * radius, y: Math.sin(a) * radius, a })
      }
      maxR = Math.max(maxR, radius)
      i += cap
    }
    angle += span
  })
  // bounding box (with room for labels) so the view can be fitted to the canvas
  const xs = [0, ...nodes.map(p => p.x), ...hubs.map(h => h.x)], ys = [0, ...nodes.map(p => p.y), ...hubs.map(h => h.y)]
  const box = { x0: Math.min(...xs) - 90, x1: Math.max(...xs) + 90, y0: Math.min(...ys) - 40, y1: Math.max(...ys) + 40 }
  return { hubs, nodes, radius: maxR + 60, box }
}

export const nodeColor = n =>
  n.maxSev !== null ? `var(--p${n.maxSev})`
    : n.scope === 'lan' || n.scope === 'link-local' ? 'var(--blue)'
      : n.scope === 'loopback' ? 'var(--muted)' : 'var(--teal)'

export const nodeRadius = n => 4 + Math.min(6, Math.log2(1 + n.conns.length + Math.min(n.alertCount, 400) / 4))

/** Text search over ip, names, process and AppID */
export const matches = (n, q) => {
  const s = q.trim().toLowerCase()
  if (!s) return true
  return (n.addrs || [n.ip]).some(a => a.toLowerCase().includes(s)) || [...n.names].some(x => x.toLowerCase().includes(s)) ||
    [...n.processes.keys()].some(x => x.toLowerCase().includes(s)) || [...n.appid.keys()].some(x => x.toLowerCase().includes(s))
}

export const summary = (snapshot, peers) => {
  const live = peers.filter(n => n.live)
  const conns = snapshot?.connections || []
  return {
    hosts: live.length,
    lanHosts: live.filter(n => n.scope === 'lan' || n.scope === 'link-local').length,
    netHosts: live.filter(n => n.scope === 'internet').length,
    connections: conns.length,
    inbound: conns.filter(c => c.direction === 'in').length,
    outbound: conns.filter(c => c.direction === 'out').length,
    listening: new Set((snapshot?.listening || []).map(l => `${l.proto}|${l.port}`)).size,
    // devices, not addresses: IPv4 and IPv6 entries of one MAC count once
    neighbors: new Set((snapshot?.neighbors || []).filter(x => scopeOf(x.ip) !== 'multicast').map(x => x.mac || x.ip)).size,
    alerted: peers.filter(n => n.maxSev !== null).length,
    p1: peers.filter(n => n.maxSev === 1).length,
    processes: new Set(conns.map(c => c.process).filter(Boolean)).size,
    attention: peers.filter(n => attentionCount(n) > 0).length,
    attentionHigh: peers.filter(n => topLevel(n) === 3).length,
  }
}
