// Builds the connection graph: this machine in the centre, every remote address it talks
// to (or that Snort / AppID saw it talk to) as a node, grouped by process, service or scope.
// Pure functions; inputs are the server's /network/snapshot, normalised alerts and AppID lines.

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

const emptyNode = ip => ({
  ip, scope: scopeOf(ip), conns: [], processes: new Map(), remotePorts: new Map(),
  inbound: 0, outbound: 0, names: new Set(), alerts: [], sev: { 1: 0, 2: 0, 3: 0, 4: 0, 0: 0 },
  maxSev: null, appid: new Map(), appSessions: 0, neighbor: null, gateway: false, discovered: null,
})

/**
 * @param snapshot  /network/snapshot response
 * @param alerts    normalised alerts (overview/aggregate normalizeAlert)
 * @param appid     raw appid.json lines
 * @param opts      { seen: include peers only Snort/AppID saw, lan: include ARP neighbours,
 *                    loopback, discovered: nmap ping-sweep hosts }
 */
export const buildPeers = (snapshot, alerts = [], appid = [], opts = {}) => {
  const local = new Set((snapshot?.host?.addrs || []).map(a => a.ip))
  const isLocal = ip => !ip || local.has(ip) || UNSPEC.has(ip)
  const peers = new Map()
  const get = ip => { if (!peers.has(ip)) peers.set(ip, emptyNode(ip)); return peers.get(ip) }
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

  // the other side of alerts and AppID sessions
  const others = (a, b) => [a, b].filter(ip => ip && !isLocal(ip))
  ;(alerts || []).forEach(a => {
    others(a.srcIp, a.dstIp).forEach(ip => {
      if (!allowed(ip) || scopeOf(ip) === 'multicast') return
      if (!live.has(ip) && !opts.seen) return
      const n = get(ip)
      n.alerts.push(a)
      n.sev[a.priority] = (n.sev[a.priority] || 0) + 1
    })
  })
  ;(appid || []).forEach(e => {
    const c = e && e.client_info && e.client_info.ip, s = e && e.service_info && e.service_info.ip
    if (!c || !s) return
    const ip = isLocal(c) ? s : isLocal(s) ? c : null
    if (!ip || !allowed(ip) || scopeOf(ip) === 'multicast') return
    if (!live.has(ip) && !opts.seen) return
    const n = get(ip)
    n.appSessions += 1
    const app = e.apps && (e.apps.service || e.apps.client || e.apps.payload)
    if (app) add(n.appid, app)
    // TLS SNI and HTTP Host name the server side only
    if (ip === s) { if (e.tls_host) n.names.add(e.tls_host); if (e.http && e.http.host) n.names.add(e.http.host) }
  })

  const neigh = new Map((snapshot?.neighbors || []).map(x => [x.ip, x]))
  if (opts.lan) neigh.forEach((x, ip) => { if (allowed(ip) && scopeOf(ip) !== 'multicast') get(ip) })
  ;(opts.discovered || []).forEach(h => { if (allowed(h.ip)) { const n = get(h.ip); n.discovered = h; if (h.name) n.names.add(h.name) } })

  const wire = snapshot?.names || {}
  const gw = snapshot?.host?.gateway
  peers.forEach(n => {
    n.neighbor = neigh.get(n.ip) || null
    n.gateway = n.ip === gw
    ;(wire[n.ip] || []).forEach(x => n.names.add(x))
    const sevs = [1, 2, 3, 4].filter(p => n.sev[p])
    n.maxSev = sevs.length ? sevs[0] : n.alerts.length ? 0 : null
    n.live = n.conns.length > 0
    n.process = topKey(n.processes) || null
    n.port = topKey(n.remotePorts) ?? null
    n.app = topKey(n.appid) || null
    n.name = [...n.names][0] || (n.discovered && n.discovered.name) || null
    n.weight = n.conns.length + n.alerts.length + Math.min(n.appSessions, 20) / 4
  })
  return [...peers.values()]
}

export const GROUP_BY = [['process', 'Process'], ['service', 'Service'], ['scope', 'Network']]

// hosts without an open connection, by what saw them
const notConnected = n => (n.scope === 'lan' || n.scope === 'link-local' ? 'Local devices'
  : n.alerts.length ? 'Snort alerts, not connected' : 'AppID only, not connected')

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

export const nodeRadius = n => 4 + Math.min(6, Math.log2(1 + n.conns.length + n.alerts.length / 4))

/** Text search over ip, names, process and AppID */
export const matches = (n, q) => {
  const s = q.trim().toLowerCase()
  if (!s) return true
  return n.ip.toLowerCase().includes(s) || [...n.names].some(x => x.toLowerCase().includes(s)) ||
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
    neighbors: (snapshot?.neighbors || []).filter(x => scopeOf(x.ip) !== 'multicast').length,
    alerted: peers.filter(n => n.maxSev !== null).length,
    p1: peers.filter(n => n.maxSev === 1).length,
    processes: new Set(conns.map(c => c.process).filter(Boolean)).size,
  }
}
