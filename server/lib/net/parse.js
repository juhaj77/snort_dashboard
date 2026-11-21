// Parsers for the output of network tools. Pure functions, no I/O.
// Every parser skips lines it does not understand instead of failing.
const net = require('net')

/** "1.2.3.4:80", "[::1]:80", "*:53", "127.0.0.53%lo:53", "[fe80::1%eth0]:546" → {ip, port} */
const splitHostPort = s => {
  if (!s) return null
  let host, port
  const b = s.match(/^\[(.*)\](?:%[^:]*)?:(\*|\d+)$/)
  if (b) { host = b[1]; port = b[2] } else {
    const i = s.lastIndexOf(':')
    if (i < 0) return null
    host = s.slice(0, i); port = s.slice(i + 1)
  }
  host = host.replace(/%.*$/, '')
  if (host.startsWith('::ffff:') && net.isIPv4(host.slice(7))) host = host.slice(7)
  if (host === '*') host = '0.0.0.0'
  return { ip: host, port: port === '*' ? null : Number(port) }
}

const UNSPECIFIED = new Set(['0.0.0.0', '::', '*'])
const isUnspecified = ip => UNSPECIFIED.has(ip)

/** `ss -tunapH` (iproute2) */
const parseSs = text => {
  const out = []
  String(text || '').split('\n').forEach(line => {
    const f = line.trim().split(/\s+/)
    if (f.length < 6 || !/^(tcp|udp)$/.test(f[0])) return
    const local = splitHostPort(f[4]), peer = splitHostPort(f[5])
    if (!local || !peer) return
    const users = line.match(/users:\(\("([^"]*)",pid=(\d+)/)
    out.push({
      proto: f[0].toUpperCase(), state: f[1],
      localIp: local.ip, localPort: local.port, remoteIp: peer.ip, remotePort: peer.port,
      pid: users ? Number(users[2]) : null, process: users ? users[1] : null,
    })
  })
  return out
}

/** `netstat -tunapW` (net-tools, Linux) */
const parseNetstatLinux = text => {
  const out = []
  String(text || '').split('\n').forEach(line => {
    const f = line.trim().split(/\s+/)
    if (!/^(tcp|udp)6?$/.test(f[0]) || f.length < 5) return
    const local = splitHostPort(f[3]), peer = splitHostPort(f[4])
    if (!local || !peer) return
    const tcp = f[0].startsWith('tcp')
    const state = tcp ? f[5] : (isUnspecified(peer.ip) ? 'UNCONN' : 'ESTAB')
    const prog = (tcp ? f[6] : f[5]) || ''
    const m = prog.match(/^(\d+)\/(.*)$/)
    out.push({
      proto: tcp ? 'TCP' : 'UDP', state,
      localIp: local.ip, localPort: local.port, remoteIp: peer.ip, remotePort: peer.port,
      pid: m ? Number(m[1]) : null, process: m ? m[2] : null,
    })
  })
  return out
}

/** `netstat -ano` (Windows). State words are localised, so only their position is used. */
const parseNetstatWin = text => {
  const out = []
  String(text || '').split(/\r?\n/).forEach(line => {
    const f = line.trim().split(/\s+/)
    if (!/^(TCP|UDP)$/i.test(f[0])) return
    const local = splitHostPort(f[1]), peer = splitHostPort(f[2])
    if (!local || !peer) return
    const tcp = /^TCP$/i.test(f[0])
    const pid = Number(tcp ? f[4] : f[3])
    out.push({
      proto: tcp ? 'TCP' : 'UDP',
      state: tcp ? f[3] : (isUnspecified(peer.ip) ? 'UNCONN' : 'ESTAB'),
      localIp: local.ip, localPort: local.port, remoteIp: peer.ip, remotePort: peer.port,
      pid: Number.isFinite(pid) ? pid : null, process: null,
    })
  })
  return out
}

/** `tasklist /fo csv /nh` → Map pid → image name */
const parseTasklist = text => {
  const map = new Map()
  String(text || '').split(/\r?\n/).forEach(line => {
    const m = line.match(/^"([^"]*)","(\d+)"/)
    if (m) map.set(Number(m[2]), m[1])
  })
  return map
}

/** `ip -j neigh` */
const parseIpNeighJson = text => {
  let list
  try { list = JSON.parse(text) } catch (e) { return [] }
  if (!Array.isArray(list)) return []
  return list.filter(n => n && net.isIP(n.dst)).map(n => ({
    ip: n.dst, mac: normMac(n.lladdr) || null, iface: n.dev || null,
    state: Array.isArray(n.state) ? n.state.join(' ') : (n.state || null),
  }))
}

const normMac = m => (m ? m.toLowerCase().replace(/-/g, ':') : null)
const BROADCAST_MAC = 'ff:ff:ff:ff:ff:ff'

/** `arp -a` (Windows) and `arp -an` (net-tools) */
const parseArp = text => {
  const out = []
  let iface = null
  String(text || '').split(/\r?\n/).forEach(line => {
    const head = line.match(/^\S.*?:\s*([\d.]+)\s+---/) // "Interface: 192.168.1.217 --- 0xb"
    if (head) { iface = head[1]; return }
    const unix = line.match(/\(([\d.]+)\) at ([0-9a-f:]{11,17})(?: \[\w+\])? on (\S+)/i)
    if (unix) { out.push({ ip: unix[1], mac: normMac(unix[2]), iface: unix[3], state: null }); return }
    const win = line.trim().match(/^([\d.]+)\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})\s+(\S+)/i)
    if (win) out.push({ ip: win[1], mac: normMac(win[2]), iface, state: win[3] })
  })
  // broadcast and multicast entries (01:00:5e… IPv4, 33:33… IPv6) are not devices
  return out.filter(n => n.mac !== BROADCAST_MAC && !/^(01:00:5e|33:33)/.test(n.mac || ''))
}

/**
 * `netsh interface ipv6 show neighbors` (Windows IPv6 neighbour table; `arp -a` is IPv4 only).
 * Headers are localised, so only rows of "address  mac  type" are read. Rows without a MAC
 * (Unreachable) and multicast entries are skipped.
 */
const parseNetshNeighbors = text => {
  const out = [], seen = new Set()
  let iface = null
  String(text || '').split(/\r?\n/).forEach(line => {
    const head = line.match(/^\S.*?\s(\d+):\s*(.+?)\s*$/) // "Interface 17: Ethernet"
    if (head && !line.includes('  ')) { iface = head[2]; return }
    const row = line.trim().match(/^([0-9a-f:.%]+)\s+([0-9a-f]{2}(?:-[0-9a-f]{2}){5})\s*(.*)$/i)
    if (!row) return
    const ip = row[1].replace(/%.*$/, '')
    const mac = normMac(row[2])
    if (!net.isIPv6(ip) || /^ff/i.test(ip) || /^(33:33|00:00:00:00:00:00)/.test(mac) || mac === BROADCAST_MAC) return
    if (seen.has(ip + mac)) return
    seen.add(ip + mac)
    out.push({ ip, mac, iface, state: row[3].trim() || null })
  })
  return out
}

/** `traceroute -n -q 1` / `tracert -d` → [{hop, ip, rtt: [ms...], lost}] */
const parseTrace = text => {
  const hops = []
  String(text || '').split(/\r?\n/).forEach(line => {
    const m = line.match(/^\s*(\d+)\s+(.*)$/)
    if (!m) return
    const hop = Number(m[1]), rest = m[2]
    if (hop < 1 || hop > 64 || !/(ms|\*)/.test(rest)) return
    const rtt = [...rest.matchAll(/<?\s*([\d.]+)\s*ms/g)].map(x => Number(x[1]))
    const ip = rest.split(/\s+/).map(t => t.replace(/^\[|\]$/g, '')).find(t => net.isIP(t)) || null
    const lost = (rest.match(/\*/g) || []).length
    hops.push({ hop, ip, rtt, lost })
  })
  return hops
}

/** `nmap -oG -` → [{ip, name, up, ports: [{port, proto, state, service, version}]}] */
const parseNmapGrepable = text => {
  const hosts = new Map()
  String(text || '').split(/\r?\n/).forEach(line => {
    const m = line.match(/^Host: (\S+) \(([^)]*)\)\s+(.*)$/)
    if (!m) return
    const h = hosts.get(m[1]) || { ip: m[1], name: m[2] || null, up: false, ports: [] }
    hosts.set(m[1], h)
    const rest = m[3]
    if (/Status: Up/.test(rest)) h.up = true
    const pm = rest.match(/Ports: (.*?)(?:\t|$)/)
    if (pm) {
      h.up = true
      pm[1].split(/, (?=\d+\/)/).forEach(p => {
        const [port, state, proto, , service, , version] = p.split('/')
        if (!/^\d+$/.test(port)) return
        h.ports.push({ port: Number(port), state, proto, service: service || null, version: version || null })
      })
    }
  })
  return [...hosts.values()]
}

/** tshark fields: ip.dst ipv6.dst dns.qry.name dns.a dns.aaaa tls SNI → [[ip, name]] */
const parseTsharkNames = line => {
  const [dst4, dst6, qry, a, aaaa, sni] = String(line).replace(/\r$/, '').split('\t')
  const pairs = []
  if (sni) {
    const dst = dst4 || dst6
    if (dst && net.isIP(dst)) pairs.push([dst, sni])
  }
  if (qry) {
    const name = qry.split(',')[0]
    ;[a, aaaa].filter(Boolean).forEach(list =>
      list.split(',').filter(ip => net.isIP(ip)).forEach(ip => pairs.push([ip, name])))
  }
  return pairs
}

// RFC 1918, ULA, link-local, CGNAT: the only targets a port scan is allowed for
const isLocalTarget = ip => {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number)
    if (a === 255 || a >= 224 || a === 0) return false
    return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) ||
      (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127) || a === 127
  }
  if (net.isIPv6(ip)) {
    const v = ip.toLowerCase()
    return /^f[cd]/.test(v) || /^fe[89ab]/.test(v) || v === '::1'
  }
  return false
}

module.exports = {
  splitHostPort, isUnspecified, parseSs, parseNetstatLinux, parseNetstatWin, parseTasklist,
  parseIpNeighJson, parseArp, parseNetshNeighbors, parseTrace, parseNmapGrepable, parseTsharkNames, isLocalTarget,
}
