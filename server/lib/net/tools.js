// Finds and runs network tools on Linux, on Windows, and on Windows from WSL (interop).
// Only fixed argument lists are passed to execFile (no shell), targets are validated by
// the caller with net.isIP.
const fs = require('fs')
const os = require('os')
const path = require('path')
const dns = require('dns').promises
const { execFile, spawn } = require('child_process')
const P = require('./parse')

const IS_WIN = process.platform === 'win32'
const IS_WSL = !IS_WIN && (fs.existsSync('/proc/sys/fs/binfmt_misc/WSLInterop') || /microsoft/i.test(os.release()))
const WIN_SYS = IS_WIN ? (process.env.SystemRoot || 'C:\\Windows') + '\\System32' : '/mnt/c/Windows/System32'
const WIN_PROGRAMS = IS_WIN
  ? [process.env.ProgramFiles || 'C:\\Program Files', process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)']
  : ['/mnt/c/Program Files', '/mnt/c/Program Files (x86)']

// WSL prints this when it cannot start a Windows program (interop broken until `wsl --shutdown`)
const INTEROP_FAIL = /UtilAcceptVsock|accept4 failed/i
const INTEROP_HINT = 'WSL could not start Windows programs (interop error). Run `wsl --shutdown` in Windows and start WSL again.'

const exists = p => { try { fs.accessSync(p, fs.constants.X_OK); return true } catch (e) { return false } }

/** Binary on PATH (Linux side) or null */
const which = name => {
  if (IS_WIN) return null
  for (const dir of (process.env.PATH || '').split(':').concat(['/usr/sbin', '/sbin', '/usr/bin'])) {
    const p = path.join(dir, name)
    if (dir && exists(p)) return p
  }
  return null
}
/** Windows binary in System32 (works natively and from WSL) */
const winSys = name => {
  const join = IS_WIN ? path.win32.join : path.posix.join
  for (const n of [name.toUpperCase() + '.EXE', name.toLowerCase() + '.exe']) {
    const p = join(WIN_SYS, n)
    if (exists(p)) return p
  }
  return null
}
const winProgram = rel => {
  for (const base of WIN_PROGRAMS) {
    const p = IS_WIN ? path.win32.join(base, rel) : path.posix.join(base, rel.replace(/\\/g, '/'))
    if (exists(p)) return p
  }
  return null
}

const run = (file, args, timeout = 15000) => new Promise(resolve => {
  execFile(file, args, { timeout, maxBuffer: 16 * 1024 * 1024, windowsHide: true },
    (err, stdout, stderr) => resolve({ err, stdout: String(stdout || ''), stderr: String(stderr || '') }))
})

/** Which tools exist, per side. Re-checked on every call (cheap) so installs show up without restart. */
const tools = () => {
  const t = {
    linux: IS_WIN ? null : {
      ss: which('ss'), netstat: which('netstat'), ip: which('ip'), arp: which('arp'),
      traceroute: which('traceroute'), nmap: which('nmap'), tshark: which('tshark'), whois: which('whois'),
    },
    windows: (IS_WIN || IS_WSL) ? {
      netstat: winSys('netstat'), tasklist: winSys('tasklist'), arp: winSys('arp'), tracert: winSys('tracert'),
      hostname: winSys('hostname'), ipconfig: winSys('ipconfig'), netsh: winSys('netsh'),
      nmap: winProgram('Nmap\\nmap.exe'), tshark: winProgram('Wireshark\\tshark.exe'),
    } : null,
  }
  return t
}

const sources = () => {
  const t = tools()
  const list = []
  if (t.windows && t.windows.netstat) list.push({ id: 'windows', label: IS_WSL ? 'Windows host' : 'This computer' })
  if (t.linux && (t.linux.ss || t.linux.netstat)) list.push({ id: 'linux', label: IS_WSL ? 'WSL' : 'This computer' })
  return list
}

// ---------------------------------------------------------------------------

const linuxAddrs = () => Object.values(os.networkInterfaces()).flat()
  .filter(a => a && !a.internal).map(a => ({ ip: a.address, cidr: a.cidr }))

const winAddrs = async t => {
  if (!t.ipconfig) return []
  const r = await run(t.ipconfig, [])
  const ips = []
  r.stdout.split(/\r?\n/).forEach(l => {
    if (!/IPv[46]/i.test(l)) return
    const m = l.match(/:\s*([0-9a-f.:]+)(%\d+)?(\(|\s|$)/i)
    if (m && require('net').isIP(m[1])) ips.push({ ip: m[1], cidr: null })
  })
  return ips
}

const directionOf = (c, listening) => {
  if (P.isUnspecified(c.remoteIp) || c.remotePort === null || c.remotePort === 0) return 'listen'
  return listening.has(`${c.proto}|${c.localPort}`) ? 'in' : 'out'
}

/** Current connections, listening sockets and neighbours (ARP / NDP) for one side. */
const snapshot = async source => {
  const t = tools()
  let raw = [], neighbors = [], hostName = os.hostname(), addrs = [], via = []
  if (source === 'windows') {
    const w = t.windows
    if (!w || !w.netstat) throw new Error('Windows tools are not reachable from here')
    const [ns, tl, arp, hn, ad, nd] = await Promise.all([
      run(w.netstat, ['-ano']), w.tasklist ? run(w.tasklist, ['/fo', 'csv', '/nh']) : null,
      w.arp ? run(w.arp, ['-a']) : null, w.hostname ? run(w.hostname, []) : null, winAddrs(w),
      w.netsh ? run(w.netsh, ['interface', 'ipv6', 'show', 'neighbors']).catch(() => null) : null,
    ])
    if (!ns.stdout.trim() && INTEROP_FAIL.test(ns.stderr)) throw new Error(INTEROP_HINT)
    raw = P.parseNetstatWin(ns.stdout)
    const procs = tl ? P.parseTasklist(tl.stdout) : new Map()
    // pid 0 owns sockets that are closing (TIME_WAIT); no process is behind them any more
    raw.forEach(c => { c.process = c.pid === 0 ? '(closing)' : procs.get(c.pid) || null })
    neighbors = [...(arp ? P.parseArp(arp.stdout) : []), ...(nd ? P.parseNetshNeighbors(nd.stdout) : [])]
    if (hn && hn.stdout.trim()) hostName = hn.stdout.trim()
    addrs = ad
    via = ['netstat -ano', w.tasklist && 'tasklist', w.arp && 'arp -a', nd && 'netsh ipv6 neighbors'].filter(Boolean)
  } else {
    const l = t.linux
    if (!l) throw new Error('Linux tools are not available here')
    if (l.ss) { raw = P.parseSs((await run(l.ss, ['-tunapH'])).stdout); via.push('ss -tunap') }
    else if (l.netstat) { raw = P.parseNetstatLinux((await run(l.netstat, ['-tunapW'])).stdout); via.push('netstat -tunap') }
    if (l.ip) { neighbors = P.parseIpNeighJson((await run(l.ip, ['-j', 'neigh'])).stdout); via.push('ip neigh') }
    else if (l.arp) { neighbors = P.parseArp((await run(l.arp, ['-an'])).stdout); via.push('arp -an') }
    addrs = linuxAddrs()
  }
  // default gateway (Linux view; with WSL mirrored networking it is the Windows gateway too)
  let gateway = null
  if (t.linux && t.linux.ip) {
    try { const g = JSON.parse((await run(t.linux.ip, ['-j', 'route', 'show', 'default'])).stdout); gateway = (g[0] && g[0].gateway) || null } catch (e) { /* none */ }
  }
  const listening = new Set(raw.filter(c => P.isUnspecified(c.remoteIp) || c.remotePort === 0)
    .map(c => `${c.proto}|${c.localPort}`))
  const connections = [], listen = []
  raw.forEach(c => {
    const d = directionOf(c, listening)
    if (d === 'listen') listen.push({ proto: c.proto, ip: c.localIp, port: c.localPort, pid: c.pid, process: c.process })
    else connections.push({ ...c, direction: d })
  })
  return { source, host: { name: hostName, addrs, gateway }, connections, listening: listen, neighbors, via }
}

// ---------------------------------------------------------------------------
// traceroute / tracert, nmap, reverse DNS

const traceCmd = (source, ip) => {
  const t = tools()
  const v6 = ip.includes(':')
  if (source === 'windows' && t.windows && t.windows.tracert) {
    return [t.windows.tracert, ['-d', '-h', '20', '-w', '600', v6 ? '-6' : '-4', ip], 'tracert']
  }
  if (t.linux && t.linux.traceroute) {
    return [t.linux.traceroute, [v6 ? '-6' : '-4', '-n', '-q', '1', '-w', '1', '-m', '20', ip], 'traceroute']
  }
  if (t.windows && t.windows.tracert) return [t.windows.tracert, ['-d', '-h', '20', '-w', '600', ip], 'tracert']
  return null
}

const trace = async (source, ip) => {
  const cmd = traceCmd(source, ip)
  if (!cmd) return { tool: null, hops: [], error: 'No traceroute tool found. See NETWORK.md for installing traceroute.' }
  const r = await run(cmd[0], cmd[1], 90000)
  const hops = P.parseTrace(r.stdout)
  if (hops.length) return { tool: cmd[2], hops, error: null }
  const msg = r.stderr.trim() || (r.err && r.err.message) || 'no hops'
  const interop = INTEROP_FAIL.test(msg)
  // tracert.exe failed to start from WSL: the Linux traceroute takes the same path out
  const t = tools()
  if (cmd[2] === 'tracert' && IS_WSL && t.linux && t.linux.traceroute) {
    const alt = traceCmd('linux', ip)
    const r2 = await run(alt[0], alt[1], 90000)
    const hops2 = P.parseTrace(r2.stdout)
    if (hops2.length) return { tool: alt[2], hops: hops2, error: null, note: interop ? 'tracert could not start (WSL interop error), used WSL traceroute instead' : 'tracert gave no hops, used WSL traceroute instead' }
  }
  return { tool: cmd[2], hops: [], error: interop ? INTEROP_HINT : msg }
}

const nmapBin = () => {
  const t = tools()
  return (t.linux && t.linux.nmap) || (t.windows && t.windows.nmap) || null
}

/** Service scan of the 100 most common ports. Local targets only (checked by the route). */
const scan = async ip => {
  const bin = nmapBin()
  if (!bin) return { tool: null, error: 'nmap is not installed. See NETWORK.md.' }
  const args = ['-Pn', '-sV', '--version-light', '-F', '--host-timeout', '90s', '-oG', '-']
  if (ip.includes(':')) args.push('-6')
  args.push(ip)
  const r = await run(bin, args, 120000)
  const hosts = P.parseNmapGrepable(r.stdout)
  const h = hosts.find(x => x.ip === ip) || hosts[0] || null
  return { tool: 'nmap', ports: h ? h.ports : [], name: h ? h.name : null, error: h ? null : (r.stderr.trim() || 'host did not answer') }
}

/** Ping sweep of the local IPv4 networks (prefix /22 … /30) to find devices. */
const discover = async () => {
  const bin = nmapBin()
  if (!bin) return { tool: null, hosts: [], error: 'nmap is not installed. See NETWORK.md.' }
  const nets = linuxAddrs().filter(a => a.cidr && require('net').isIPv4(a.ip) && P.isLocalTarget(a.ip) && !a.ip.startsWith('127.'))
    .map(a => a.cidr).filter(c => { const p = Number(c.split('/')[1]); return p >= 22 && p <= 30 })
  if (!nets.length) return { tool: 'nmap', hosts: [], networks: [], error: 'No private IPv4 network (/22 or smaller) found on this machine' }
  const r = await run(bin, ['-sn', '-oG', '-', ...new Set(nets)], 180000)
  return { tool: 'nmap', networks: [...new Set(nets)], hosts: P.parseNmapGrepable(r.stdout).filter(h => h.up), error: null }
}

const rdnsCache = new Map()
const reverse = async ip => {
  const c = rdnsCache.get(ip)
  if (c && Date.now() - c.at < 30 * 60 * 1000) return c.names
  let names = []
  try {
    names = await Promise.race([dns.reverse(ip), new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), 3000))])
  } catch (e) { names = [] }
  rdnsCache.set(ip, { at: Date.now(), names })
  if (rdnsCache.size > 5000) rdnsCache.delete(rdnsCache.keys().next().value)
  return names
}

// ---------------------------------------------------------------------------
// Names seen on the wire: DNS answers and TLS SNI captured by tshark (optional)

// NET_CAPTURE_IFACE, else snort0 (the WSL forwarding setup), else the default-route interface
// (a plain Linux machine where Snort reads e.g. eth0 directly)
const defaultRouteIface = () => {
  try {
    const row = fs.readFileSync('/proc/net/route', 'utf8').split('\n').slice(1)
      .map(l => l.trim().split(/\s+/)).find(f => f[1] === '00000000')
    return row ? row[0] : null
  } catch (e) { return null }
}
const captureIface = () => process.env.NET_CAPTURE_IFACE ||
  (fs.existsSync('/sys/class/net/snort0') ? 'snort0' : defaultRouteIface() || 'snort0')
const wireNames = new Map() // ip → { names: Map(name → last seen s) }
let tshark = null, tsharkError = null, tsharkStarted = false

const startWireNames = () => {
  if (tsharkStarted || IS_WIN) return
  tsharkStarted = true
  const t = tools()
  const bin = t.linux && t.linux.tshark
  if (!bin) { tsharkError = 'tshark is not installed'; tsharkStarted = false; return }
  const iface = captureIface()
  if (!fs.existsSync(`/sys/class/net/${iface}`)) { tsharkError = `interface ${iface} not found (NET_CAPTURE_IFACE)`; tsharkStarted = false; return }
  const args = ['-i', iface, '-n', '-l', '-Q', '-T', 'fields', '-E', 'separator=/t', '-E', 'occurrence=a', '-E', 'aggregator=,',
    '-Y', 'dns.flags.response == 1 || tls.handshake.extensions_server_name',
    '-e', 'ip.dst', '-e', 'ipv6.dst', '-e', 'dns.qry.name', '-e', 'dns.a', '-e', 'dns.aaaa', '-e', 'tls.handshake.extensions_server_name']
  tshark = spawn(bin, args, { stdio: ['ignore', 'pipe', 'pipe'] })
  tsharkError = null
  let buf = ''
  tshark.stdout.on('data', d => {
    buf += d
    const lines = buf.split('\n'); buf = lines.pop()
    const now = Date.now() / 1000
    lines.forEach(l => P.parseTsharkNames(l).forEach(([ip, name]) => {
      const e = wireNames.get(ip) || { names: new Map() }
      e.names.set(name, now)
      if (e.names.size > 8) e.names.delete(e.names.keys().next().value)
      wireNames.set(ip, e)
      if (wireNames.size > 50000) wireNames.delete(wireNames.keys().next().value)
    }))
  })
  let err = ''
  tshark.stderr.on('data', d => { err = (err + d).slice(-500) })
  tshark.on('exit', code => {
    tsharkError = `tshark exited (${code}): ${err.trim().split('\n').pop() || ''}`
    tshark = null
    setTimeout(() => { tsharkStarted = false }, 60000) // retry on a later request
  })
  process.once('exit', () => { if (tshark) tshark.kill() })
}

const namesFor = ips => {
  const out = {}
  ips.forEach(ip => {
    const e = wireNames.get(ip)
    if (e) out[ip] = [...e.names.entries()].sort((a, b) => b[1] - a[1]).map(x => x[0])
  })
  return out
}
const wireStatus = () => ({ running: !!tshark, iface: captureIface(), error: tsharkError, known: wireNames.size })

module.exports = { IS_WIN, IS_WSL, tools, sources, snapshot, trace, scan, discover, reverse, startWireNames, namesFor, wireStatus }
