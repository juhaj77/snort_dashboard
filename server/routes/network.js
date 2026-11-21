// Live network view: who this machine talks to, from the OS's own tools.
//
// GET /network                       sources and installed tools
// GET /network/snapshot?source=      connections, listening sockets, neighbours, wire names
// GET /network/trace/:ip?source=     traceroute / tracert to ip
// GET /network/scan/:ip              nmap service scan (private / link-local addresses only)
// GET /network/discover              nmap ping sweep of the local networks
// GET /network/rdns/:ip              reverse DNS
// GET /network/history?window=       per-address Snort alert and AppID counts over 1 h / 6 h / 24 h
//
// Read-only: nothing is configured or written. Targets must be literal IP addresses.
const express = require('express')
const net = require('net')
const T = require('../lib/net/tools')
const { isLocalTarget } = require('../lib/net/parse')
const { cachedHistory } = require('../lib/net/history')

const router = express.Router()
const MAX_JOBS = 2
let jobs = 0

const sourceOf = req => {
  const list = T.sources()
  const want = req.query.source
  const s = list.find(x => x.id === want) || list[0]
  return s ? s.id : null
}

const ipParam = (req, res) => {
  const ip = String(req.params.ip || '')
  if (!net.isIP(ip)) { res.status(400).json({ error: 'not an IP address' }); return null }
  return ip
}

// Long-running tools: at most MAX_JOBS at a time, so a click storm cannot pile up processes
const job = fn => async (req, res) => {
  if (jobs >= MAX_JOBS) return res.status(429).json({ error: 'Another trace or scan is still running; try again shortly' })
  jobs += 1
  try { res.json(await fn(req, res)) } catch (e) { console.log(e.message); res.status(500).json({ error: e.message }) } finally { jobs -= 1 }
}

router.get('/', (req, res) => {
  T.startWireNames()
  const t = T.tools()
  res.json({
    platform: T.IS_WIN ? 'windows' : T.IS_WSL ? 'wsl' : 'linux',
    sources: T.sources(),
    tools: {
      traceroute: !!((t.linux && t.linux.traceroute) || (t.windows && t.windows.tracert)),
      nmap: !!((t.linux && t.linux.nmap) || (t.windows && t.windows.nmap)),
      tshark: !!(t.linux && t.linux.tshark),
      netTools: !!(t.linux && t.linux.netstat),
      found: Object.fromEntries(['windows', 'linux'].filter(k => t[k])
        .map(k => [k, Object.fromEntries(Object.entries(t[k]).map(([n, v]) => [n, !!v]))])),
    },
    wire: T.wireStatus(),
  })
})

router.get('/snapshot', async (req, res) => {
  const source = sourceOf(req)
  if (!source) return res.status(503).json({ error: 'No connection tool (ss, netstat) found' })
  try {
    T.startWireNames()
    const s = await T.snapshot(source)
    const ips = new Set([...s.connections.map(c => c.remoteIp), ...s.neighbors.map(n => n.ip)])
    res.json({ ...s, at: Date.now() / 1000, names: T.namesFor(ips), wire: T.wireStatus() })
  } catch (e) {
    console.log(e.message)
    res.status(500).json({ error: e.message })
  }
})

router.get('/trace/:ip', (req, res, next) => {
  const ip = ipParam(req, res)
  if (ip) job(() => T.trace(sourceOf(req), ip))(req, res, next)
})

router.get('/scan/:ip', (req, res, next) => {
  const ip = ipParam(req, res)
  if (!ip) return
  if (!isLocalTarget(ip)) {
    return res.status(403).json({ error: 'Port scans are limited to your own network (private, link-local and loopback addresses). Scanning hosts you do not own may be illegal.' })
  }
  job(() => T.scan(ip))(req, res, next)
})

router.get('/discover', job(() => T.discover()))

router.get('/rdns/:ip', async (req, res) => {
  const ip = ipParam(req, res)
  if (ip) res.json({ ip, names: await T.reverse(ip) })
})

// Per-address Snort alert and AppID history for 1 h, 6 h or 24 h (counts from the logs)
const WINDOWS = { 3600: 30, 21600: 60, 86400: 120 } // window → cache seconds
router.get('/history', async (req, res) => {
  const window = Number(req.query.window || 3600)
  if (!WINDOWS[window]) return res.status(400).json({ error: 'window must be 3600, 21600 or 86400' })
  try {
    res.json(await cachedHistory(window, WINDOWS[window]))
  } catch (e) {
    console.log(e.message)
    res.status(500).json({ error: e.message })
  }
})

module.exports = router
