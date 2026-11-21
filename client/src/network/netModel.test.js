import { attention, buildPeers, eui64Mac, expand6, groupKey, layout, scopeOf, signalsOf, summary, matches, portLabel } from './netModel'

const snapshot = {
  host: { name: 'pc', addrs: [{ ip: '192.168.1.217' }], gateway: '192.168.1.1' },
  connections: [
    { proto: 'TCP', state: 'ESTABLISHED', localIp: '192.168.1.217', localPort: 50000, remoteIp: '20.1.2.3', remotePort: 443, pid: 10, process: 'chrome.exe', direction: 'out' },
    { proto: 'TCP', state: 'ESTABLISHED', localIp: '192.168.1.217', localPort: 50001, remoteIp: '20.1.2.3', remotePort: 443, pid: 10, process: 'chrome.exe', direction: 'out' },
    { proto: 'TCP', state: 'ESTABLISHED', localIp: '192.168.1.217', localPort: 22, remoteIp: '192.168.1.50', remotePort: 40000, pid: 5, process: 'sshd', direction: 'in' },
    { proto: 'TCP', state: 'ESTABLISHED', localIp: '127.0.0.1', localPort: 9000, remoteIp: '127.0.0.1', remotePort: 40001, pid: 7, process: 'node', direction: 'in' },
  ],
  listening: [{ proto: 'TCP', ip: '0.0.0.0', port: 22 }, { proto: 'TCP', ip: '::', port: 22 }],
  neighbors: [{ ip: '192.168.1.1', mac: 'aa:bb:cc:dd:ee:ff' }, { ip: '224.0.0.251', mac: '01:00:5e:00:00:fb' }],
  names: { '20.1.2.3': ['example.com'] },
}
const NOW = 100000
const bins = () => Array(30).fill(0)
const al = (n, sev, extra = {}) => ({ n, sev: { 0: 0, 1: 0, 2: 0, 3: 0, 4: 0, ...sev }, first: NOW - 3000, last: NOW - 10, recent: 0, bins: bins(), sigs: [], sigCount: 0, ...extra })
const ap = (n, extra = {}) => ({ n, first: NOW - 2000, last: NOW - 5, recent: 0, bins: bins(), apps: {}, services: [], names: [], ...extra })
const hist = {
  window: 3600, since: NOW - 3600, until: NOW, bins: 30, step: 120, recent: 600,
  coverage: { alerts: { total: 10, from: NOW - 3600 }, appid: { total: 3, from: NOW - 3600 } },
  hosts: {
    '192.168.1.217': { alerts: al(9, { 1: 1 }) }, // this machine: ignored
    '6.6.6.6': { alerts: al(1, { 1: 1 }, { sigs: [{ msg: 'bad', priority: 1, count: 1, last: NOW - 10 }], sigCount: 1 }) },
    '20.1.2.3': { alerts: al(1, { 3: 1 }), appid: ap(1, { apps: { HTTPS: 1 }, names: ['api.example.com'] }) },
    '192.168.1.1': { alerts: al(1, { 2: 1 }) },
    '239.255.255.250': { alerts: al(1, { 2: 1 }) }, // multicast: ignored
    '9.9.9.9': { appid: ap(1, { apps: { DNS: 1 } }) },
  },
}

test('scopeOf', () => {
  expect(scopeOf('192.168.1.1')).toBe('lan')
  expect(scopeOf('8.8.8.8')).toBe('internet')
  expect(scopeOf('fe80::1')).toBe('link-local')
  expect(scopeOf('239.255.255.250')).toBe('multicast')
  expect(scopeOf('::1')).toBe('loopback')
  expect(scopeOf('100.100.1.1')).toBe('lan')
})

test('buildPeers merges connections, alerts, AppID, neighbours and wire names', () => {
  const peers = buildPeers(snapshot, hist, { seen: true, lan: true })
  const by = Object.fromEntries(peers.map(p => [p.ip, p]))
  expect(Object.keys(by).sort()).toEqual(['192.168.1.1', '192.168.1.50', '20.1.2.3', '6.6.6.6', '9.9.9.9'])
  expect(by['20.1.2.3']).toMatchObject({ live: true, process: 'chrome.exe', port: 443, outbound: 2, maxSev: 3, app: 'HTTPS', appSessions: 1, alertCount: 1, firstSeen: NOW - 3000, lastSeen: NOW - 5 })
  expect([...by['20.1.2.3'].names]).toEqual(['api.example.com', 'example.com'])
  expect(by['192.168.1.50']).toMatchObject({ inbound: 1, scope: 'lan' })
  expect(by['192.168.1.1']).toMatchObject({ gateway: true, live: false, maxSev: 2 })
  expect(by['192.168.1.1'].neighbor.mac).toBe('aa:bb:cc:dd:ee:ff')
  expect(by['6.6.6.6']).toMatchObject({ live: false, maxSev: 1 })
  expect(by['6.6.6.6'].signals.map(x => x.id)).toEqual(['p1'])
  expect(by['6.6.6.6'].signals[0].detail).toContain('bad')
})

test('buildPeers options: without seen peers only live hosts get alerts; loopback opt-in', () => {
  const peers = buildPeers(snapshot, hist, { seen: false, lan: false })
  expect(peers.map(p => p.ip).sort()).toEqual(['192.168.1.50', '20.1.2.3'])
  const withLo = buildPeers(snapshot, null, { loopback: true })
  expect(withLo.map(p => p.ip)).toContain('127.0.0.1')
  expect(buildPeers(null, null, {})).toEqual([])
})

test('grouping and layout are deterministic and place every node', () => {
  const peers = buildPeers(snapshot, hist, { seen: true, lan: true })
  expect(groupKey(peers.find(p => p.ip === '20.1.2.3'), 'process')).toBe('chrome.exe')
  expect(groupKey(peers.find(p => p.ip === '20.1.2.3'), 'service')).toBe('HTTPS')
  expect(groupKey(peers.find(p => p.ip === '6.6.6.6'), 'process')).toBe('Snort alerts, not connected')
  expect(groupKey(peers.find(p => p.ip === '9.9.9.9'), 'process')).toBe('AppID only, not connected')
  expect(groupKey(peers.find(p => p.ip === '192.168.1.1'), 'scope')).toBe('Local network')
  const a = layout(peers, 'process'), b = layout(peers, 'process')
  expect(a.nodes).toHaveLength(peers.length)
  expect(a.nodes.map(p => [p.x, p.y])).toEqual(b.nodes.map(p => [p.x, p.y]))
  expect(a.box.x1).toBeGreaterThan(a.box.x0)
  expect(layout([], 'process').nodes).toEqual([])
})

test('summary, search and port labels', () => {
  const peers = buildPeers(snapshot, hist, { seen: true, lan: true })
  expect(summary(snapshot, peers)).toMatchObject({ hosts: 2, lanHosts: 1, netHosts: 1, connections: 4, inbound: 2, outbound: 2, listening: 1, neighbors: 1, alerted: 3, p1: 1 })
  const ex = peers.find(p => p.ip === '20.1.2.3')
  expect(matches(ex, 'example')).toBe(true)
  expect(matches(ex, 'chrome')).toBe(true)
  expect(matches(ex, 'nope')).toBe(false)
  expect(portLabel(443)).toBe('443 HTTPS')
  expect(portLabel(12345)).toBe('12345')
})

const peer = (over = {}) => {
  const [n] = buildPeers({ host: { addrs: [] }, connections: [] }, { ...hist, hosts: { '8.8.4.4': over.h || { alerts: al(0, {}) } } }, { seen: true })
  return Object.assign(n, over.n || {})
}

test('signals: rising alerts need a clear jump against enough earlier log', () => {
  // 10 recent alerts, 2 in the 50 minutes before → rising
  const up = peer({ h: { alerts: al(12, { 3: 12 }, { recent: 10 }) } })
  expect(up.signals.map(x => x.id)).toContain('rising')
  // steady rate: 10 recent, 50 before (= 10 per 10 min) → not rising
  expect(peer({ h: { alerts: al(60, { 3: 60 }, { recent: 10 }) } }).signals.map(x => x.id)).not.toContain('rising')
  // fewer than 5 recent → not rising
  expect(peer({ h: { alerts: al(4, { 3: 4 }, { recent: 4 }) } }).signals).toEqual([])
  // log starts 15 minutes ago: not enough earlier log to compare
  const short = { ...hist, coverage: { ...hist.coverage, alerts: { from: NOW - 900 } } }
  expect(signalsOf(up, short).map(x => x.id)).not.toContain('rising')
})

test('signals: new host, service on unexpected port, inbound from the internet, uncommon port', () => {
  const fresh = peer({ h: { appid: ap(2, { first: NOW - 300 }) } })
  expect(fresh.signals.map(x => x.id)).toEqual(['new'])
  // logs only started 20 min ago → can't say it is new
  const shortLog = { ...hist, coverage: { alerts: { from: NOW - 1200 }, appid: { from: NOW - 1200 } } }
  expect(signalsOf(fresh, shortLog)).toEqual([])
  const ssh = peer({ h: { appid: ap(1, { services: [{ app: 'SSH', port: 2222, proto: 'TCP', count: 1 }, { app: 'HTTP', port: 80, proto: 'TCP', count: 3 }] }) } })
  expect(ssh.signals).toEqual([expect.objectContaining({ id: 'mismatch', detail: 'SSH on 2222/TCP (AppID)' })])

  const snap = {
    host: { addrs: [{ ip: '10.0.0.2' }] },
    connections: [
      { proto: 'TCP', localIp: '10.0.0.2', localPort: 3389, remoteIp: '7.7.7.7', remotePort: 51000, direction: 'in', process: 'svchost.exe' },
      { proto: 'TCP', localIp: '10.0.0.2', localPort: 50000, remoteIp: '8.8.8.8', remotePort: 6667, direction: 'out' },
      { proto: 'TCP', localIp: '10.0.0.2', localPort: 50001, remoteIp: '1.1.1.1', remotePort: 443, direction: 'out' },
      { proto: 'UDP', localIp: '10.0.0.2', localPort: 5353, remoteIp: '9.9.9.9', remotePort: 443, direction: 'in' },
    ],
  }
  const by = Object.fromEntries(buildPeers(snap, null, {}).map(p => [p.ip, p]))
  expect(by['7.7.7.7'].signals).toEqual([expect.objectContaining({ id: 'inbound', level: 'warn', detail: '1 TCP connection to local port 3389 (svchost.exe)' })])
  expect(by['8.8.8.8'].signals).toEqual([expect.objectContaining({ id: 'port', level: 'info' })])
  expect(by['1.1.1.1'].signals).toEqual([])
  expect(by['9.9.9.9'].signals).toEqual([]) // UDP direction is not trusted
})

test('attention orders by most serious signal, then by count', () => {
  const peers = buildPeers(snapshot, hist, { seen: true, lan: true })
  expect(attention(peers).map(p => p.ip)).toEqual(['6.6.6.6', '192.168.1.1'])
})

test('IPv6 helpers: expand and EUI-64 MAC', () => {
  expect(expand6('2001:db8::1')).toEqual([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1])
  expect(expand6('fe80::1%12')).toEqual([0xfe80, 0, 0, 0, 0, 0, 0, 1])
  expect(expand6('1.2.3.4')).toBeNull()
  expect(expand6('1:2:3')).toBeNull()
  expect(eui64Mac('fe80::6c14:8aff:feb2:d281')).toBe('6e:14:8a:b2:d2:81')
  expect(eui64Mac('2001:db8::1')).toBeNull()
})

test('addresses of one device merge into one node; own /64 is the local network', () => {
  const snap = {
    host: { addrs: [{ ip: '192.168.1.217' }, { ip: '2001:db8:1:2:aaaa:bbbb:cccc:dddd' }], gateway: '192.168.1.1' },
    connections: [{ proto: 'TCP', localIp: '2001:db8:1:2:aaaa:bbbb:cccc:dddd', localPort: 50000, remoteIp: '2001:db8:1:2::1', remotePort: 53, direction: 'out', process: 'svchost.exe' }],
    neighbors: [
      { ip: '192.168.1.1', mac: '44:d4:37:69:ad:d8' },
      { ip: '2001:db8:1:2::1', mac: '44:d4:37:69:ad:d8' },
      { ip: 'fe80::46d4:37ff:fe69:add8', mac: '44:d4:37:69:ad:d8' },
      { ip: '192.168.1.221', mac: '6e:14:8a:b2:d2:81' },
    ],
  }
  const h = {
    ...hist,
    hosts: {
      '192.168.1.1': { alerts: al(10, { 2: 10 }, { sigs: [{ msg: 'upnp', priority: 2, count: 10, last: NOW - 20 }], sigCount: 1 }) },
      '2001:db8:1:2::1': { alerts: al(5, { 2: 3, 3: 2 }, { last: NOW - 5, sigs: [{ msg: 'upnp', priority: 2, count: 3, last: NOW - 5 }, { msg: 'opt', priority: 3, count: 2, last: NOW - 9 }], sigCount: 2 }), appid: ap(7) },
      'fe80::6c14:8aff:feb2:d281': { alerts: al(2, { 0: 2 }) }, // no neighbour entry: matched by its EUI-64 MAC
      '2001:db8:9::5': { appid: ap(1) }, // another /64: internet
    },
  }
  const peers = buildPeers(snap, h, { seen: true, lan: true })
  const by = Object.fromEntries(peers.map(p => [p.ip, p]))
  expect(Object.keys(by).sort()).toEqual(['192.168.1.1', '192.168.1.221', '2001:db8:9::5'])
  const gw = by['192.168.1.1']
  expect(gw.addrs).toEqual(['192.168.1.1', '2001:db8:1:2::1', 'fe80::46d4:37ff:fe69:add8'])
  expect(gw).toMatchObject({ gateway: true, scope: 'lan', live: true, alertCount: 15, appSessions: 7, process: 'svchost.exe' })
  expect(gw.sev).toMatchObject({ 2: 13, 3: 2 })
  expect(gw.sigs.map(s => [s.msg, s.count])).toEqual([['upnp', 13], ['opt', 2]])
  expect(gw.alertHist.last).toBe(NOW - 5)
  expect(gw.signals.map(x => x.id)).toEqual(['p2']) // no "uncommon port" now that it is local
  expect(by['192.168.1.221'].addrs).toEqual(['192.168.1.221', 'fe80::6c14:8aff:feb2:d281'])
  expect(by['192.168.1.221'].alertCount).toBe(2)
  expect(by['2001:db8:9::5'].scope).toBe('internet')
  expect(matches(gw, 'fe80::46d4')).toBe(true)
  expect(summary(snap, peers).neighbors).toBe(2) // devices, not addresses
})
