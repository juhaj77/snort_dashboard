import { buildPeers, groupKey, layout, scopeOf, summary, matches, portLabel } from './netModel'

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
const alerts = [
  { id: 'a', seconds: 100, priority: 1, srcIp: '6.6.6.6', dstIp: '192.168.1.217', msg: 'bad' },
  { id: 'b', seconds: 101, priority: 3, srcIp: '192.168.1.217', dstIp: '20.1.2.3', msg: 'meh' },
  { id: 'c', seconds: 102, priority: 2, srcIp: '192.168.1.1', dstIp: '239.255.255.250', msg: 'upnp' },
]
const appid = [
  { client_info: { ip: '192.168.1.217' }, service_info: { ip: '20.1.2.3' }, apps: { service: 'HTTPS' }, tls_host: 'api.example.com' },
  { client_info: { ip: '192.168.1.217' }, service_info: { ip: '9.9.9.9' }, apps: { service: 'DNS' } },
  { broken: true },
]

test('scopeOf', () => {
  expect(scopeOf('192.168.1.1')).toBe('lan')
  expect(scopeOf('8.8.8.8')).toBe('internet')
  expect(scopeOf('fe80::1')).toBe('link-local')
  expect(scopeOf('239.255.255.250')).toBe('multicast')
  expect(scopeOf('::1')).toBe('loopback')
  expect(scopeOf('100.100.1.1')).toBe('lan')
})

test('buildPeers merges connections, alerts, AppID, neighbours and wire names', () => {
  const peers = buildPeers(snapshot, alerts, appid, { seen: true, lan: true })
  const by = Object.fromEntries(peers.map(p => [p.ip, p]))
  expect(Object.keys(by).sort()).toEqual(['192.168.1.1', '192.168.1.50', '20.1.2.3', '6.6.6.6', '9.9.9.9'])
  expect(by['20.1.2.3']).toMatchObject({ live: true, process: 'chrome.exe', port: 443, outbound: 2, maxSev: 3, app: 'HTTPS', appSessions: 1 })
  expect([...by['20.1.2.3'].names]).toEqual(['api.example.com', 'example.com'])
  expect(by['192.168.1.50']).toMatchObject({ inbound: 1, scope: 'lan' })
  expect(by['192.168.1.1']).toMatchObject({ gateway: true, live: false, maxSev: 2 })
  expect(by['192.168.1.1'].neighbor.mac).toBe('aa:bb:cc:dd:ee:ff')
  expect(by['6.6.6.6']).toMatchObject({ live: false, maxSev: 1 })
})

test('buildPeers options: without seen peers only live hosts get alerts; loopback opt-in', () => {
  const peers = buildPeers(snapshot, alerts, appid, { seen: false, lan: false })
  expect(peers.map(p => p.ip).sort()).toEqual(['192.168.1.50', '20.1.2.3'])
  const withLo = buildPeers(snapshot, [], [], { loopback: true })
  expect(withLo.map(p => p.ip)).toContain('127.0.0.1')
  expect(buildPeers(null, null, null, {})).toEqual([])
})

test('grouping and layout are deterministic and place every node', () => {
  const peers = buildPeers(snapshot, alerts, appid, { seen: true, lan: true })
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
  const peers = buildPeers(snapshot, alerts, appid, { seen: true, lan: true })
  expect(summary(snapshot, peers)).toMatchObject({ hosts: 2, lanHosts: 1, netHosts: 1, connections: 4, inbound: 2, outbound: 2, listening: 1, neighbors: 1, alerted: 3, p1: 1 })
  const ex = peers.find(p => p.ip === '20.1.2.3')
  expect(matches(ex, 'example')).toBe(true)
  expect(matches(ex, 'chrome')).toBe(true)
  expect(matches(ex, 'nope')).toBe(false)
  expect(portLabel(443)).toBe('443 HTTPS')
  expect(portLabel(12345)).toBe('12345')
})
