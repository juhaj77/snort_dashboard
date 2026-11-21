import { baseDomain, toSessions, hostStats, groupHosts, regularity, packCircles, prefixOf, isLocalIp, fmtPeriod } from './appidModel'

const ME = '2001:db8:1:2:aaaa:bbbb:cccc:dddd'
const ev = (sess, time, { ip = '203.0.113.5', port = 443, tls = null, dns = null, cport = 50000 } = {}) => ({
  session_num: sess, pkt_time: time, proto: port === 53 ? 'UDP' : 'TCP',
  apps: { service: null, client: null, payload: null, misc: null },
  client_info: { ip: ME, port: cport }, service_info: { ip, port },
  tls_host: tls, dns_host: dns, http: { host: null },
})

test('baseDomain keeps the registrable part', () => {
  expect(baseDomain('content-autofill.googleapis.com')).toBe('googleapis.com')
  expect(baseDomain('www.bbc.co.uk')).toBe('bbc.co.uk')
  expect(baseDomain('github.com')).toBe('github.com')
  expect(baseDomain('192.168.1.1')).toBeNull()
  expect(baseDomain('2001:db8::1')).toBeNull()
})

test('sessions merge lines, DNS sessions are named by the lookup', () => {
  const s = toSessions([
    ev('0.1', '2026-11-21 12:00:00.000001', { ip: '2001:db8:1:2::1', port: 53, dns: 'api.github.com' }),
    ev('0.1', '2026-11-21 12:00:00.000300', { ip: '2001:db8:1:2::1', port: 53, dns: 'api.github.com' }),
    ev('0.2', '2026-11-21 12:00:01.000000', { tls: 'api.github.com', cport: 50001 }),
  ])
  expect(s).toHaveLength(2)
  expect(s[0]).toMatchObject({ kind: 'dns', host: 'api.github.com', group: 'github.com', lines: 2 })
  expect(s[1]).toMatchObject({ kind: 'tls', host: 'api.github.com' })
})

test('unnamed sessions inherit the TLS name of their address, or the domain of their network', () => {
  const s = toSessions([
    ev('0.1', '2026-11-21 12:00:00.0', { ip: '198.51.100.7' }),
    ev('0.2', '2026-11-21 12:00:01.0', { ip: '198.51.100.7', tls: 'cdn.example.com', cport: 2 }),
    ev('0.3', '2026-11-21 12:00:02.0', { ip: '198.51.100.9', cport: 3 }),
    ev('0.4', '2026-11-21 12:00:03.0', { ip: '192.168.1.1', port: 80, cport: 4 }),
  ])
  expect(s[0]).toMatchObject({ host: 'cdn.example.com', inferred: true })
  expect(s[2]).toMatchObject({ host: '198.51.100.9', group: 'example.com', groupGuessed: true })
  expect(s[3]).toMatchObject({ group: 'local network', kind: 'other' })
})

test('address helpers', () => {
  expect(prefixOf('2a03:2880:f113:81:face:b00c:0:25de')).toBe('2a03:2880:f113')
  expect(prefixOf('2a03:2880::1')).toBe('2a03:2880:0')
  expect(prefixOf('10.1.2.3')).toBe('10.1.2')
  expect(isLocalIp('fe80::1')).toBe(true)
  expect(isLocalIp('ff02::16')).toBe(true)
  expect(isLocalIp('224.0.0.252')).toBe(true)
  expect(isLocalIp('2001:db8:1:2::1', new Set(['2001:db8:1:2']))).toBe(true)
  expect(isLocalIp('8.8.8.8')).toBe(false)
})

test('regularity finds a steady rhythm and ignores bursts', () => {
  const every30 = Array.from({ length: 10 }, (_, i) => i * 30000)
  expect(regularity(every30)).toBe(30000)
  // A + AAAA lookups 10 ms apart are one burst
  expect(regularity(every30.flatMap(t => [t, t + 10]))).toBe(30000)
  expect(regularity([0, 1000, 50000, 52000, 200000, 900000, 901000])).toBeNull()
  expect(regularity([0, 30000, 60000])).toBeNull() // too few
})

test('hostStats counts per host within the window, busiest first', () => {
  const lines = []
  for (let i = 0; i < 8; i++) {
    lines.push(ev('0.' + i, `2026-11-21 12:0${i}:00.0`, { tls: 'poll.example.com', cport: i }))
  }
  lines.push(ev('0.99', '2026-11-21 12:03:30.0', { tls: 'once.example.org', cport: 99 }))
  const s = toSessions(lines)
  const h = hostStats(s)
  expect(h.map(x => x.host)).toEqual(['poll.example.com', 'once.example.org'])
  expect(h[0]).toMatchObject({ count: 8, period: 60000, kind: 'tls' })
  expect(h[0].sessionKinds).toHaveLength(8)
  const late = hostStats(s, s[0].t + 5 * 60e3)
  expect(late.map(x => x.count)).toEqual([3])
  expect(groupHosts(h).map(g => g.group)).toEqual(['example.com', 'example.org'])
})

test('packCircles places circles without overlap', () => {
  const items = [30, 20, 20, 10, 10, 10, 5].map(r => ({ r }))
  const { items: out, radius } = packCircles(items, 2)
  for (let i = 0; i < out.length; i++) {
    for (let j = i + 1; j < out.length; j++) {
      expect(Math.hypot(out[i].x - out[j].x, out[i].y - out[j].y)).toBeGreaterThanOrEqual(out[i].r + out[j].r + 2 - 1e-9)
    }
    expect(Math.hypot(out[i].x, out[i].y) + out[i].r).toBeLessThanOrEqual(radius + 1e-9)
  }
})

test('fmtPeriod', () => {
  expect(fmtPeriod(30000)).toBe('~30 s')
  expect(fmtPeriod(150000)).toBe('~2.5 min')
  expect(fmtPeriod(2 * 3600e3)).toBe('~2 h')
})
