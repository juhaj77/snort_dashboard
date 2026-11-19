import {
  hostOf, normalizeAlert, normalizeAlerts, timeBins, pickStep, topN,
  severityCounts, addrScope, appIdSessions, appDistribution,
} from './aggregate'

const alert = (over = {}) => ({
  timestamp: '11/19-18:16:11.513100', seconds: 1000, priority: 3, proto: 'UDP',
  src_addr: '192.168.1.139', src_port: 59727, dst_addr: '255.255.255.255', dst_port: 6667,
  src_ap: '192.168.1.139:59727', dst_ap: '255.255.255.255:6667',
  msg: 'm', rule: '116:414:1', class: 'none', ...over,
})

test('hostOf handles IPv4, IPv6 and empty hosts', () => {
  expect(hostOf('10.0.0.1:80')).toBe('10.0.0.1')
  expect(hostOf('2001:db8::1:443')).toBe('2001:db8::1')
  expect(hostOf(':0')).toBe(null)
  expect(hostOf(undefined)).toBe(null)
})

test('normalizeAlert rejects records without seconds and fixes priority', () => {
  expect(normalizeAlert(null)).toBe(null)
  expect(normalizeAlert({ msg: 'x' })).toBe(null)
  expect(normalizeAlert(alert({ seconds: 'abc' }))).toBe(null)
  expect(normalizeAlert(alert({ priority: 0 })).priority).toBe(0)
  expect(normalizeAlert(alert({ priority: 9 })).priority).toBe(0)
  expect(normalizeAlert(alert({ priority: '1' })).priority).toBe(1)
})

test('normalizeAlert falls back to src_ap/dst_ap and leaves L2 alerts without hosts', () => {
  const n = normalizeAlert(alert({ src_addr: undefined, src_port: undefined }))
  expect(n.srcIp).toBe('192.168.1.139')
  expect(n.srcPort).toBe(59727)
  const l2 = normalizeAlert({ seconds: 5, priority: 3, proto: 'eth', dst_ap: ':0', msg: 'x', class: 'none' })
  expect(l2.srcIp).toBe(null)
  expect(l2.dstIp).toBe(null)
  expect(l2.dstPort).toBe(null)
  expect(l2.cls).toBe(null)
})

test('normalizeAlerts sorts and counts dropped records', () => {
  const { alerts, dropped } = normalizeAlerts([alert({ seconds: 3 }), 'junk', alert({ seconds: 1 }), {}])
  expect(alerts.map(a => a.seconds)).toEqual([1, 3])
  expect(dropped).toBe(2)
  expect(normalizeAlerts(undefined)).toEqual({ alerts: [], dropped: 0 })
})

test('timeBins keeps empty bins and stacks by severity', () => {
  const { alerts } = normalizeAlerts([
    alert({ seconds: 0, priority: 1 }), alert({ seconds: 1 }), alert({ seconds: 120, priority: 2 }),
  ])
  const { step, bins } = timeBins(alerts, 60)
  expect(step).toBe(5)
  expect(bins.length).toBe(25)
  expect(bins[0].total).toBe(2)
  expect(bins[0].counts[1]).toBe(1)
  expect(bins[0].counts[3]).toBe(1)
  expect(bins[24].counts[2]).toBe(1)
  expect(bins.slice(1, 24).every(b => b.total === 0)).toBe(true)
  expect(timeBins([], 60)).toEqual({ step: 0, bins: [] })
})

test('pickStep stays within the target bin count', () => {
  expect(pickStep(3600, 60)).toBe(60)
  expect(pickStep(86400 * 30, 60)).toBe(43200)
  expect(86400 * 400 / pickStep(86400 * 400, 60)).toBeLessThanOrEqual(60)
})

test('topN ranks, folds the tail into other and counts missing keys', () => {
  const { alerts } = normalizeAlerts([
    alert({ src_addr: 'a' }), alert({ src_addr: 'a', priority: 1 }), alert({ src_addr: 'b' }),
    alert({ src_addr: 'c' }), alert({ src_addr: undefined, src_ap: undefined }),
  ])
  const r = topN(alerts, a => a.srcIp, 2)
  expect(r.rows.map(x => [x.key, x.total])).toEqual([['a', 2], ['b', 1]])
  expect(r.rows[0].counts[1]).toBe(1)
  expect(r.other).toBe(1)
  expect(r.missing).toBe(1)
  expect(r.distinct).toBe(3)
})

test('severityCounts', () => {
  const { alerts } = normalizeAlerts([alert({ priority: 1 }), alert({ priority: 0 }), alert()])
  expect(severityCounts(alerts)).toEqual({ 1: 1, 2: 0, 3: 1, 4: 0, 0: 1 })
})

test('addrScope', () => {
  expect(addrScope('255.255.255.255')).toBe('broadcast')
  expect(addrScope('239.255.255.250')).toBe('multicast')
  expect(addrScope('ff02::fb')).toBe('multicast')
  expect(addrScope('fe80::1')).toBe('link-local')
  expect(addrScope('192.168.1.1')).toBe('private')
  expect(addrScope('8.8.8.8')).toBe(null)
})

test('appIdSessions keeps the last known value per session', () => {
  const s = appIdSessions([
    { session_num: '1', apps: { service: null, client: null, payload: null } },
    { session_num: '1', apps: { service: 'DNS', client: null, payload: null } },
    { session_num: '2', apps: { service: 'HTTPS', client: 'Chrome', payload: null } },
    { session_num: '2', apps: { service: null, client: null, payload: null } },
    'junk', null,
  ])
  expect(s).toHaveLength(2)
  expect(s.find(x => x.session === '1').service).toBe('DNS')
  expect(s.find(x => x.session === '2').client).toBe('Chrome')
  const d = appDistribution(s, 'payload')
  expect(d.pending).toBe(2)
  expect(d.rows).toEqual([])
})
