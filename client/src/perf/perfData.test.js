import { parsePerf, perfModel, isGauge, sumCols } from './perfData'

const csv = [
  '#timestamp,daq.received,daq.dropped,stream.current_flows,stream_tcp.sessions,stream_udp.sessions',
  '1060,1000,10,5,3,1',
  '1000,500,0,2,1,1', // out of order: sorted by time
  '1120,1200,0,9,6,2',
  'garbage',
  '1180,600,6,7',     // wrong width
]

test('isGauge recognises instantaneous columns', () => {
  expect(isGauge('stream.current_flows')).toBe(true)
  expect(isGauge('dns.concurrent_sessions')).toBe(true)
  expect(isGauge('dns.max_concurrent_sessions')).toBe(true)
  expect(isGauge('stream_tcp.memory')).toBe(true)
  expect(isGauge('appid.bytes_in_use')).toBe(true)
  expect(isGauge('stream_tcp.max')).toBe(true)
  expect(isGauge('daq.received')).toBe(false)
  expect(isGauge('daq.rx_bytes')).toBe(false)
})

test('parsePerf sorts rows and drops malformed ones', () => {
  const p = parsePerf(csv)
  expect(p.t).toEqual([1000, 1060, 1120])
  expect(p.dropped).toBe(2)
  expect(p.cols.get('daq.received')).toEqual([500, 1000, 1200])
  expect(parsePerf([]).t).toEqual([])
  expect(parsePerf(null).t).toEqual([])
  expect(parsePerf(['not,a,header']).t).toEqual([])
})

test('perfModel rates, totals, ratios and latest values', () => {
  const m = perfModel(csv)
  expect(m.intervals).toEqual([null, 60, 60])
  expect(m.rate('daq.received')).toEqual([null, 1000 / 60, 20])
  expect(m.rate('daq.received', 60)).toEqual([null, 1000, 1200])
  expect(m.total('daq.received')).toBe(2700)
  expect(m.latest('stream.current_flows')).toBe(9)
  expect(m.ratio('daq.dropped', 'daq.received')).toEqual([0, 1, 0])
  expect(m.rate('missing.column')).toBe(null)
  expect(m.total('missing.column')).toBe(null)
  expect(m.nonZero()).toContain('daq.dropped')
  expect(sumCols(m, ['stream_tcp.sessions', 'stream_udp.sessions', 'nope'])).toEqual([2, 4, 8])
  expect(sumCols(m, ['nope'])).toBe(null)
})
