const test = require('node:test')
const assert = require('node:assert')
const fs = require('fs')
const os = require('os')
const path = require('path')
const { perfRange } = require('../lib/perfRange')

const HEADER = '#timestamp,daq.received,stream.current_flows'
const tmp = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'perf-')), 'perf_monitor_base.csv')
const rows = (t0, n, step = 60) => Array.from({ length: n }, (_, i) => `${t0 + i * step},${100 + i},${i}`)

test('reads only the newest run and keeps every row when points allow it', async () => {
  const f = tmp()
  fs.writeFileSync(f, [HEADER, ...rows(1000, 5), HEADER, ...rows(5000, 4)].join('\n') + '\n')
  const r = await perfRange(f, 0, 100)
  assert.strictEqual(r.lines[0], HEADER)
  assert.deepStrictEqual(r.lines.slice(1), rows(5000, 4))
  assert.strictEqual(r.runStart, 5000)
  assert.strictEqual(r.runEnd, 5180)
  assert.strictEqual(r.anchor, false)
  assert.strictEqual(r.bucketed, false)
})

test('since returns an anchor row and the rows from since on', async () => {
  const f = tmp()
  fs.writeFileSync(f, [HEADER, ...rows(1000, 10)].join('\n') + '\n')
  const r = await perfRange(f, 1300, 100)
  assert.strictEqual(r.anchor, true)
  assert.strictEqual(r.lines[1].split(',')[0], '1240') // anchor: newest row before since
  assert.deepStrictEqual(r.lines.slice(2).map(l => l.split(',')[0]), ['1300', '1360', '1420', '1480', '1540'])
  assert.strictEqual(r.rows, 5)
})

test('bucketing sums counters, keeps the newest gauge and preserves totals', async () => {
  const f = tmp()
  const data = rows(0, 100)
  fs.writeFileSync(f, [HEADER, ...data].join('\n') + '\n')
  const r = await perfRange(f, 0, 10)
  assert.strictEqual(r.bucketed, true)
  assert.ok(r.lines.length - 1 <= 11)
  const col = i => r.lines.slice(1).map(l => Number(l.split(',')[i]))
  const total = data.reduce((s, l) => s + Number(l.split(',')[1]), 0)
  assert.strictEqual(col(1).reduce((s, v) => s + v, 0), total)
  // newest bucket ends at the newest row and carries its gauge value
  const last = r.lines[r.lines.length - 1].split(',')
  assert.strictEqual(last[0], '5940')
  assert.strictEqual(last[2], '99')
})

test('a header appended later (Snort restart) is found by the incremental scan', async () => {
  const f = tmp()
  fs.writeFileSync(f, [HEADER, ...rows(1000, 3)].join('\n') + '\n')
  assert.strictEqual((await perfRange(f, 0, 100)).runStart, 1000)
  fs.appendFileSync(f, [HEADER, ...rows(9000, 2)].join('\n') + '\n')
  const r = await perfRange(f, 0, 100)
  assert.strictEqual(r.runStart, 9000)
  assert.deepStrictEqual(r.lines.slice(1), rows(9000, 2))
})

test('a header split across read chunks is found', async () => {
  const f = tmp()
  const pad = 'x'.repeat(256 * 1024 - 10) // puts the next line start 4 bytes before a chunk boundary
  fs.writeFileSync(f, `#junk${pad}\n` + [HEADER, ...rows(7000, 2)].join('\n') + '\n')
  const r = await perfRange(f, 0, 100)
  assert.strictEqual(r.runStart, 7000)
  assert.strictEqual(r.lines[0], HEADER)
})

test('malformed rows are skipped, empty and header-only files return no rows', async () => {
  const f = tmp()
  fs.writeFileSync(f, [HEADER, '100,1,1', 'broken', '160,2', '220,3,3'].join('\n') + '\n')
  assert.deepStrictEqual((await perfRange(f, 0, 100)).lines.slice(1), ['100,1,1', '220,3,3'])
  const e = tmp(); fs.writeFileSync(e, '')
  assert.deepStrictEqual((await perfRange(e, 0, 100)).lines, [])
  const h = tmp(); fs.writeFileSync(h, HEADER + '\n')
  assert.deepStrictEqual((await perfRange(h, 0, 100)).lines, [HEADER])
})
