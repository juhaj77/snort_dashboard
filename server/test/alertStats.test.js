const test = require('node:test')
const assert = require('node:assert')
const fs = require('fs')
const os = require('os')
const path = require('path')
const { alertStats, alertsBetween } = require('../lib/alertStats')

const tmp = () => path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'alerts-')), 'alert_json.txt')
const line = (s, rule, src = '10.0.0.1', extra = {}) => JSON.stringify({
  seconds: s, rule, msg: 'm ' + rule, priority: 3, class: 'none', src_addr: src, dst_addr: '10.0.0.9', ...extra,
})

test('alertStats counts per rule and bin and keeps top sources per cell', async () => {
  const f = tmp()
  fs.writeFileSync(f, [
    line(900, '1:1:1'),            // before the window
    line(1000, '1:1:1'), line(1010, '1:1:1', '10.0.0.2'), line(1010, '1:1:1', '10.0.0.2'),
    line(1065, '1:2:1', '10.0.0.3', { priority: 1, class: 'Attack' }),
    '{"half": ', // being written
    line(1190, '1:1:1'),
  ].join('\n') + '\n')
  const r = await alertStats(f, { since: 1000, until: 1200, step: 60 })
  assert.strictEqual(r.bins, 4)
  assert.strictEqual(r.total, 5)
  const a = r.rules.find(x => x.rule === '1:1:1')
  assert.deepStrictEqual(a.counts, [3, 0, 0, 1])
  assert.deepStrictEqual(a.cells[0].src, [['10.0.0.2', 2], ['10.0.0.1', 1]])
  const b = r.rules.find(x => x.rule === '1:2:1')
  assert.deepStrictEqual(b, { rule: '1:2:1', msg: 'm 1:2:1', priority: 1, cls: 'Attack', total: 1,
    counts: [0, 1, 0, 0], cells: { 1: { src: [['10.0.0.3', 1]], dst: [['10.0.0.9', 1]] } } })
  assert.strictEqual(r.rules[0].rule, '1:1:1') // busiest first
})

test('alertsBetween filters by time and rule, oldest first, capped to the newest', async () => {
  const f = tmp()
  fs.writeFileSync(f, [1, 2, 3, 4, 5, 6].map(i => line(1000 + i, i % 2 ? '1:1:1' : '1:2:1')).join('\n') + '\n')
  const all = await alertsBetween(f, { since: 1002, until: 1005, cap: 100 })
  assert.deepStrictEqual(all.map(a => a.seconds), [1002, 1003, 1004, 1005])
  const odd = await alertsBetween(f, { since: 0, until: Infinity, rule: '1:1:1', cap: 2 })
  assert.deepStrictEqual(odd.map(a => a.seconds), [1003, 1005])
})
