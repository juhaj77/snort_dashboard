const test = require('node:test')
const assert = require('node:assert')
const fs = require('fs')
const os = require('os')
const path = require('path')
const { history, appidTime } = require('../lib/net/history')
const { eachLineBackwards } = require('../lib/readTail')

const dir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'hist-'))
const alert = (seconds, src, dst, priority = 3, msg = 'm') => JSON.stringify({ seconds, src_addr: src, dst_addr: dst, priority, msg })
const pad = n => String(n).padStart(2, '0')
const local = s => { const d = new Date(s * 1000); return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}.123456` }
const session = (t, c, s, port, app = null, extra = {}) => JSON.stringify({
  pkt_time: local(t), proto: 'TCP', apps: { service: app }, client_info: { ip: c, port: 50000 }, service_info: { ip: s, port }, ...extra,
})

test('appidTime parses appid_listener local timestamps', () => {
  const t = 1795228000
  assert.strictEqual(Math.floor(appidTime(local(t))), t)
  assert.strictEqual(appidTime('nonsense'), null)
  assert.strictEqual(appidTime(undefined), null)
})

test('alerts are counted per address over the window, through rotated files', async () => {
  const d = dir(), now = 10000
  const f = path.join(d, 'alert_json.txt')
  // rotated file holds the older part; the oldest line is outside the 1 h window
  fs.writeFileSync(f + '.9000', [alert(6000, '1.1.1.1', '10.0.0.2'), alert(7000, '1.1.1.1', '10.0.0.2', 1, 'bad')].join('\n') + '\n')
  fs.writeFileSync(f, [alert(9000, '1.1.1.1', '10.0.0.2', 2, 'meh'), 'broken {', alert(9700, '1.1.1.1', '10.0.0.2', 1, 'bad'), alert(9800, '2.2.2.2', '10.0.0.2')].join('\n') + '\n')
  const r = await history(3600, { now, alertFile: f, appidFile: path.join(d, 'none.json') })
  const a = r.hosts['1.1.1.1'].alerts
  assert.strictEqual(a.n, 3)
  assert.deepStrictEqual(a.sev, { 0: 0, 1: 2, 2: 1, 3: 0, 4: 0 })
  assert.strictEqual(a.first, 7000)
  assert.strictEqual(a.last, 9700)
  assert.strictEqual(a.recent, 1) // only 9700 is within the last 10 min
  assert.strictEqual(a.bins.reduce((s, x) => s + x, 0), 3)
  assert.deepStrictEqual(a.sigs.map(s => [s.msg, s.count]), [['bad', 2], ['meh', 1]])
  assert.strictEqual(r.hosts['10.0.0.2'].alerts.n, 4)
  assert.strictEqual(r.coverage.alerts.from, r.since) // the logs reach back past the window
  assert.deepStrictEqual(r.coverage.alerts.files, ['alert_json.txt', 'alert_json.txt.9000'])
})

test('coverage says where the logs start when they are shorter than the window', async () => {
  const d = dir(), now = 100000
  const f = path.join(d, 'alert_json.txt')
  fs.writeFileSync(f, [alert(99000, '1.1.1.1', '10.0.0.2'), alert(99500, '1.1.1.1', '10.0.0.2')].join('\n') + '\n')
  const r = await history(86400, { now, alertFile: f, appidFile: path.join(d, 'none.json') })
  assert.strictEqual(r.coverage.alerts.from, 99000)
  assert.strictEqual(r.coverage.appid.from, null)
  assert.strictEqual(r.coverage.appid.total, 0)
})

test('AppID sessions: per address counts, service names on ports, TLS names of the server side', async () => {
  const d = dir(), now = Math.floor(Date.now() / 1000)
  const af = path.join(d, 'appid.json')
  fs.writeFileSync(af, [
    session(now - 5000, '10.0.0.2', '5.5.5.5', 443), // outside 1 h
    session(now - 1000, '10.0.0.2', '5.5.5.5', 443, 'unknown', { tls_host: 'x.example' }),
    session(now - 100, '10.0.0.2', '5.5.5.5', 2222, 'SSH'),
    '{"half": ',
  ].join('\n') + '\n')
  const r = await history(3600, { now, alertFile: path.join(d, 'none'), appidFile: af })
  const s = r.hosts['5.5.5.5'].appid
  assert.strictEqual(s.n, 2)
  assert.strictEqual(s.recent, 1)
  assert.deepStrictEqual(s.names, ['x.example'])
  assert.deepStrictEqual(s.services, [{ app: 'SSH', port: 2222, proto: 'TCP', count: 1 }])
  assert.deepStrictEqual(r.hosts['10.0.0.2'].appid.names, []) // client side gets no server name
})

test('eachLineBackwards keeps multi-byte characters intact across chunk boundaries', async () => {
  const f = path.join(dir(), 'x.txt')
  const lines = Array.from({ length: 3000 }, (_, i) => `${i} ääkköset € ${'ö'.repeat(i % 300)}`)
  fs.writeFileSync(f, lines.join('\n') + '\n')
  const got = []
  await eachLineBackwards(f, fs.statSync(f).size, 0, l => { got.push(l) })
  assert.deepStrictEqual(got.reverse(), lines)
})

test('eachLineBackwards ends when a chunk or the file starts with a newline', async () => {
  const d = dir()
  // 256 KiB chunks: the last chunk starts exactly at the '\n' after 'head1'
  const f = path.join(d, 'nl.txt')
  fs.writeFileSync(f, 'head1\n' + 'y'.repeat(256 * 1024 - 2) + '\n')
  const got = []
  await eachLineBackwards(f, fs.statSync(f).size, 0, l => { got.push(l.slice(0, 5)) })
  assert.deepStrictEqual(got, ['yyyyy', 'head1'])
  const g = path.join(d, 'lead.txt')
  fs.writeFileSync(g, '\n\na\n\nb\n')
  const out = []
  await eachLineBackwards(g, fs.statSync(g).size, 0, l => { out.push(l) })
  assert.deepStrictEqual(out, ['b', 'a'])
  const small = []
  await eachLineBackwards(g, fs.statSync(g).size, 2, l => { small.push(l) })
  assert.deepStrictEqual(small, ['b', 'a'])
})
