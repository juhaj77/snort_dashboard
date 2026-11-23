const test = require('node:test')
const assert = require('node:assert')
const fs = require('fs')
const os = require('os')
const path = require('path')
const H = require('../lib/net/homeNet')

test('lastHomeNet takes the last assignment and ignores comments', () => {
  const lua = [
    "-- HOME_NET = '[1.2.3.0/24]'  (example in a comment)",
    "HOME_NET = '[10.0.0.0/8,fe80::/10]'",
    "--   HOME_NET = '[9.9.9.0/24]'",
    'HOME_NET = "[192.168.1.0/24, 2001:db8:1::/56]" -- local',
    "EXTERNAL_NET = '!$HOME_NET'",
  ].join('\n')
  assert.strictEqual(H.lastHomeNet(lua), '[192.168.1.0/24, 2001:db8:1::/56]')
  assert.strictEqual(H.lastHomeNet("EXTERNAL_NET = 'any'"), null)
})

test('parseNets splits a Snort ipvar list', () => {
  assert.deepStrictEqual(H.parseNets('[192.168.1.0/24, 2001:db8:1::/56]'), ['192.168.1.0/24', '2001:db8:1::/56'])
  assert.deepStrictEqual(H.parseNets('any'), [])
  assert.deepStrictEqual(H.parseNets('10.0.0.0/8'), ['10.0.0.0/8'])
})

test('read prefers local_net.lua over snort.lua', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'homenet-'))
  try {
    fs.writeFileSync(path.join(dir, 'snort.lua'), "HOME_NET = '[10.0.0.0/8]'\n")
    assert.deepStrictEqual(H.read(dir), { file: path.join(dir, 'snort.lua'), value: '[10.0.0.0/8]', nets: ['10.0.0.0/8'] })
    fs.writeFileSync(path.join(dir, 'local_net.lua'), "HOME_NET = '[192.168.1.0/24,2001:db8:1::/56]'\n")
    assert.deepStrictEqual(H.read(dir).nets, ['192.168.1.0/24', '2001:db8:1::/56'])
    assert.strictEqual(H.read(path.join(dir, 'missing')).value, null)
  } finally { fs.rmSync(dir, { recursive: true, force: true }) }
})
