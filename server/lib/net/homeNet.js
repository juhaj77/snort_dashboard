// Snort's HOME_NET, read from the Lua config so the Network tab can tell whether this
// machine's internet provider IPv6 prefix is still inside it. Read-only.
//
// local_net.lua (loaded by the repository's snort.lua) overrides snort.lua, so it is read
// first. Only plain string assignments (HOME_NET = '[a,b,...]') are understood.
const fs = require('fs')
const path = require('path')

const CONF_DIR = process.env.SNORT_CONF_DIR || '/usr/local/etc/snort'
const FILES = ['local_net.lua', 'snort.lua']

/** Value of the last `HOME_NET = '...'` assignment outside comments, or null */
const lastHomeNet = text => {
  let value = null
  String(text).split(/\r?\n/).forEach(line => {
    const code = line.replace(/--.*$/, '')
    const m = code.match(/^\s*HOME_NET\s*=\s*(['"])(.*?)\1/)
    if (m) value = m[2].trim()
  })
  return value
}

/** '[10.0.0.0/8, fe80::/10]' → ['10.0.0.0/8', 'fe80::/10']; 'any' → [] */
const parseNets = value => {
  if (!value || value === 'any') return []
  return value.replace(/^\[|\]$/g, '').split(',').map(s => s.trim()).filter(Boolean)
}

const read = (dir = CONF_DIR) => {
  for (const f of FILES) {
    const file = path.join(dir, f)
    let text
    try { text = fs.readFileSync(file, 'utf8') } catch (e) { continue }
    const value = lastHomeNet(text)
    if (value !== null) return { file, value, nets: parseNets(value) }
  }
  return { file: null, dir, value: null, nets: [] }
}

module.exports = { read, lastHomeNet, parseNets }
