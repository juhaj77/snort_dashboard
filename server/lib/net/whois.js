// Who owns a public IP address: the network's holder from the regional internet registry
// (whois command) and the announcing autonomous system (Team Cymru IP-to-ASN, over DNS).
//
// Both are outside lookups: the address is sent to the registry's whois server and to
// Team Cymru's DNS servers. Private, link-local, loopback and multicast addresses are
// never looked up. Results are cached for a day; at most WHOIS_JOBS whois processes run
// at a time, because the registries rate-limit clients that ask too often.
const net = require('net')
const dns = require('dns').promises
const { execFile } = require('child_process')

const TTL_MS = 24 * 3600 * 1000
const WHOIS_JOBS = 2
const cache = new Map() // ip → { at, value }
let jobs = 0
const waiting = []

/** true for addresses that belong to a public network (worth a registry lookup) */
const isPublic = ip => {
  if (net.isIPv4(ip)) {
    const [a, b] = ip.split('.').map(Number)
    return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b < 128) ||
      (a === 169 && b === 254) || (a === 172 && b >= 16 && b < 32) || (a === 192 && b === 168))
  }
  if (!net.isIPv6(ip)) return false
  const v4 = ip.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/i)
  if (v4) return isPublic(v4[1])
  return /^[23]/.test(ip) && !/^2001:0?db8:/i.test(ip) // global unicast 2000::/3, not documentation
}

// ---------------------------------------------------------------------------
// whois text → fields. ARIN, RIPE, APNIC, AFRINIC and LACNIC all print "key: value" lines,
// with different keys. Blocks are separated by blank lines; with nested networks the most
// specific one comes last.

const NET_KEYS = /^(netrange|inetnum|inet6num|cidr)$/
const NAME_KEYS = ['org-name', 'orgname', 'owner', 'descr', 'organization', 'netname']

const blocksOf = text => String(text).split(/\r?\n\s*\r?\n/).map(b => {
  const f = []
  b.split(/\r?\n/).forEach(l => {
    if (/^\s*[%#]/.test(l)) return
    const m = l.match(/^([A-Za-z][\w-]*):\s*(.*)$/)
    if (m && m[2].trim()) f.push([m[1].toLowerCase(), m[2].trim()])
  })
  return f
}).filter(f => f.length)

const first = (fields, key) => { const x = fields.find(f => f[0] === key); return x ? x[1] : null }

/** Parsed whois answer: { name, netname, country, range, asn } (null fields when not given) */
const parseWhois = text => {
  const blocks = blocksOf(text)
  const nets = blocks.filter(b => b.some(f => NET_KEYS.test(f[0])))
  const netBlock = nets[nets.length - 1] || []
  const all = blocks.flat()
  // RIPE / APNIC / AFRINIC: the organisation object's org-name is the real holder
  let name = first(all, 'org-name')
  if (!name) for (const k of NAME_KEYS) { name = first(netBlock, k); if (name) break }
  if (name) name = name.replace(/\s*\([A-Z0-9-]+\)$/, '') // ARIN "Google LLC (GOOGL-2)"
  const range = first(netBlock, 'cidr') || first(netBlock, 'inet6num') || first(netBlock, 'inetnum') || first(netBlock, 'netrange')
  const asField = first(all, 'originas') || first(all, 'origin') || first(all, 'aut-num')
  const asn = asField && /\d/.test(asField) ? Number(asField.replace(/^AS/i, '').split(/[\s,]/)[0]) || null : null
  return {
    name: name || null,
    netname: first(netBlock, 'netname'),
    country: (first(netBlock, 'country') || first(all, 'country') || '').toUpperCase().slice(0, 2) || null,
    range: range ? range.split(',')[0].trim() : null,
    asn,
  }
}

// ---------------------------------------------------------------------------

// Some registries answer in Latin-1. The whois client may already have replaced those
// bytes with U+FFFD (valid UTF-8); then the text is kept as it is.
const decode = buf => {
  const s = buf.toString('utf8')
  const replaced = (s.match(/\uFFFD/g) || []).length
  const literal = (buf.toString('latin1').match(/\xEF\xBF\xBD/g) || []).length
  return replaced > literal ? buf.toString('latin1') : s
}

const slot = () => new Promise(resolve => {
  if (jobs < WHOIS_JOBS) { jobs += 1; resolve() } else waiting.push(resolve)
})
const release = () => { const next = waiting.shift(); if (next) next(); else jobs -= 1 }

const runWhois = async (bin, ip) => {
  await slot()
  try {
    return await new Promise(resolve => execFile(bin, [ip], { timeout: 15000, maxBuffer: 1024 * 1024, encoding: 'buffer' },
      (err, stdout) => resolve(err && !(stdout && stdout.length) ? null : decode(stdout || Buffer.alloc(0)))))
  } finally { release() }
}

const withTimeout = (p, ms) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error('timeout')), ms))])
const txt = async q => { try { return (await withTimeout(dns.resolveTxt(q), 4000)).map(r => r.join(''))[0] || null } catch (e) { return null } }

/** Reversed nibbles / octets for the Cymru origin zones */
const cymruName = ip => {
  if (net.isIPv4(ip)) return ip.split('.').reverse().join('.') + '.origin.asn.cymru.com'
  const parts = ip.split('::')
  const head = parts[0] ? parts[0].split(':') : []
  const tail = parts.length > 1 && parts[1] ? parts[1].split(':') : []
  const groups = [...head, ...Array(8 - head.length - tail.length).fill('0'), ...tail]
  return groups.map(g => g.padStart(4, '0')).join('').split('').reverse().join('.') + '.origin6.asn.cymru.com'
}

/** "15169 | 8.8.8.0/24 | US | arin | 2023-12-28" → { asn, prefix, country } */
const parseCymruOrigin = s => {
  if (!s) return null
  const f = s.split('|').map(x => x.trim())
  const asn = Number(String(f[0]).split(' ')[0])
  return asn ? { asn, prefix: f[1] || null, country: f[2] || null } : null
}
/** "15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US" → "GOOGLE - Google LLC, US" */
const parseCymruAs = s => (s ? s.split('|').map(x => x.trim())[4] || null : null)

const cymru = async (ip, asnHint) => {
  const origin = parseCymruOrigin(await txt(cymruName(ip)))
  const asn = (origin && origin.asn) || asnHint
  const asName = asn ? parseCymruAs(await txt(`AS${asn}.asn.cymru.com`)) : null
  return { asn: asn || null, asName, prefix: origin && origin.prefix, country: origin && origin.country }
}

/**
 * { ip, public, name, netname, country, range, asn, asName, sources, error }
 * whoisBin: path of the whois command, or null to use only the DNS lookup.
 */
const lookup = async (ip, whoisBin) => {
  if (!isPublic(ip)) return { ip, public: false }
  const c = cache.get(ip)
  if (c && Date.now() - c.at < TTL_MS) return c.value
  const text = whoisBin ? await runWhois(whoisBin, ip) : null
  const w = text ? parseWhois(text) : {}
  const cy = await cymru(ip, w.asn)
  // "GOOGLE - Google LLC, US" → "Google LLC": used when whois gave no readable name
  const asHolder = cy.asName ? cy.asName.replace(/^[^ ]+ - /, '').replace(/, [A-Z]{2}$/, '') : null
  const value = {
    ip, public: true,
    name: (w.name && !w.name.includes('\uFFFD') ? w.name : asHolder || w.name) || null,
    netname: w.netname || null,
    country: w.country || cy.country || null,
    range: w.range || cy.prefix || null,
    asn: cy.asn || w.asn || null,
    asName: cy.asName,
    sources: [text && 'whois', cy.asn && 'Team Cymru'].filter(Boolean),
    error: !text && !cy.asn ? (whoisBin ? 'no answer from whois or Team Cymru' : 'whois is not installed and Team Cymru did not answer') : null,
  }
  // do not keep a failure for a whole day
  if (!value.error) cache.set(ip, { at: Date.now(), value })
  if (cache.size > 5000) cache.delete(cache.keys().next().value)
  return value
}

module.exports = { lookup, isPublic, parseWhois, parseCymruOrigin, parseCymruAs, cymruName }
