const test = require('node:test')
const assert = require('node:assert')
const W = require('../lib/net/whois')

const ARIN = `
# comment
NetRange:       2600:1900:: - 2600:190F:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF
CIDR:           2600:1900::/28
NetName:        GOOGLE-CLOUD
OriginAS:
Organization:   Google LLC (GOOGL-2)
Country:        US

OrgName:        Google LLC
OrgId:          GOOGL-2
Country:        US
`
const RIPE = `
% This is the RIPE Database query service.

inet6num:       2001:db9:1200::/40
netname:        EXAMPLE-BB-V6
descr:          Example Oyj
descr:          Broadband
country:        fi

route6:         2001:db9::/29
descr:          Example Oy
origin:         AS64500
`
const ARIN_NESTED = `
NetRange:       13.64.0.0 - 13.107.255.255
CIDR:           13.64.0.0/11, 13.96.0.0/13
NetName:        MSFT
Organization:   Microsoft Corporation (MSFT)
Country:        US

NetRange:       13.104.0.0 - 13.104.255.255
CIDR:           13.104.0.0/16
NetName:        CUSTOMER-NET
Organization:   Customer Inc (CUST-1)
Country:        CA
`

test('parseWhois reads ARIN, RIPE and nested answers', () => {
  assert.deepStrictEqual(W.parseWhois(ARIN), { name: 'Google LLC', netname: 'GOOGLE-CLOUD', country: 'US', range: '2600:1900::/28', asn: null })
  assert.deepStrictEqual(W.parseWhois(RIPE), { name: 'Example Oyj', netname: 'EXAMPLE-BB-V6', country: 'FI', range: '2001:db9:1200::/40', asn: 64500 })
  const n = W.parseWhois(ARIN_NESTED)
  assert.strictEqual(n.name, 'Customer Inc')
  assert.strictEqual(n.range, '13.104.0.0/16')
  assert.strictEqual(W.parseWhois('owner: NIC.BR\ninetnum: 200.160.0.0/20\naut-num: AS22548\ncountry: BR').name, 'NIC.BR')
})

test('Team Cymru names and answers', () => {
  assert.strictEqual(W.cymruName('8.8.4.1'), '1.4.8.8.origin.asn.cymru.com')
  assert.strictEqual(W.cymruName('2600:1900:8010:16d3::'),
    '0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.3.d.6.1.0.1.0.8.0.0.9.1.0.0.6.2.origin6.asn.cymru.com')
  assert.deepStrictEqual(W.parseCymruOrigin('15169 | 8.8.8.0/24 | US | arin | 2023-12-28'), { asn: 15169, prefix: '8.8.8.0/24', country: 'US' })
  assert.strictEqual(W.parseCymruAs('15169 | US | arin | 2000-03-30 | GOOGLE - Google LLC, US'), 'GOOGLE - Google LLC, US')
  assert.strictEqual(W.parseCymruOrigin(null), null)
})

test('only public addresses are looked up', async () => {
  for (const ip of ['192.168.1.1', '10.1.2.3', '172.20.0.1', '100.64.0.1', '169.254.1.1', '127.0.0.1', '224.0.0.251',
    'fe80::1', 'fd00::1', '::1', 'ff02::1', '2001:db8::1', '::ffff:192.168.1.1']) {
    assert.strictEqual(W.isPublic(ip), false, ip)
    assert.deepStrictEqual(await W.lookup(ip, null), { ip, public: false })
  }
  for (const ip of ['8.8.8.8', '172.32.0.1', '2600:1900::1', '::ffff:8.8.8.8']) assert.strictEqual(W.isPublic(ip), true, ip)
})
