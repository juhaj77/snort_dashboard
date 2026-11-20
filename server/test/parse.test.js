const test = require('node:test')
const assert = require('node:assert')
const P = require('../lib/net/parse')

test('splitHostPort handles IPv4, IPv6, wildcards, zones and mapped addresses', () => {
  assert.deepStrictEqual(P.splitHostPort('1.2.3.4:80'), { ip: '1.2.3.4', port: 80 })
  assert.deepStrictEqual(P.splitHostPort('[::1]:443'), { ip: '::1', port: 443 })
  assert.deepStrictEqual(P.splitHostPort('*:53'), { ip: '0.0.0.0', port: 53 })
  assert.deepStrictEqual(P.splitHostPort('127.0.0.53%lo:53'), { ip: '127.0.0.53', port: 53 })
  assert.deepStrictEqual(P.splitHostPort('[fe80::1]%eth0:546'), { ip: 'fe80::1', port: 546 })
  assert.deepStrictEqual(P.splitHostPort('[::ffff:10.0.0.2]:22'), { ip: '10.0.0.2', port: 22 })
  assert.deepStrictEqual(P.splitHostPort('0.0.0.0:*'), { ip: '0.0.0.0', port: null })
})

test('parseSs reads ss -tunapH', () => {
  const out = P.parseSs([
    'tcp ESTAB 0 0 192.168.1.217:59993 160.79.104.10:443 users:(("claude",pid=4084,fd=21))',
    'udp UNCONN 0 0 127.0.0.53%lo:53 0.0.0.0:*',
    'tcp LISTEN 0 511 *:9000 *:* users:(("node",pid=12,fd=3))',
    'garbage',
  ].join('\n'))
  assert.strictEqual(out.length, 3)
  assert.deepStrictEqual(out[0], { proto: 'TCP', state: 'ESTAB', localIp: '192.168.1.217', localPort: 59993, remoteIp: '160.79.104.10', remotePort: 443, pid: 4084, process: 'claude' })
  assert.strictEqual(out[1].pid, null)
  assert.strictEqual(out[2].localPort, 9000)
})

test('parseNetstatLinux reads net-tools netstat -tunapW', () => {
  const out = P.parseNetstatLinux([
    'Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name',
    'tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      812/sshd: /usr/sbin',
    'tcp        0      0 192.168.1.5:40000       93.184.216.34:443       ESTABLISHED 1234/firefox',
    'udp        0      0 0.0.0.0:68              0.0.0.0:*                           600/dhclient',
  ].join('\n'))
  assert.strictEqual(out.length, 3)
  assert.strictEqual(out[1].process, 'firefox')
  assert.strictEqual(out[1].remoteIp, '93.184.216.34')
  assert.strictEqual(out[2].state, 'UNCONN')
  assert.strictEqual(out[2].pid, 600)
})

test('parseNetstatWin reads netstat -ano with localised states', () => {
  const out = P.parseNetstatWin([
    '', 'Active Connections', '',
    '  Proto  Local Address          Foreign Address        State           PID',
    '  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1688',
    '  TCP    192.168.1.217:50123    20.42.65.92:443        MUODOSTETTU     4321',
    '  TCP    [::]:445               [::]:0                 LISTENING       4',
    '  UDP    0.0.0.0:5353           *:*                                    2400',
  ].join('\r\n'))
  assert.strictEqual(out.length, 4)
  assert.deepStrictEqual(out[1], { proto: 'TCP', state: 'MUODOSTETTU', localIp: '192.168.1.217', localPort: 50123, remoteIp: '20.42.65.92', remotePort: 443, pid: 4321, process: null })
  assert.strictEqual(out[2].localIp, '::')
  assert.strictEqual(out[3].pid, 2400)
  assert.strictEqual(out[3].state, 'UNCONN')
})

test('parseTasklist maps pid to image name', () => {
  const m = P.parseTasklist('"System","4","Services","0","29 528 K"\r\n"chrome.exe","9012","Console","1","120 000 K"\r\n')
  assert.strictEqual(m.get(9012), 'chrome.exe')
  assert.strictEqual(m.get(4), 'System')
})

test('parseArp reads Windows and net-tools output and drops broadcast/multicast', () => {
  const win = P.parseArp([
    'Interface: 192.168.1.217 --- 0xb',
    '  Internet Address      Physical Address      Type',
    '  192.168.1.1           44-d4-37-69-ad-d8     dynamic',
    '  192.168.1.255         ff-ff-ff-ff-ff-ff     static',
    '  224.0.0.22            01-00-5e-00-00-16     static',
  ].join('\r\n'))
  assert.deepStrictEqual(win, [{ ip: '192.168.1.1', mac: '44:d4:37:69:ad:d8', iface: '192.168.1.217', state: 'dynamic' }])
  const nix = P.parseArp('? (192.168.1.1) at 44:d4:37:69:ad:d8 [ether] on eth0\n? (192.168.1.9) at <incomplete> on eth0')
  assert.deepStrictEqual(nix, [{ ip: '192.168.1.1', mac: '44:d4:37:69:ad:d8', iface: 'eth0', state: null }])
})

test('parseIpNeighJson', () => {
  const out = P.parseIpNeighJson('[{"dst":"192.168.1.1","dev":"eth0","lladdr":"44:d4:37:69:ad:d8","state":["REACHABLE"]},{"dst":"x"}]')
  assert.deepStrictEqual(out, [{ ip: '192.168.1.1', mac: '44:d4:37:69:ad:d8', iface: 'eth0', state: 'REACHABLE' }])
  assert.deepStrictEqual(P.parseIpNeighJson('not json'), [])
})

test('parseTrace reads tracert and traceroute', () => {
  const win = P.parseTrace([
    'Tracing route to 8.8.8.8 over a maximum of 20 hops', '',
    '  1    <1 ms    <1 ms    <1 ms  192.168.1.1',
    '  2     *        *        *     Request timed out.',
    '  3    12 ms    11 ms    13 ms  8.8.8.8', '', 'Trace complete.',
  ].join('\r\n'))
  assert.deepStrictEqual(win, [
    { hop: 1, ip: '192.168.1.1', rtt: [1, 1, 1], lost: 0 },
    { hop: 2, ip: null, rtt: [], lost: 3 },
    { hop: 3, ip: '8.8.8.8', rtt: [12, 11, 13], lost: 0 },
  ])
  const nix = P.parseTrace('traceroute to 1.1.1.1 (1.1.1.1), 20 hops max\n 1  192.168.1.1  0.512 ms\n 2  *\n 3  1.1.1.1  9.8 ms')
  assert.deepStrictEqual(nix.map(h => [h.hop, h.ip, h.rtt]), [[1, '192.168.1.1', [0.512]], [2, null, []], [3, '1.1.1.1', [9.8]]])
})

test('parseNmapGrepable reads hosts, status and ports', () => {
  const out = P.parseNmapGrepable([
    '# Nmap 7.94 scan initiated',
    'Host: 192.168.1.1 (router.lan)\tStatus: Up',
    'Host: 192.168.1.1 (router.lan)\tPorts: 53/open/tcp//domain//dnsmasq 2.80/, 80/open/tcp//http//lighttpd/, 443/filtered/tcp//https///\tIgnored State: closed (97)',
    'Host: 192.168.1.20 ()\tStatus: Up',
  ].join('\n'))
  assert.strictEqual(out.length, 2)
  assert.strictEqual(out[0].name, 'router.lan')
  assert.deepStrictEqual(out[0].ports[0], { port: 53, state: 'open', proto: 'tcp', service: 'domain', version: 'dnsmasq 2.80' })
  assert.strictEqual(out[0].ports[2].state, 'filtered')
  assert.deepStrictEqual(out[1], { ip: '192.168.1.20', name: null, up: true, ports: [] })
})

test('parseTsharkNames maps DNS answers and TLS SNI to addresses', () => {
  assert.deepStrictEqual(P.parseTsharkNames('192.168.1.217\t\texample.com\t93.184.216.34,93.184.216.35\t\t'),
    [['93.184.216.34', 'example.com'], ['93.184.216.35', 'example.com']])
  assert.deepStrictEqual(P.parseTsharkNames('20.1.2.3\t\t\t\t\tlogin.example.net'), [['20.1.2.3', 'login.example.net']])
  assert.deepStrictEqual(P.parseTsharkNames(''), [])
})

test('isLocalTarget only allows own-network addresses', () => {
  ;['192.168.1.1', '10.0.0.5', '172.20.1.1', '169.254.1.1', 'fe80::1', 'fd00::5', '127.0.0.1'].forEach(ip =>
    assert.strictEqual(P.isLocalTarget(ip), true, ip))
  ;['8.8.8.8', '172.32.0.1', '224.0.0.1', '255.255.255.255', '2001:db8::1', 'x'].forEach(ip =>
    assert.strictEqual(P.isLocalTarget(ip), false, ip))
})
