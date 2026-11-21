import { render, screen, fireEvent, act, waitFor } from '@testing-library/react';
import App from './App';

jest.mock('socket.io-client', () => () => ({ on: jest.fn(), off: jest.fn(), connected: false }));

const alert = (i, over = {}) => ({
  timestamp: `11/19-18:00:${String(i).padStart(2, '0')}.000001`, seconds: Math.floor(Date.now() / 1000) - 600 + i,
  priority: i % 2 ? 3 : 1, proto: 'UDP', src_addr: '192.168.1.10', src_port: 5000 + i,
  dst_addr: '8.8.8.8', dst_port: 53, src_ap: `192.168.1.10:${5000 + i}`, dst_ap: '8.8.8.8:53',
  msg: i % 2 ? 'low thing' : 'bad thing', rule: i % 2 ? '1:2:1' : '1:3:1', class: 'Misc Attack',
  gid: 1, sid: i % 2 ? 2 : 3, rev: 1, pkt_num: i, ...over,
});

beforeEach(() => {
  const alerts = [...Array.from({ length: 10 }, (_, i) => alert(i)), { broken: true }];
  const appid = [{ session_num: '1', apps: { service: 'DNS', client: null, payload: null } }];
  global.fetch = jest.fn(url => Promise.resolve({
    ok: true,
    json: () => Promise.resolve(url.includes('/appid/') ? appid : url.includes('/alerts_all/') ? alerts : []),
  }));
});

test('renders the tabs with Overview first', async () => {
  render(<App />);
  await screen.findByText('Top sources');
  const tabs = screen.getAllByRole('button').filter(b => b.className.includes('tab')).map(b => b.textContent);
  expect(tabs).toEqual(['Overview', 'Network', 'Alerts', 'AppID', 'Search', 'Performance']);
});

test('overview summarises alerts, skips malformed records and shows event details', async () => {
  render(<App />);
  expect(await screen.findByText('Top sources')).toBeInTheDocument();
  expect(screen.getByText('1 unreadable skipped')).toBeInTheDocument();
  expect(screen.getAllByText('192.168.1.10').length).toBeGreaterThan(0);
  expect(await screen.findByText('DNS')).toBeInTheDocument();
  // default window is the last hour, requested from the server with ?since=
  const url = global.fetch.mock.calls.map(c => c[0]).find(u => u.includes('/alerts_all/'));
  const since = Number(new URL(url).searchParams.get('since'));
  expect(Math.abs(Date.now() / 1000 - 3600 - since)).toBeLessThan(5);

  fireEvent.click(screen.getAllByText('bad thing').map(e => e.closest('.ev')).find(Boolean));
  expect(screen.getByText('Find with Wireshark')).toBeInTheDocument();
  expect(screen.getAllByText('1:3:1').length).toBeGreaterThan(0);
});

test('overview shows an error when the server is unreachable', async () => {
  global.fetch = jest.fn(() => Promise.reject(new Error('Failed to fetch')));
  render(<App />);
  expect(await screen.findByText(/Could not load data from the server/)).toBeInTheDocument();
});

test('AppID tab shows existing events immediately instead of waiting for live data', async () => {
  const ev = (n, service) => ({
    session_num: `0.${n}`, pkt_time: `2026-11-19 18:16:0${n}.000001`, pkt_num: n, proto: 'TCP',
    apps: { service, client: null, payload: null },
    client_info: { ip: '192.168.1.5', port: 50000 + n }, service_info: { ip: '1.1.1.1', port: 443 },
    dns_host: null, tls_host: `host${n}.example`,
  });
  global.fetch = jest.fn(url => Promise.resolve({
    ok: true,
    json: () => Promise.resolve(url.includes('/appid/') ? [ev(1, 'HTTPS'), 'junk', ev(2, 'unknown')] : []),
  }));
  render(<App />);
  fireEvent.click(screen.getByRole('button', { name: 'AppID' }));
  expect(await screen.findByText('host2.example')).toBeInTheDocument();
  expect(screen.getByText('host1.example')).toBeInTheDocument();
  const hosts = screen.getAllByText(/host\d\.example/).map(e => e.textContent);
  expect(hosts).toEqual(['host2.example', 'host1.example']); // newest first
});

test('Performance tab summarises perf_monitor data', async () => {
  const perf = [
    '#timestamp,daq.received,daq.dropped,daq.rx_bytes,detection.alerts,stream.flows,stream.current_flows,stream_tcp.sessions,stream_tcp.gaps',
    '1000,1000,0,1000000,10,5,3,4,0',
    '1060,6000,60,6000000,30,12,7,9,2',
  ];
  global.fetch = jest.fn(url => Promise.resolve({ ok: true, json: () => Promise.resolve(url.includes('/perf?')
    ? { lines: perf, runStart: 1000, runEnd: 1060, rows: 2, bucketed: false, anchor: false, step: null } : []) }));
  render(<App />);
  fireEvent.click(screen.getByRole('button', { name: 'Performance' }));
  expect(await screen.findByText('Packet drops')).toBeInTheDocument();
  expect(screen.getByText('0.86%')).toBeInTheDocument();     // 60 / 7000 dropped over the run
  expect(screen.getByText('now 100 pkt/s')).toBeInTheDocument(); // 6000 packets in 60 s
  expect(screen.getByText('TCP gaps')).toBeInTheDocument();
});

test('Network tab draws hosts from the connection snapshot and shows details', async () => {
  const snap = {
    source: 'windows', at: 1, via: ['netstat -ano'], names: {},
    host: { name: 'pc', addrs: [{ ip: '192.168.1.217' }], gateway: '192.168.1.1' },
    connections: [{ proto: 'TCP', state: 'ESTABLISHED', localIp: '192.168.1.217', localPort: 50000, remoteIp: '20.1.2.3', remotePort: 443, pid: 10, process: 'chrome.exe', direction: 'out' }],
    listening: [{ proto: 'TCP', ip: '0.0.0.0', port: 135, process: 'svchost.exe' }],
    neighbors: [],
  };
  const info = { platform: 'wsl', sources: [{ id: 'windows', label: 'Windows host' }, { id: 'linux', label: 'WSL' }], tools: { traceroute: true, nmap: false }, wire: { iface: 'snort0' } };
  const now = Math.floor(Date.now() / 1000);
  const hist = w => ({
    window: w, since: now - w, until: now, bins: 30, step: w / 30, recent: 600,
    coverage: { alerts: { total: 3, from: now - w, files: ['alert_json.txt'] }, appid: { total: 0, from: null } },
    hosts: { '20.1.2.3': { alerts: { n: 3, sev: { 0: 0, 1: 3, 2: 0, 3: 0, 4: 0 }, first: now - 900, last: now - 60, recent: 2, bins: Array(30).fill(0).map((_, i) => (i === 29 ? 3 : 0)), sigs: [{ msg: 'Bad thing', priority: 1, count: 3, last: now - 60 }], sigCount: 1 } } },
  });
  try { localStorage.removeItem('net.window'); } catch (e) { /* ignore */ }
  global.fetch = jest.fn(url => Promise.resolve({
    ok: true,
    json: () => Promise.resolve(url.includes('/network/snapshot') ? snap : url.includes('/network/rdns/') ? { names: ['host.example'] }
      : url.includes('/network/history') ? hist(Number(url.split('window=')[1])) : url.endsWith('/network') ? info : []),
  }));
  const { unmount } = render(<App />);
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Network' })); });
  expect(await screen.findByText('Needs attention')).toBeInTheDocument();
  expect((await screen.findAllByText('P1 alerts')).length).toBeGreaterThan(0);
  expect(await screen.findByText('Connection map')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Windows host' })).toBeInTheDocument();
  await act(async () => { fireEvent.click(screen.getAllByText('20.1.2.3')[0].closest('tr')); });
  expect(await screen.findByText('host.example')).toBeInTheDocument();
  expect(screen.getByRole('button', { name: 'Port scan' })).toBeDisabled(); // no nmap
  expect(screen.getByRole('button', { name: 'Traceroute' })).toBeEnabled();
  expect(screen.getByText('TCP 135')).toBeInTheDocument();
  expect(screen.getByText('Why look at this host')).toBeInTheDocument();
  expect(screen.getAllByText(/Bad thing/).length).toBeGreaterThan(0);
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: '6 h' })); });
  await waitFor(() => expect(global.fetch.mock.calls.some(c => c[0].includes('/network/history?window=21600'))).toBe(true));
  expect(await screen.findByText('Snort alerts · last 6 hours')).toBeInTheDocument();
  unmount();
});

test('Performance range picker asks the server for that range', async () => {
  localStorage.removeItem('perf.range');
  const perf = ['#timestamp,daq.received', '1000,10', '1060,20'];
  global.fetch = jest.fn(() => Promise.resolve({ ok: true, json: () => Promise.resolve(
    { lines: perf, runStart: 1000, runEnd: 1060, rows: 2, bucketed: false, anchor: false, step: null }) }));
  render(<App />);
  fireEvent.click(screen.getByRole('button', { name: 'Performance' }));
  await screen.findByText('Packet rate');
  const sinceOf = () => Number(new URL(global.fetch.mock.calls.at(-1)[0]).searchParams.get('since'));
  expect(Date.now() / 1000 - sinceOf()).toBeCloseTo(86400, -1); // default 24 h
  fireEvent.click(screen.getByRole('button', { name: '7 d' }));
  await waitFor(() => expect(Date.now() / 1000 - sinceOf()).toBeCloseTo(7 * 86400, -1));
  await waitFor(() => expect(document.querySelector('.ov.stale')).toBeNull());
  fireEvent.click(screen.getByRole('button', { name: 'Whole run' }));
  await waitFor(() => expect(sinceOf()).toBe(0));
  await waitFor(() => expect(document.querySelector('.ov.stale')).toBeNull());
  expect(localStorage.getItem('perf.range')).toBe('run');
});

test('Alerts pause while details are open and catch up when closed', async () => {
  jest.useFakeTimers();
  let batch = [alert(1)];
  global.fetch = jest.fn(() => Promise.resolve({ ok: true, json: () => Promise.resolve([...batch]) }));
  const { unmount } = render(<App />);
  await act(async () => { fireEvent.click(screen.getByRole('button', { name: 'Alerts' })); });
  const row = (await screen.findByText(alert(1).timestamp)).closest('tr');
  fireEvent.click(row);
  expect(screen.getByRole('status')).toHaveTextContent('Paused');
  batch = [alert(1), alert(2)];
  await act(async () => { jest.advanceTimersByTime(5100); });
  expect(screen.getByRole('status')).toHaveTextContent('Paused · 1 new');
  expect(screen.queryByText(alert(2).timestamp)).toBeNull(); // list frozen, details still open
  expect(screen.getByText('Find with Wireshark')).toBeInTheDocument();
  fireEvent.click(row);
  expect(await screen.findByText(alert(2).timestamp)).toBeInTheDocument();
  expect(screen.queryByRole('status')).toBeNull();
  unmount();
  jest.useRealTimers();
});
