import { render, screen, fireEvent } from '@testing-library/react';
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
  expect(tabs).toEqual(['Overview', 'Alerts', 'AppID', 'Search', 'Performance']);
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
  global.fetch = jest.fn(url => Promise.resolve({ ok: true, json: () => Promise.resolve(url.endsWith('/perf') ? perf : []) }));
  render(<App />);
  fireEvent.click(screen.getByRole('button', { name: 'Performance' }));
  expect(await screen.findByText('Packet drops')).toBeInTheDocument();
  expect(screen.getByText('0.86%')).toBeInTheDocument();     // 60 / 7000 dropped over the run
  expect(screen.getByText('now 100 pkt/s')).toBeInTheDocument(); // 6000 packets in 60 s
  expect(screen.getByText('TCP gaps')).toBeInTheDocument();
});
