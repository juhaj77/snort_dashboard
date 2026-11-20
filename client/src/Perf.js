import React, { useEffect, useMemo, useRef, useState } from 'react'
import { Status } from './Panel'
import { getJson } from './api'
import { perfModel, sumCols, isGauge } from './perf/perfData'
import { TimeSeries, Sparkline, BarList } from './overview/charts'
import { Section, Kpi } from './overview/ui'
import { fmtNum, fmtClock, fmtDay, fmtSpan, fmtCompact, fmtBytes, fmtPct } from './overview/format'

const REFRESH_MS = 60000
const DROP_WARN_PCT = 1
const STALE_S = 15 * 60

const C1 = 'var(--s1)', C2 = 'var(--s2)', C3 = 'var(--s3)'
const POINTS = 600 // the server folds longer ranges into at most this many samples

export const RANGES = [
  ['1h', '1 h', 3600], ['6h', '6 h', 6 * 3600], ['24h', '24 h', 86400],
  ['7d', '7 d', 7 * 86400], ['30d', '30 d', 30 * 86400], ['run', 'Whole run', null],
]
const RANGE_KEY = 'perf.range'
const savedRange = () => {
  try { const v = localStorage.getItem(RANGE_KEY); return RANGES.some(r => r[0] === v) ? v : '24h' } catch (e) { return '24h' }
}

// Inspector activity: [column, label]. Only columns present in the CSV are shown.
const INSPECTORS = [
  ['appid.total_sessions', 'AppID sessions'],
  ['dns.requests', 'DNS requests'],
  ['dns.responses', 'DNS responses'],
  ['http_inspect.requests', 'HTTP requests'],
  ['ssl.client_hello', 'TLS client hellos'],
  ['ssl.handshakes_completed', 'TLS handshakes completed'],
  ['file_inspect.total_files', 'Files inspected'],
  ['ssh.packets', 'SSH packets'],
  ['smtp.packets', 'SMTP packets'],
  ['sip.packets', 'SIP packets'],
  ['dce_tcp.pdus', 'DCE/RPC PDUs'],
  ['arp_spoof.packets', 'ARP packets'],
]

// Counters that point at capture loss, evasion attempts or broken traffic.
// Labels stay close to the Snort counter; the raw name is shown too.
const HEALTH = [
  ['daq.dropped', 'Packets dropped by DAQ'],
  ['detection.alert_limit', 'Events over the alert limit'],
  ['stream_tcp.gaps', 'TCP gaps'],
  ['stream_tcp.overlaps', 'TCP overlapping segments'],
  ['stream_tcp.full_retransmits', 'TCP full retransmits'],
  ['stream_tcp.invalid_seq_left', 'TCP invalid seq (left)'],
  ['stream_tcp.invalid_seq_right', 'TCP invalid seq (right)'],
  ['stream_tcp.invalid_ack', 'TCP invalid ACKs'],
  ['stream_tcp.bad_syn_seq', 'TCP bad SYN seq'],
  ['stream_tcp.rsts_bad_seq', 'TCP RSTs, bad seq'],
  ['stream_tcp.asymmetric_flows', 'TCP asymmetric flows'],
  ['stream_ip.total_frags', 'IP fragments'],
  ['http_inspect.malformed_headers', 'HTTP malformed headers'],
  ['ssl.unrecognized_records', 'TLS unrecognized records'],
  ['ssl.alert', 'TLS alert records'],
]

/** The original table of every non-zero counter, now searchable and collapsed by default. */
const RawCounters = ({ model }) => {
  const [open, setOpen] = useState(false)
  const [q, setQ] = useState('')
  const keys = useMemo(() => model.nonZero(), [model])
  const shown = keys.filter(k => k.includes(q.trim()))
  return (
    <Section title="All counters" note={`${fmtNum(keys.length)} non-zero of ${fmtNum(model.cols.size)} · values per sample interval (gauges are instantaneous)`}
             right={<button type="button" className="btn" onClick={() => setOpen(!open)}>{open ? 'Hide' : 'Show'}</button>}>
      {open && <>
        <input className="input raw-search" placeholder="filter counters, e.g. stream_tcp" value={q} onChange={e => setQ(e.target.value)} />
        <div className="table-wrap">
          <table className="grid perf">
            <thead>
              <tr>
                <th className="sticky">counter</th>
                {model.t.map((s, i) => <th key={i} className="num">{fmtDay(s)} {fmtClock(s)}</th>)}
              </tr>
            </thead>
            <tbody>
              {shown.map(k =>
                <tr key={k} className="row">
                  <td className="sticky">{k}{isGauge(k) && <span className="scope">gauge</span>}</td>
                  {model.get(k).map((v, i) => <td key={i} className="mono num">{v === null ? '' : fmtNum(v)}</td>)}
                </tr>)}
            </tbody>
          </table>
        </div>
      </>}
    </Section>
  )
}

/** Old servers answer /perf?since with the whole run as an array: cut it here. */
const fromResponse = (res, since) => {
  if (!Array.isArray(res)) return res
  const [head, ...rows] = res
  const t = l => Number(String(l).split(',')[0])
  const first = rows.findIndex(l => t(l) >= since)
  const keep = first === -1 ? [] : rows.slice(Math.max(0, first - 1))
  return { lines: head ? [head, ...keep] : [], runStart: rows.length ? t(rows[0]) : null, runEnd: rows.length ? t(rows[rows.length - 1]) : null,
    rows: keep.length, bucketed: false, anchor: first > 0, step: null }
}

function Perf() {
  const [range, setRangeState] = useState(savedRange)
  const [state, setState] = useState({ data: null, error: null, loading: true, updated: null, range: null })
  const timer = useRef(0)
  const setRange = r => { setRangeState(r); try { localStorage.setItem(RANGE_KEY, r) } catch (e) { /* private mode */ } }

  const load = useRef(null)
  load.current = async () => {
    clearTimeout(timer.current)
    setState(s => ({ ...s, loading: true }))
    const secs = RANGES.find(r => r[0] === range)[2]
    const since = secs === null ? 0 : Math.floor(Date.now() / 1000) - secs
    try {
      const res = await getJson(`/perf?since=${since}&points=${POINTS}`)
      setState({ data: fromResponse(res, since), error: null, loading: false, updated: Date.now(), range })
    } catch (error) {
      setState(s => ({ ...s, error, loading: false }))
    }
    timer.current = setTimeout(() => load.current(), REFRESH_MS)
  }
  useEffect(() => {
    load.current()
    return () => clearTimeout(timer.current)
  }, [range])

  const d = state.data
  const m = useMemo(() => perfModel(d ? d.lines : null, { anchor: !!(d && d.anchor) }), [d])

  const rangeLabel = RANGES.find(r => r[0] === range)[1]
  const picker = <div className="seg" role="group" aria-label="Time range">
    {RANGES.map(([id, label]) => <button key={id} type="button" className={range === id ? 'seg-on' : ''} onClick={() => setRange(id)}>{label}</button>)}
  </div>

  if (!d) return <Status error={state.error} text="Loading perf_monitor data…" />
  const samples = m.n - (m.anchor ? 1 : 0)
  if (samples <= 0) {
    return <div className="ov">
      <div className="ov-filters">{picker}</div>
      <Section title="Performance">
        <div className="viz-empty">{d.runEnd
          ? <>No perf_monitor samples in the last {rangeLabel}. The newest sample of the current Snort run is from {fmtDay(d.runEnd)} {fmtClock(d.runEnd, false)} ({fmtSpan(Date.now() / 1000 - d.runEnd)} ago); pick a longer range.</>
          : <>No perf_monitor samples for the current Snort run yet. perf_monitor writes a sample once
            both its time (default 60 s) and packet (default 10,000) thresholds are reached.</>}</div>
      </Section>
    </div>
  }

  const t = m.t
  const now = Date.now() / 1000
  const last = t[m.n - 1]
  const first = t[m.anchor ? 1 : 0]
  const age = now - last
  const has = c => m.has(c)

  // headline numbers
  const recvTotal = m.total('daq.received')
  const dropTotal = m.total('daq.dropped')
  const dropPctRun = recvTotal > 0 && dropTotal !== null ? (dropTotal / recvTotal) * 100 : null
  const dropPct = m.ratio('daq.dropped', 'daq.received')
  const dropPctLatest = m.latestOf(dropPct)
  const dropWarn = (dropPctRun ?? 0) >= DROP_WARN_PCT || (dropPctLatest ?? 0) >= DROP_WARN_PCT
  const pps = m.rate('daq.received')
  const mbps = m.rate('daq.rx_bytes', 8 / 1e6)
  const alertsPerMin = m.rate('detection.alerts', 60)
  const flowsPerMin = m.rate('stream.flows', 60)
  const curFlows = m.get('stream.current_flows')
  const alertLimit = m.total('detection.alert_limit')

  // flows by transport, per minute
  const perMin = col => m.rate(col, 60)
  const flowSeries = [
    has('stream_tcp.sessions') && { key: 'tcp', label: 'TCP', color: C1, values: perMin('stream_tcp.sessions') },
    has('stream_udp.sessions') && { key: 'udp', label: 'UDP', color: C2, values: perMin('stream_udp.sessions') },
    (has('stream_icmp.sessions') || has('stream_ip.sessions')) && {
      key: 'other', label: 'ICMP + IP', color: C3,
      values: (() => {
        const sum = sumCols(m, ['stream_icmp.sessions', 'stream_ip.sessions'])
        return sum.map((v, i) => (i === 0 || !(m.intervals[i] > 0) ? null : (v / m.intervals[i]) * 60))
      })(),
    },
  ].filter(Boolean)

  const inspectorRows = INSPECTORS
    .filter(([c]) => has(c) && m.total(c) > 0)
    .map(([c, label]) => ({ key: label, total: m.total(c), col: c }))
    .sort((a, b) => b.total - a.total)

  const health = HEALTH.filter(([c]) => has(c))
  const healthHit = health.filter(([c]) => m.total(c) > 0)
  const healthZero = health.filter(([c]) => !(m.total(c) > 0))

  return (
    <div className={'ov' + (state.loading ? ' stale' : '')}>
      <div className="ov-filters">
        {picker}
        <span className="muted">
          <strong className="hl">{fmtNum(d.rows)}</strong> samples · {fmtDay(first)} {fmtClock(first, false)} – {fmtDay(last)} {fmtClock(last, false)}
          {d.bucketed && <> · averaged per {fmtSpan(d.step)}</>}
        </span>
        {d.runStart && <span className="muted" title="perf_monitor_base.csv starts a new header on every Snort start; only the current run is shown">
          run since {fmtDay(d.runStart)} {fmtClock(d.runStart, false)} ({fmtSpan(last - d.runStart)})</span>}
        {age > STALE_S
          ? <span className="warn" title="perf_monitor writes only after both its time and packet thresholds are reached; Snort may be idle or stopped.">
              ⚠ last sample {fmtSpan(age)} ago
            </span>
          : <span className="muted">last sample {fmtSpan(Math.max(0, age))} ago</span>}
        <span className="ov-filters-right">
          {state.error && <span className="err">refresh failed: {state.error.message}</span>}
          {state.updated && <span className="muted">updated {fmtClock(state.updated / 1000)}</span>}
          <button type="button" className="btn" onClick={() => load.current()}>Refresh</button>
        </span>
      </div>

      <div className="kpis kpis-6">
        <Kpi label="Packets" value={fmtCompact(recvTotal)} sub={`now ${fmtCompact(m.latestOf(pps))} pkt/s`} />
        <Kpi label="Traffic" value={fmtBytes(m.total('daq.rx_bytes'))} sub={`now ${fmtCompact(m.latestOf(mbps))} Mbit/s`} />
        <Kpi label="Dropped" status={dropWarn ? 'warn' : null}
             value={<>{dropWarn && <span aria-label="warning">⚠ </span>}{fmtPct(dropPctRun)}</>}
             sub={`${fmtCompact(dropTotal)} pkts · last interval ${fmtPct(dropPctLatest)}`} />
        <Kpi label="Alerts" value={fmtCompact(m.total('detection.alerts'))}
             sub={`now ${fmtCompact(m.latestOf(alertsPerMin))}/min` + (alertLimit ? ` · ${fmtCompact(alertLimit)} over limit` : '')} />
        <Kpi label="Active flows" value={curFlows ? fmtNum(m.latest('stream.current_flows')) : '—'}
             sub={curFlows ? `peak ${fmtNum(Math.max(...curFlows.filter(v => v !== null)))} in range` : 'not reported'} />
        <Kpi label="New flows" value={fmtCompact(m.total('stream.flows'))} sub={`now ${fmtCompact(m.latestOf(flowsPerMin))}/min`} />
      </div>

      <div className="perf-grid">
        <Section title="Packet rate" note="packets/s received, average per sample interval">
          <TimeSeries t={t} series={[{ key: 'pps', label: 'packets/s', color: 'var(--bar)', values: pps || [] }]} format={fmtCompact} />
        </Section>
        <Section title="Throughput" note="Mbit/s received">
          <TimeSeries t={t} series={[{ key: 'mbps', label: 'Mbit/s', color: 'var(--bar)', values: mbps || [] }]} format={fmtCompact} />
        </Section>
        <Section title="Packet drops" note={`dropped / received per interval · capture loss means Snort missed traffic`}
                 right={dropWarn && <span className="warn">⚠ above {DROP_WARN_PCT}%</span>}>
          <TimeSeries t={t} series={[{ key: 'drop', label: 'dropped %', color: 'var(--bar)', values: dropPct || [] }]} format={v => fmtPct(v)} />
        </Section>
        <Section title="Alerts" note="detection alerts per minute">
          <TimeSeries t={t} series={[{ key: 'apm', label: 'alerts/min', color: 'var(--bar)', values: alertsPerMin || [] }]} format={fmtCompact} />
        </Section>
        <Section title="New flows by transport" note="sessions per minute">
          {flowSeries.length
            ? <TimeSeries t={t} series={flowSeries} format={fmtCompact} />
            : <div className="viz-empty">Not reported by this Snort configuration.</div>}
        </Section>
        <Section title="Active flows" note="stream.current_flows at each sample">
          {curFlows
            ? <TimeSeries t={t} mode="line" series={[{ key: 'cur', label: 'active flows', color: 'var(--bar)', values: curFlows }]} format={fmtCompact} />
            : <div className="viz-empty">Not reported by this Snort configuration.</div>}
        </Section>
      </div>

      <div className="perf-grid">
        <Section title="Inspector activity" note={range === 'run' ? 'totals, whole run' : `totals, last ${rangeLabel}`}>
          <BarList rows={inspectorRows} renderMeta={(k, r) => <span className="muted mono raw-name">{r.col}</span>}
                   empty="No inspector activity reported." />
        </Section>
        <Section title="Traffic anomalies & capture health" note={`total in range · sparkline = rate per minute`}>
          {healthHit.length === 0 && <div className="viz-empty">None of the tracked anomaly counters moved in this range.</div>}
          <div className="health">
            {healthHit.map(([c, label]) =>
              <div key={c} className="health-row" title={c}>
                <span className="health-label">{label}<span className="muted mono raw-name">{c}</span></span>
                <Sparkline t={t} values={m.rate(c, 60)} color={c === 'daq.dropped' && dropWarn ? 'var(--p2)' : 'var(--bar)'} />
                <span className="health-total">{fmtNum(m.total(c))}</span>
              </div>)}
          </div>
          {healthZero.length > 0 &&
            <div className="card-note">Zero in this range: {healthZero.map(([, l]) => l).join(', ')}</div>}
        </Section>
      </div>

      <RawCounters model={m} />
    </div>
  )
}

export default Perf;
