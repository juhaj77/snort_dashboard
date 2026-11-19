import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { getJson } from '../api'
import { PriorityBadge, Status } from '../Panel'
import { ActivityChart, BarList, SeverityBar, SwimLane } from './charts'
import EventDetails from './EventDetails'
import AppIdSummary from './AppIdSummary'
import {
  normalizeAlerts, timeBins, topN, severityCounts, distinctCount, addrScope,
} from './aggregate'
import { sevLabel } from './severity'
import { fmtClock, fmtDay, fmtNum, fmtSpan, fmtStep, hostPort } from './format'

const WINDOWS = [1000, 5000, 10000, 20000]
const REFRESH_MS = 60000
const TIMELINE_CAP = 3000
const RECENT_ROWS = 100

/** Dimensions the dashboard can be filtered on. Add new data fields here. */
const FOCUS = {
  sev: { label: 'Severity', get: a => a.priority, show: v => `P${v} ${sevLabel(v)}` },
  src: { label: 'Source', get: a => a.srcIp },
  dst: { label: 'Destination', get: a => a.dstIp },
  rule: { label: 'Rule', get: a => a.rule },
  proto: { label: 'Protocol', get: a => a.proto },
  dport: { label: 'Dst port', get: a => a.dstPort },
  cls: { label: 'Class', get: a => a.cls },
}

/** Poll a JSON endpoint; keeps the previous data while refetching. */
const usePoll = (path, intervalMs) => {
  const [state, setState] = useState({ data: null, error: null, loading: true, updated: null })
  const timer = useRef(0)
  const alive = useRef(true)
  const load = useCallback(async () => {
    clearTimeout(timer.current)
    setState(s => ({ ...s, loading: true }))
    try {
      const data = await getJson(path)
      if (alive.current) setState({ data, error: null, loading: false, updated: Date.now() })
    } catch (error) {
      if (alive.current) setState(s => ({ ...s, error, loading: false }))
    }
    if (alive.current) timer.current = setTimeout(load, intervalMs)
  }, [path, intervalMs])
  useEffect(() => {
    alive.current = true
    load()
    return () => { alive.current = false; clearTimeout(timer.current) }
  }, [load])
  return [state, load]
}

const Section = ({ title, note, right, className = '', children }) =>
  <section className={'card ' + className}>
    <header className="card-head">
      <h3>{title}</h3>
      {note && <span className="card-sub">{note}</span>}
      {right && <span className="card-right">{right}</span>}
    </header>
    {children}
  </section>

const Kpi = ({ label, value, sub }) =>
  <div className="kpi">
    <div className="kpi-label">{label}</div>
    <div className="kpi-value">{value}</div>
    {sub && <div className="kpi-sub">{sub}</div>}
  </div>

const ScopeTag = ({ ip }) => {
  const s = addrScope(ip)
  return s ? <span className="scope">{s}</span> : null
}

function Overview() {
  const [windowSize, setWindowSize] = useState(5000)
  const [alertsState, reloadAlerts] = usePoll(`/alerts_all/${windowSize}`, REFRESH_MS)
  const [appidState, reloadAppid] = usePoll('/appid/5000', REFRESH_MS)
  const [focus, setFocus] = useState([]) // [{ field, value }]
  const [slice, setSlice] = useState(null) // { from, to } from the activity chart
  const [selected, setSelected] = useState(null)

  const { alerts, dropped } = useMemo(() => normalizeAlerts(alertsState.data), [alertsState.data])

  const toggleFocus = useCallback((field, value) => {
    setFocus(f => f.some(x => x.field === field && x.value === value)
      ? f.filter(x => !(x.field === field && x.value === value))
      : [...f.filter(x => x.field !== field), { field, value }])
  }, [])

  const focused = useMemo(
    () => alerts.filter(a => focus.every(f => FOCUS[f.field].get(a) === f.value)),
    [alerts, focus])
  const inView = useMemo(
    () => (slice ? focused.filter(a => a.seconds >= slice.from && a.seconds < slice.to) : focused),
    [focused, slice])

  const fullRange = alerts.length ? [alerts[0].seconds, alerts[alerts.length - 1].seconds] : [0, 0]
  const activity = useMemo(() => timeBins(focused, 60, alerts.length ? fullRange : undefined),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [focused, alerts])

  const sev = useMemo(() => severityCounts(inView), [inView])
  const tops = useMemo(() => ({
    src: topN(inView, a => a.srcIp, 8),
    dst: topN(inView, a => a.dstIp, 8),
    rule: topN(inView, a => a.rule, 8),
    proto: topN(inView, a => a.proto, 8),
    dport: topN(inView, a => a.dstPort, 8),
    cls: topN(inView, a => a.cls, 8),
  }), [inView])

  const viewRange = inView.length ? [inView[0].seconds, inView[inView.length - 1].seconds] : fullRange
  const span = viewRange[1] - viewRange[0]
  const timeline = inView.length > TIMELINE_CAP ? inView.slice(-TIMELINE_CAP) : inView
  const timelineRange = timeline.length ? [timeline[0].seconds, timeline[timeline.length - 1].seconds] : viewRange
  const recent = useMemo(() => inView.slice(-RECENT_ROWS).reverse(), [inView])

  const activeKey = field => (focus.find(f => f.field === field) || {}).value
  const pick = field => key => toggleFocus(field, key)
  const isFiltered = focus.length > 0 || slice

  const refresh = () => { reloadAlerts(); reloadAppid() }

  if (!alertsState.data) {
    return <Status error={alertsState.error} text="Loading alerts…" />
  }

  const ruleMsg = key => (tops.rule.rows.find(r => r.key === key) || {}).sample?.msg

  return (
    <div className={'ov' + (alertsState.loading ? ' stale' : '')}>
      {/* ---- one filter row for everything below ---- */}
      <div className="ov-filters">
        <span className="muted">Window</span>
        <div className="seg">
          {WINDOWS.map(w =>
            <button key={w} type="button" className={w === windowSize ? 'seg-on' : ''}
                    onClick={() => { setWindowSize(w); setSlice(null) }}>
              last {fmtNum(w)}
            </button>)}
        </div>
        <span className="muted">
          {alerts.length
            ? <>alerts covering <strong className="hl">{fmtSpan(fullRange[1] - fullRange[0])}</strong> · {fmtDay(fullRange[0])} {fmtClock(fullRange[0], false)} – {fmtClock(fullRange[1], false)}</>
            : 'no alerts in alert_json.txt'}
        </span>
        {focus.map(f =>
          <button key={f.field} type="button" className="chip" onClick={() => toggleFocus(f.field, f.value)}>
            {FOCUS[f.field].label}: <strong>{FOCUS[f.field].show ? FOCUS[f.field].show(f.value) : String(f.value)}</strong> ×
          </button>)}
        {slice &&
          <button type="button" className="chip" onClick={() => setSlice(null)}>
            Time: <strong>{fmtClock(slice.from)} – {fmtClock(slice.to)}</strong> ×
          </button>}
        {isFiltered && <button type="button" className="link" onClick={() => { setFocus([]); setSlice(null) }}>clear all</button>}
        <span className="ov-filters-right">
          {alertsState.error && <span className="err">refresh failed: {alertsState.error.message}</span>}
          {alertsState.updated && <span className="muted">updated {fmtClock(alertsState.updated / 1000)}</span>}
          <button type="button" className="btn" onClick={refresh}>Refresh</button>
        </span>
      </div>

      {/* ---- headline numbers + severity split ---- */}
      <div className="ov-summary">
        <div className="kpis">
          <Kpi label={isFiltered ? 'Alerts in view' : 'Alerts'} value={fmtNum(inView.length)}
               sub={isFiltered ? `of ${fmtNum(alerts.length)} loaded` : dropped ? `${fmtNum(dropped)} unreadable skipped` : 'in window'} />
          <Kpi label="Rate" value={span > 0 ? (inView.length / (span / 60)).toFixed(1) : '—'} sub="alerts / min avg" />
          <Kpi label="Sources" value={fmtNum(distinctCount(inView, a => a.srcIp))} sub="distinct IPs" />
          <Kpi label="Destinations" value={fmtNum(distinctCount(inView, a => a.dstIp))} sub="distinct IPs" />
          <Kpi label="Signatures" value={fmtNum(tops.rule.distinct)} sub="distinct rules" />
        </div>
        <div className="ov-sev">
          <div className="kpi-label">Severity</div>
          <SeverityBar counts={sev} total={inView.length} activeSev={activeKey('sev')} onPick={p => toggleFocus('sev', p)} />
        </div>
      </div>

      {/* ---- activity over time ---- */}
      <Section title="Alert activity" note={activity.step ? `${fmtStep(activity.step)} intervals, stacked by severity · click a column to focus that interval` : null}>
        {focused.length
          ? <ActivityChart bins={activity.bins} step={activity.step} selectedT={slice ? slice.from : null}
                           onSelect={b => setSlice(b ? { from: b.t, to: b.t + activity.step } : null)} />
          : <div className="viz-empty">No alerts match the filters.</div>}
      </Section>

      {/* ---- who ---- */}
      <div className="ov-grid3">
        <Section title="Top sources" note="by alert count, split by severity">
          <BarList stacked rows={tops.src.rows} other={tops.src.other} missing={tops.src.missing}
                   missingLabel="without an IP (L2 / decoder alerts)"
                   onPick={pick('src')} activeKey={activeKey('src')}
                   renderLabel={k => <span className="mono">{k}</span>} renderMeta={k => <ScopeTag ip={k} />} />
        </Section>
        <Section title="Top destinations" note="by alert count, split by severity">
          <BarList stacked rows={tops.dst.rows} other={tops.dst.other} missing={tops.dst.missing}
                   missingLabel="without an IP (L2 / decoder alerts)"
                   onPick={pick('dst')} activeKey={activeKey('dst')}
                   renderLabel={k => <span className="mono">{k}</span>} renderMeta={k => <ScopeTag ip={k} />} />
        </Section>
        <Section title="Top signatures" note="rule gid:sid:rev">
          <BarList stacked rows={tops.rule.rows} other={tops.rule.other} missing={tops.rule.missing}
                   onPick={pick('rule')} activeKey={activeKey('rule')}
                   renderLabel={k => <><span className="mono rule-id">{k}</span><span className="rule-msg">{ruleMsg(k)}</span></>} />
        </Section>
      </div>

      {/* ---- what ---- */}
      <div className="ov-grid4">
        <Section title="Protocols" note="Snort proto field">
          <BarList rows={tops.proto.rows} other={tops.proto.other} missing={tops.proto.missing}
                   onPick={pick('proto')} activeKey={activeKey('proto')} />
        </Section>
        <Section title="Destination ports">
          <BarList rows={tops.dport.rows} other={tops.dport.other} missing={tops.dport.missing}
                   missingLabel="without a port"
                   onPick={pick('dport')} activeKey={activeKey('dport')}
                   renderLabel={k => <span className="mono">{k}</span>} />
        </Section>
        <Section title="Classification">
          <BarList rows={tops.cls.rows} other={tops.cls.other} missing={tops.cls.missing}
                   missingLabel="unclassified"
                   onPick={pick('cls')} activeKey={activeKey('cls')} />
        </Section>
        <Section title="AppID applications" note="appid.json · not affected by alert filters"
                 right={appidState.error && <span className="err">unavailable</span>}>
          {appidState.data
            ? <AppIdSummary events={appidState.data} />
            : <Status error={appidState.error} text="Loading AppID…" />}
        </Section>
      </div>

      {/* ---- events ---- */}
      <div className="ov-events">
        <div className="ov-events-main">
          <Section title="Event timeline"
                   note={inView.length > TIMELINE_CAP ? `latest ${fmtNum(TIMELINE_CAP)} of ${fmtNum(inView.length)} alerts in view` : `${fmtNum(inView.length)} alerts in view`}>
            {timeline.length
              ? <SwimLane alerts={timeline} range={timelineRange} selectedId={selected && selected.id} onSelect={setSelected} />
              : <div className="viz-empty">No alerts match the filters.</div>}
          </Section>
          <Section title="Recent events" note={`newest ${Math.min(RECENT_ROWS, inView.length)} in view`}>
            <div className="evlist">
              {recent.map(a =>
                <button key={a.id} type="button"
                        className={'ev prio prio-' + a.priority + (selected && a.id === selected.id ? ' ev-on' : '')}
                        onClick={() => setSelected(a)}>
                  <span className="mono muted ev-time">{fmtClock(a.seconds)}</span>
                  <PriorityBadge p={a.priority} />
                  <span className="ev-msg">{a.msg || '(no message)'}</span>
                  <span className="mono ev-addr">{hostPort(a.srcIp, a.srcPort)} → {hostPort(a.dstIp, a.dstPort)}</span>
                  <span className="ev-proto muted">{a.proto}</span>
                </button>)}
              {recent.length === 0 && <div className="viz-empty">No alerts match the filters.</div>}
            </div>
          </Section>
        </div>
        <Section title="Event details" className="ov-details">
          <EventDetails alert={selected} onFocus={toggleFocus} onClose={() => setSelected(null)} />
        </Section>
      </div>
    </div>
  )
}

export default Overview
