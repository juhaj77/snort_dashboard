import React, { useCallback, useMemo, useState } from 'react'
import usePoll from '../usePoll'
import { PriorityBadge, Status } from '../Panel'
import { ActivityChart, BarList, SeverityBar, SwimLane } from './charts'
import EventDetails from './EventDetails'
import { Section, Kpi } from './ui'
import AppIdSummary from './AppIdSummary'
import {
  windowAlerts, timeBins, statsBins, pickStep, topN, severityCounts, distinctCount, addrScope,
} from './aggregate'
import { sevLabel } from './severity'
import { fmtClock, fmtDay, fmtNum, fmtSpan, fmtStep, hostPort } from './format'

// Time windows ask the server for alerts since a moment (`?since=`), capped at
// TIME_CAP alerts; the count window is the old "latest N" behaviour.
// The activity chart and the alert count come from the server's per-rule counts
// (/alerts_stats), which cover the whole window even when more than TIME_CAP alerts
// happened. A column outside the loaded alerts is fetched on its own when clicked.
const WINDOWS = [
  { id: '15m', label: '15 min', minutes: 15 },
  { id: '1h', label: '1 h', minutes: 60 },
  { id: '6h', label: '6 h', minutes: 360 },
  { id: '24h', label: '24 h', minutes: 1440 },
  { id: 'n5000', label: 'latest 5,000', count: 5000 },
]
const TIME_CAP = 20000
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

const ScopeTag = ({ ip }) => {
  const s = addrScope(ip)
  return s ? <span className="scope">{s}</span> : null
}

function Overview() {
  const [windowId, setWindowId] = useState('1h')
  const win = WINDOWS.find(w => w.id === windowId)
  const [alertsState, reloadAlerts] = usePoll(() => {
    if (win.count) return { path: `/alerts_all/${win.count}`, meta: { win } }
    const now = Math.floor(Date.now() / 1000)
    const since = now - win.minutes * 60
    // ask for one more than the cap so truncation can be detected
    return { path: `/alerts_all/${TIME_CAP + 1}?since=${since}`, meta: { win, since, now } }
  }, REFRESH_MS, windowId)
  const [statsState, reloadStats] = usePoll(() => {
    if (win.count) return null
    const span = win.minutes * 60
    const step = pickStep(span, 60)
    const until = (Math.floor(Date.now() / 1000 / step) + 1) * step // current bin included, still filling
    const bins = Math.ceil(span / step)
    return { path: `/alerts_stats?since=${until - bins * step}&until=${until}&step=${step}` }
  }, REFRESH_MS, windowId)
  const [appidState, reloadAppid] = usePoll(() => ({ path: '/appid/5000' }), REFRESH_MS, 'appid')
  const [focus, setFocus] = useState([]) // [{ field, value }]
  const [slice, setSlice] = useState(null) // { from, to } from the activity chart
  const [selected, setSelected] = useState(null)

  const meta = alertsState.meta || {}
  const { alerts, dropped, truncated } = useMemo(
    () => windowAlerts(alertsState.data, meta.since, TIME_CAP),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [alertsState.data])

  const toggleFocus = useCallback((field, value) => {
    setFocus(f => f.some(x => x.field === field && x.value === value)
      ? f.filter(x => !(x.field === field && x.value === value))
      : [...f.filter(x => x.field !== field), { field, value }])
  }, [])

  const dataRange = alerts.length ? [alerts[0].seconds, alerts[alerts.length - 1].seconds] : null
  // a clicked column older than the loaded alerts: load that interval by itself
  const sliceOutside = !!(slice && truncated && dataRange && slice.from < dataRange[0])
  const [sliceState] = usePoll(() => (sliceOutside
    ? { path: `/alerts_all/${TIME_CAP + 1}?since=${slice.from}&until=${slice.to}`, meta: { since: slice.from } }
    : null), REFRESH_MS, sliceOutside ? `${slice.from}-${slice.to}` : 'none')
  const sliceAlerts = useMemo(
    () => (sliceOutside && sliceState.data ? windowAlerts(sliceState.data, slice.from, TIME_CAP) : null),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [sliceOutside, sliceState.data])

  const matchFocus = useCallback(a => focus.every(f => FOCUS[f.field].get(a) === f.value), [focus])
  const focused = useMemo(() => alerts.filter(matchFocus), [alerts, matchFocus])
  const inView = useMemo(() => {
    if (!slice) return focused
    const base = sliceAlerts ? sliceAlerts.alerts.filter(matchFocus) : focused
    return base.filter(a => a.seconds >= slice.from && a.seconds < slice.to)
  }, [focused, slice, sliceAlerts, matchFocus])
  const sliceLoading = sliceOutside && !sliceAlerts
  // Time window: the axis spans the whole window (quiet periods stay visible),
  // except the part lost to truncation, which the data doesn't cover.
  const fullRange = meta.since !== undefined
    ? [truncated && dataRange ? dataRange[0] : meta.since, Math.max(meta.now, dataRange ? dataRange[1] : 0)]
    : dataRange || [0, 0]
  const fromStats = useMemo(() => (meta.since !== undefined ? statsBins(statsState.data, focus) : null),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [statsState.data, focus])
  const loadedBins = useMemo(() => timeBins(focused, 60, alerts.length ? fullRange : undefined),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [focused, alerts])
  const activity = fromStats || loadedBins
  // alerts in the whole window (all filters applied), when the server's counts can tell
  const windowTotal = fromStats ? fromStats.total : null
  const sliceTotal = fromStats && slice ? (fromStats.bins.find(b => b.t === slice.from) || {}).total ?? null : null

  const sev = useMemo(() => severityCounts(inView), [inView])
  const tops = useMemo(() => ({
    src: topN(inView, a => a.srcIp, 8),
    dst: topN(inView, a => a.dstIp, 8),
    rule: topN(inView, a => a.rule, 8),
    proto: topN(inView, a => a.proto, 8),
    dport: topN(inView, a => a.dstPort, 8),
    cls: topN(inView, a => a.cls, 8),
  }), [inView])

  // with the server's counts the alert total is exact even beyond the loaded alerts
  const alertCount = (slice ? sliceTotal : windowTotal) ?? inView.length
  const viewRange = inView.length ? [inView[0].seconds, inView[inView.length - 1].seconds] : fullRange
  // rate denominator: the selected interval, else the window, else the data's own span
  const span = slice ? slice.to - slice.from
    : meta.since !== undefined ? (windowTotal !== null ? meta.now - meta.since : fullRange[1] - fullRange[0])
      : viewRange[1] - viewRange[0]
  const timeline = inView.length > TIMELINE_CAP ? inView.slice(-TIMELINE_CAP) : inView
  const timelineRange = timeline.length ? [timeline[0].seconds, timeline[timeline.length - 1].seconds] : viewRange
  const recent = useMemo(() => inView.slice(-RECENT_ROWS).reverse(), [inView])

  const activeKey = field => (focus.find(f => f.field === field) || {}).value
  const pick = field => key => toggleFocus(field, key)
  const isFiltered = focus.length > 0 || slice

  const refresh = () => { reloadAlerts(); reloadStats(); reloadAppid() }

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
            <button key={w.id} type="button" className={w.id === windowId ? 'seg-on' : ''}
                    onClick={() => { setWindowId(w.id); setSlice(null) }}>
              {w.label}
            </button>)}
        </div>
        <span className="muted">
          {windowTotal !== null && !focus.length && windowTotal > 0
            ? <><strong className="hl">{fmtNum(windowTotal)}</strong> alerts · {fmtDay(meta.since)} {fmtClock(meta.since, false)} – {fmtClock(meta.now, false)}</>
            : alerts.length
            ? <><strong className="hl">{fmtNum(alerts.length)}</strong> alerts · {fmtDay(fullRange[0])} {fmtClock(fullRange[0], false)} – {fmtClock(fullRange[1], false)}
                {!meta.since && <> · covering <strong className="hl">{fmtSpan(fullRange[1] - fullRange[0])}</strong></>}</>
            : meta.since !== undefined ? `no alerts in the last ${win.label}` : 'no alerts in alert_json.txt'}
        </span>
        {truncated &&
          <span className="warn" title={`More than ${fmtNum(TIME_CAP)} alerts in this window. The activity chart and the alert count cover the whole window; the top lists, severity split and recent alerts use the newest ${fmtNum(TIME_CAP)}, unless you click an older column of the chart.`}>
            ⚠ lists use the newest {fmtNum(TIME_CAP)} ({fmtSpan(fullRange[1] - fullRange[0])} of {win.label})
          </span>}
        {sliceLoading && <span className="muted">loading {fmtClock(slice.from)} – {fmtClock(slice.to)}…</span>}
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
          <Kpi label={isFiltered ? 'Alerts in view' : 'Alerts'} value={fmtNum(alertCount)}
               sub={isFiltered ? (alertCount !== inView.length || windowTotal !== null ? `filtered, last ${win.label}` : `of ${fmtNum(alerts.length)} loaded`) : dropped ? `${fmtNum(dropped)} unreadable skipped` : meta.since !== undefined ? `last ${win.label}` : 'in window'} />
          <Kpi label="Rate" value={span > 0 ? (alertCount / (span / 60)).toFixed(1) : '—'} sub="alerts / min avg" />
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
      <Section title="Alert activity" note={activity.step ? `${fmtStep(activity.step)} intervals, stacked by severity${!fromStats && truncated ? ` · newest ${fmtNum(TIME_CAP)} alerts only (this filter is not in the server's counts)` : ''} · click a column to focus that interval` : null}>
        {(fromStats ? fromStats.total : focused.length)
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
