import React, { useCallback, useEffect, useMemo, useState } from 'react'
import usePoll from '../usePoll'
import { Panel, Status, PriorityBadge } from '../Panel'
import { Section } from '../overview/ui'
import { fmtClock, fmtDay, fmtNum } from '../overview/format'
import { analyse, pickStep } from './anomaly'
import RuleHeatmap from './RuleHeatmap'
import { LiveList, HistoryList, FocusList, TextFilter } from './AlertList'
import useClearOnEmptyClick from '../useClearOnEmptyClick'

const WINDOWS = [
  { id: '1h', label: '1 h', seconds: 3600, refresh: 30000 },
  { id: '6h', label: '6 h', seconds: 6 * 3600, refresh: 60000 },
  { id: '24h', label: '24 h', seconds: 86400, refresh: 120000 },
]
const ROWS = 14

/** Same burst / cell selected: same rule and time span. */
const sameFocus = (a, b) => !!a && !!b && a.rule === b.rule && a.from === b.from && a.to === b.to
const EPISODES = 6

const span = (from, to) => {
  const day = fmtDay(from) !== fmtDay(Date.now() / 1000) ? fmtDay(from) + ' ' : ''
  return `${day}${fmtClock(from, false)}–${fmtClock(to, false)}`
}

const howUnusual = e => (e.expected < 0.5
  ? (e.isNew ? 'first time in this window' : 'normally silent')
  : `×${(e.count / e.expected).toFixed(e.count / e.expected < 10 ? 1 : 0)} the usual ~${fmtNum(Math.round(e.expected))}`)

const Episode = ({ e, active, onClick }) =>
  <button type="button" className={active ? 'episode episode-on' : 'episode'} onClick={onClick}>
    <div className="episode-head">
      <PriorityBadge p={e.priority} />
      <span className="episode-time">{span(e.from, e.to)}</span>
      {e.isNew && <span className="tag tag-new">new</span>}
    </div>
    <div className="episode-msg" title={e.msg}>{e.msg || e.rule}</div>
    <div className="episode-num"><strong>{fmtNum(e.count)}</strong> alerts · {howUnusual(e)}</div>
    {e.src.length > 0 &&
      <div className="episode-addr mono" title={e.src.map(([ip, n]) => `${ip} ×${n}`).join('\n')}>
        {e.src[0][0]}{e.dst.length > 0 ? ` → ${e.dst[0][0]}` : ''}
      </div>}
  </button>

function AlertsTab() {
  const [winId, setWinId] = useState('6h')
  const win = WINDOWS.find(w => w.id === winId)
  const [stats, reload] = usePoll(() => {
    const step = pickStep(win.seconds)
    const now = Date.now() / 1000
    const bins = Math.ceil(win.seconds / step)
    const until = (Math.floor(now / step) + 1) * step // current bin included, still filling
    const since = until - bins * step
    return { path: `/alerts_stats?since=${since}&until=${until}&step=${step}` }
  }, win.refresh, winId)
  const [focus, setFocus] = useState(null) // { rule, msg, priority, from, to }
  const [listMode, setListMode] = useState('live')
  const [text, setText] = useState('')
  const [textMode, setTextMode] = useState('include')
  const [allRules, setAllRules] = useState(false)
  const [liveStatus, setLiveStatus] = useState(null)

  const { rules, episodes } = useMemo(() => analyse(stats.data), [stats.data])
  const clearFocus = useCallback(() => { setFocus(null); setListMode('live') }, [])
  // clicking the selected burst or cell again clears the selection and returns to the live feed
  const pick = useCallback(f => {
    if (!f || sameFocus(f, focus)) return clearFocus()
    setFocus(f)
    setListMode('focus')
  }, [focus, clearFocus])
  // a click on empty space (or anything that is not a burst or cell) clears the selection
  useClearOnEmptyClick(focus !== null, clearFocus)
  // Esc clears the selection
  useEffect(() => {
    if (!focus) return
    const onKey = e => { if (e.key === 'Escape') clearFocus() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [focus, clearFocus])
  const d = stats.data

  const legend =
    <span className="hm-legend">
      <span><i className="hm-swatch" style={{ background: 'var(--hm-usual)' }} />as usual</span>
      <span className="hm-ramp" aria-hidden="true" />
      <span>×2 → ×32 the rule's normal</span>
      <span><i className="hm-swatch hm-swatch-unusual" />unusual</span>
    </span>

  return (
    <Panel title="Alerts" accent="teal"
           right={listMode === 'live' ? liveStatus : null}
           description="Which alerts are out of the ordinary. Every rule is compared with its own normal level in the window, so a steady flood stays calm while a burst — or a rule that is normally silent — stands out. Click a burst or a cell to list its alerts; the live feed and the history search are below.">
      <div className="ov-filters">
        <div className="seg" role="tablist" aria-label="Time window">
          {WINDOWS.map(w =>
            <button key={w.id} type="button" role="tab" aria-selected={w.id === winId}
                    className={w.id === winId ? 'seg-on' : ''} onClick={() => { setWinId(w.id); clearFocus() }}>{w.label}</button>)}
        </div>
        {d && <span className="muted">
          {fmtNum(d.total)} alerts · {fmtNum(rules.length)} rules · {Math.round(d.step / 60)} min columns
          {episodes.length > 0 && <> · <strong className="text-strong">{fmtNum(episodes.length)}</strong> unusual bursts</>}
        </span>}
        <span className="ov-filters-right">
          {stats.loading && <span className="muted">updating…</span>}
          <button type="button" className="btn" onClick={reload}>Refresh</button>
        </span>
      </div>

      {!d
        ? <Status error={stats.error} text="Counting alerts per rule…" />
        : <>
            {stats.error && <div className="warn">Could not refresh ({String(stats.error.message)}); showing the previous data.</div>}
            <Section title="Unusual bursts" note={episodes.length ? 'most unusual first · click to list the alerts' : null}>
              {episodes.length === 0
                ? <div className="viz-empty">Nothing out of the ordinary in this window: every rule stays near its normal level.</div>
                : <div className="episodes">
                    {episodes.slice(0, EPISODES).map(e =>
                      <Episode key={e.id} e={e}
                               active={sameFocus(focus, e)}
                               onClick={() => pick({ rule: e.rule, msg: e.msg, priority: e.priority, from: e.from, to: e.to })} />)}
                  </div>}
              {episodes.length > EPISODES &&
                <div className="card-note">{fmtNum(episodes.length - EPISODES)} more are outlined in the map below.</div>}
            </Section>
            <Section title="Rule map" note="each rule against its own normal · most unusual rules first" right={legend}>
              {rules.length === 0
                ? <div className="viz-empty">No alerts in this window.</div>
                : <>
                    <RuleHeatmap rules={rules} since={d.since} step={d.step} bins={d.bins}
                                 focus={focus} onFocus={pick} limit={allRules ? rules.length : ROWS} />
                    {rules.length > ROWS &&
                      <button type="button" className="link card-note" onClick={() => setAllRules(a => !a)}>
                        {allRules ? 'Show the most unusual rules only' : `Show all ${rules.length} rules (${rules.length - ROWS} quiet ones hidden)`}
                      </button>}
                  </>}
            </Section>
          </>}

      <Section title="Alert list"
               right={
                 <div className="seg" role="tablist" aria-label="Alert list">
                   <button type="button" role="tab" aria-selected={listMode === 'live'} className={listMode === 'live' ? 'seg-on' : ''}
                           onClick={clearFocus}>Live</button>
                   <button type="button" role="tab" aria-selected={listMode === 'history'} className={listMode === 'history' ? 'seg-on' : ''}
                           onClick={() => { setFocus(null); setListMode('history') }}>History search</button>
                   {focus &&
                     <button type="button" role="tab" aria-selected={listMode === 'focus'} className={listMode === 'focus' ? 'seg-on' : ''}
                             onClick={() => setListMode('focus')}>Selected burst</button>}
                 </div>}>
        <div className="toolbar toolbar-sub">
          <TextFilter text={text} mode={textMode} onText={setText} onMode={setTextMode} />
          {focus && listMode === 'focus' &&
            <button type="button" className="chip" onClick={clearFocus} title="Clear the selection and go back to the live feed (Esc)">
              <PriorityBadge p={focus.priority} /> <strong>{focus.msg || focus.rule}</strong> · {span(focus.from, focus.to)} ✕
            </button>}
        </div>
        {listMode === 'live' && <LiveList text={text} mode={textMode} onStatus={setLiveStatus} />}
        {listMode === 'history' && <HistoryList text={text} mode={textMode} />}
        {listMode === 'focus' && focus && <FocusList focus={focus} text={text} mode={textMode} />}
      </Section>
    </Panel>
  )
}

export default AlertsTab
