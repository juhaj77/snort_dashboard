import React, { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import Alert, { AlertHeader } from '../Alert'
import { Status } from '../Panel'
import { getJson } from '../api'

const keyOf = e => `${e.timestamp}|${e.pkt_num ?? ''}|${e.rule ?? ''}`

/** Case-insensitive text match on message, classification, rule and addresses. */
export const matchText = (a, text) => {
  if (!text) return true
  const t = text.toLowerCase()
  return [a.msg, a.class, a.rule, a.src_ap, a.dst_ap].some(v => typeof v === 'string' && v.toLowerCase().includes(t))
}
const textFilter = (list, text, mode) =>
  !text ? list : list.filter(a => (mode === 'include') === matchText(a, text))

/** Group by rule, rarest rule first (newest first inside a group). */
export const rarestFirst = list => {
  const byRule = new Map()
  list.forEach(a => {
    const k = a.rule || ''
    if (!byRule.has(k)) byRule.set(k, [])
    byRule.get(k).push(a)
  })
  return [...byRule.values()].sort((A, B) => A.length - B.length).flat()
}

const sortBy = (list, sort) => {
  if (!sort) return list
  if (sort === 'rarest') return rarestFirst(list)
  const { key, dir } = sort
  return [...list].sort((a, b) => (a[key] > b[key] ? dir : a[key] < b[key] ? -dir : 0))
}

const AlertTable = ({ alerts, onSort, openKey, onToggle, fresh }) =>
  <div className="table-wrap" data-keep-selection="">
    <table className="grid">
      <AlertHeader onSort={onSort} />
      <tbody>
        {alerts.map((e, i) => {
          const key = keyOf(e) + '#' + i
          return onToggle
            ? <Alert key={key} json={e} open={openKey === key} onToggle={() => onToggle(key)}
                     isNew={!!fresh && fresh.has(keyOf(e))} />
            : <Alert key={key} json={e} />
        })}
      </tbody>
    </table>
  </div>

const useSort = () => {
  const [sort, setSort] = useState(null)
  const onSort = useCallback(key =>
    setSort(s => (s && s.key === key ? { key, dir: -s.dir } : { key, dir: 1 })), [])
  return [sort, setSort, onSort]
}

/** Text filter shared by every list mode. */
export const TextFilter = ({ text, mode, onText, onMode }) =>
  <div className="field field-grow">
    <select className="input" value={mode} onChange={e => onMode(e.target.value)} aria-label="Filter mode">
      <option value="include">include</option>
      <option value="exclude">exclude</option>
    </select>
    <input className="input input-grow" placeholder="message, class, rule or address contains…"
           value={text} onChange={e => onText(e.target.value)} />
  </div>

// How often the live list moves. The server is asked at the same pace, but at least
// every POLL_MS, so the counter of waiting alerts stays current with slow paces.
// One /alerts call reads only the end of the file (~1 ms on the server), so 1 s is cheap.
export const RATES = [
  [1000, '1 s'],
  [2000, '2 s'],
  [5000, '5 s'],
  [15000, '15 s'],
  [30000, '30 s'],
  [60000, '1 min'],
  [0, 'manual'],
]
const POLL_MS = 5000
const RATE_KEY = 'snort.alerts.liveRate'
const loadRate = () => {
  try {
    const v = Number(window.localStorage.getItem(RATE_KEY))
    return RATES.some(([r]) => r === v) && window.localStorage.getItem(RATE_KEY) !== null ? v : 5000
  } catch (e) {
    return 5000
  }
}
const saveRate = v => { try { window.localStorage.setItem(RATE_KEY, String(v)) } catch (e) { /* private mode */ } }

/**
 * The newest alerts. The list moves at the chosen pace (or only on demand); alerts that
 * arrived with the last update are highlighted. While a row is open the list is frozen
 * so the row doesn't jump away; a counter shows what is waiting.
 */
export const LiveList = ({ text, mode, onStatus }) => {
  const [alertsArray, setAlertsArray] = useState([])
  const [fresh, setFresh] = useState(() => new Set()) // keys that came with the last update
  const [error, setError] = useState(null)
  const [openKey, setOpenKey] = useState(null)
  const [waiting, setWaiting] = useState(0)
  const [rate, setRateState] = useState(loadRate)
  const [sort, , onSort] = useSort()
  const timeoutId = useRef(0)
  const open = useRef(false)        // details open
  const rateRef = useRef(rate)
  const lastApplied = useRef(0)     // when the list last moved
  const latest = useRef(null)       // newest fetched list not shown yet
  const shown = useRef([])
  const openRef = useRef(null)
  open.current = openKey !== null
  rateRef.current = rate
  shown.current = alertsArray

  const apply = useCallback(data => {
    const before = new Set(shown.current.map(keyOf))
    // nothing is "new" on the first load
    setFresh(before.size ? new Set(data.map(keyOf).filter(k => !before.has(k))) : new Set())
    setAlertsArray(data)
    shown.current = data
    latest.current = null
    lastApplied.current = Date.now()
    setWaiting(0)
  }, [])

  const callServer = useRef(null)
  callServer.current = async () => {
    clearTimeout(timeoutId.current)
    try {
      const data = (await getJson('/alerts')).reverse()
      if (!callServer.alive) return
      setError(null)
      const r = rateRef.current
      // small slack so a poll that lands a moment early still counts as on time
      const due = shown.current.length === 0 || (r > 0 && Date.now() - lastApplied.current >= r * 0.9)
      if (!open.current && due) {
        apply(data)
      } else {
        latest.current = data
        const seen = new Set(shown.current.map(keyOf))
        const n = data.filter(e => !seen.has(keyOf(e))).length
        setWaiting(n >= data.length && shown.current.length ? `${n}+` : n)
      }
    } catch (e) {
      if (callServer.alive) setError(e)
    }
    if (callServer.alive) {
      const r = rateRef.current
      timeoutId.current = setTimeout(() => callServer.current(), r > 0 ? Math.min(r, POLL_MS) : POLL_MS)
    }
  }

  useEffect(() => {
    callServer.alive = true
    callServer.current()
    return () => { callServer.alive = false; clearTimeout(timeoutId.current) }
  }, [])

  const showNow = useCallback(() => {
    if (latest.current) apply(latest.current)
    else callServer.current()
  }, [apply])

  const setRate = v => {
    setRateState(v)
    rateRef.current = v
    saveRate(v)
    if (v > 0 && !open.current && latest.current) apply(latest.current)
    // a faster pace takes effect now, not after the poll already scheduled
    if (v > 0 && v < POLL_MS) callServer.current()
  }

  const toggle = useCallback(key => {
    if (open.current && openRef.current === key) {
      open.current = false
      openRef.current = null
      setOpenKey(null)
      // closing: catch up right away (unless updates are manual)
      if (rateRef.current > 0) showNow()
    } else {
      open.current = true // before the next render, so a fetch in flight cannot move the row
      openRef.current = key
      setOpenKey(key)
    }
  }, [showNow])

  const frozen = openKey !== null || rate === 0
  useEffect(() => {
    onStatus(frozen
      ? <span className="paused" role="status" title={openKey !== null
          ? 'Updates are paused while an alert is open so the row stays put. Close it to see the latest alerts.'
          : 'Manual updates: the list changes only when you click Show.'}>
          <span className="paused-icon" aria-hidden="true" /> Paused{waiting ? ` · ${waiting} new` : ''}
        </span>
      : <span className="live live-on"><span className="dot" />live</span>)
  }, [frozen, openKey, waiting, onStatus])

  const rows = useMemo(() => sortBy(textFilter(alertsArray, text, mode), sort), [alertsArray, text, mode, sort])
  if (alertsArray.length === 0) return <Status error={error} />
  return <>
    <div className="result-count live-bar">
      <span className="muted">{rows.length} of the newest {alertsArray.length} alerts · newest first</span>
      <label className="live-rate">
        <span className="muted">Update</span>
        <select className="input input-sm" value={rate} onChange={e => setRate(Number(e.target.value))}
                aria-label="Update the list every">
          {RATES.map(([v, label]) => <option key={v} value={v}>{v ? `every ${label}` : 'manually'}</option>)}
        </select>
      </label>
      {waiting !== 0 && openKey === null &&
        <button type="button" className="btn btn-sm" onClick={showNow} title="Show the waiting alerts now">
          Show {waiting} new
        </button>}
      {fresh.size > 0 && <span className="muted"><i className="new-swatch" /> {fresh.size} new in the last update</span>}
    </div>
    {rows.length === 0
      ? <div className="status">No alerts match the filter.</div>
      : <AlertTable alerts={rows} onSort={onSort} openKey={openKey} onToggle={toggle} fresh={fresh} />}
  </>
}

const DATE_HINT = 'YYYY-MM-DDTHH:mm:ss or MM/DD-HH:mm:ss'

/** "2026-11-21T10:00", "11/21-10:00:00" -> Date, or null. Dates without a year get this year. */
export const parseDate = (str, now = new Date()) => {
  if (!str) return null
  let d = new Date(str)
  if (!isNaN(d)) {
    if (d.getFullYear() === 2001 && !/2001/.test(str)) d.setFullYear(now.getFullYear()) // Chrome: no year -> 2001
    return d
  }
  const [md, time] = str.split('-')
  const [m, day] = (md || '').split('/')
  if (!m || !day || !time) return null
  d = new Date(`${now.getFullYear()}-${m.padStart(2, '0')}-${day.padStart(2, '0')}T${time}`)
  return isNaN(d) ? null : d
}

/** Load the latest N alerts and narrow them down by time, text, sort and rarity. */
export const HistoryList = ({ text, mode }) => {
  const [data, setData] = useState([])
  const [amount, setAmount] = useState(1000)
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [range, setRange] = useState({ d1: null, d2: null })
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [sort, setSort, onSort] = useSort()

  const load = useCallback(async n => {
    setLoading(true)
    try {
      setData(await getJson(`/alerts_all/${n}`))
      setError(null)
    } catch (e) {
      setError(e)
    }
    setLoading(false)
  }, [])
  useEffect(() => { load(1000) }, [load])

  const rows = useMemo(() => {
    const { d1, d2 } = range
    const inRange = data.filter(a =>
      (!d1 || a.seconds >= d1.getTime() / 1000) && (!d2 || a.seconds <= d2.getTime() / 1000))
    return sortBy(textFilter(inRange, text, mode), sort)
  }, [data, range, text, mode, sort])

  return <>
    <div className="toolbar toolbar-sub">
      <div className="field">
        <label>Load</label>
        <input className="input input-num" value={amount} aria-label="Number of alerts to load"
               onChange={e => !isNaN(e.target.value) && setAmount(e.target.value)}
               onKeyDown={e => e.key === 'Enter' && load(amount)} />
        <span className="muted">alerts</span>
        <button className="btn" onClick={() => load(amount)}>Load</button>
      </div>
      <div className="divider" />
      <div className="field">
        <label>From</label>
        <input className="input input-date" placeholder={DATE_HINT} title={DATE_HINT}
               value={from} onChange={e => setFrom(e.target.value)} />
        <label>to</label>
        <input className="input input-date" placeholder={DATE_HINT} title={DATE_HINT}
               value={to} onChange={e => setTo(e.target.value)} />
        <button className="btn" onClick={() => setRange({ d1: parseDate(from), d2: parseDate(to) })}>Apply</button>
      </div>
      <div className="divider" />
      <button className={sort === 'rarest' ? 'btn btn-on' : 'btn'} title="Group by rule, rarest first"
              onClick={() => setSort(s => (s === 'rarest' ? null : 'rarest'))}>Rarest first</button>
    </div>
    <div className="result-count muted">
      {loading ? 'Loading…' : `${rows.length} of ${data.length} alerts`}
    </div>
    {rows.length === 0
      ? (loading || error
          ? <Status error={error} text="Loading alerts…" />
          : <div className="status">No alerts match the filter.</div>)
      : <AlertTable alerts={rows} onSort={onSort} />}
  </>
}

const FOCUS_CAP = 2000

/** Alerts of one rule in one time span (a burst picked from the heatmap). */
export const FocusList = ({ focus, text, mode }) => {
  const [state, setState] = useState({ data: null, error: null })
  const [sort, , onSort] = useSort()
  useEffect(() => {
    let alive = true
    setState({ data: null, error: null })
    const q = `since=${focus.from}&until=${focus.to - 1e-6}` + (focus.rule ? `&rule=${encodeURIComponent(focus.rule)}` : '')
    getJson(`/alerts_all/${FOCUS_CAP}?${q}`)
      .then(data => alive && setState({ data: Array.isArray(data) ? data : [], error: null }))
      .catch(error => alive && setState({ data: [], error }))
    return () => { alive = false }
  }, [focus.from, focus.to, focus.rule])

  const rows = useMemo(() => sortBy(textFilter([...(state.data || [])].reverse(), text, mode), sort),
    [state.data, text, mode, sort])
  if (state.data === null) return <Status text="Loading the alerts of this burst…" />
  if (state.error) return <Status error={state.error} />
  return <>
    <div className="result-count muted">
      {rows.length} of {state.data.length} alerts{state.data.length >= FOCUS_CAP ? ` (newest ${FOCUS_CAP})` : ''} · newest first
    </div>
    {rows.length === 0
      ? <div className="status">No alerts match the filter.</div>
      : <AlertTable alerts={rows} onSort={onSort} />}
  </>
}
