import React, { useState, useEffect } from 'react'
import Alert, { AlertHeader } from './Alert';
import { Panel, Status } from './Panel';
import { getJson } from './api';

const DATE_HINT = 'YYYY-MM-DDTHH:mm:ss or MM/DD-HH:mm:ss'

function Search() {
  const [alertsArray, setAlertsArray] = useState([])
  const [alertsToShow, setAlertsToShow] = useState([])
  const [startString, setStartString] = useState('')
  const [endString, setEndString] = useState('')
  const [mode, setMode] = useState('search')
  const [filter, setFilter] = useState('')
  const [alerts, setAlerts] = useState(1000)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  const callServer = async (amount) => {
    setLoading(true)
    try {
      const data = await getJson(`/alerts_all/${amount}`)
      setAlertsArray(data)
      setAlertsToShow(data)
      setError(null)
    } catch (e) {
      setError(e)
    }
    setLoading(false)
  }

  useEffect(() => {
    callServer(alerts)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const sortAlerts = (sorter) => {
    const clone = [...alertsToShow]
    clone.sort((a, b) => a[sorter] > b[sorter] ? 1 : -1)
    setAlertsToShow(clone)
  }

  const parseDate = (str, now) => {
    if (str === '') return null
    let d = new Date(str)
    if (!isNaN(d)) {
      // Chrome parses dates without a year as 2001
      if (d.getUTCFullYear() === 2001) d.setUTCFullYear(now.getUTCFullYear())
      return d
    }
    const dt = str.split('-')
    const md = dt[0].split('/')
    d = new Date(now.getUTCFullYear() + '-' + md[0] + '-' + md[1] + 'T' + dt[1])
    return isNaN(d) ? null : d
  }

  const filterByDate = () => {
    setFilter('')
    const now = new Date()
    const d1 = parseDate(startString, now)
    const d2 = parseDate(endString, now)
    setAlertsToShow(alertsArray.filter(a =>
      (!d1 || a.seconds >= d1.getTime() / 1000) && (!d2 || a.seconds <= d2.getTime() / 1000)))
  }

  const filterAlerts = (str, mod) => {
    setFilter(str)
    setStartString('')
    setEndString('')
    const hit = a => a.msg.indexOf(str) !== -1 || a.class.indexOf(str) !== -1
    if (str === '') setAlertsToShow(alertsArray)
    else if (mod === 'search') setAlertsToShow(alertsArray.filter(hit))
    else setAlertsToShow(alertsArray.filter(a => !hit(a)))
  }

  const updateMode = (newMode) => {
    setMode(newMode)
    filterAlerts(filter, newMode)
  }

  const sortByRarity = () => {
    const byRule = alertsToShow.reduce((acc, a) => {
      (acc[a.rule] = acc[a.rule] || []).push(a)
      return acc
    }, {})
    const grouped = Object.values(byRule).sort((A, B) => A.length - B.length)
    setAlertsToShow(grouped.flat())
  }

  const handleAmount = str => {
    if (isNaN(str)) return
    setAlerts(str)
  }

  return (
    <Panel title="Search · alert history" accent="amber"
           description="Load the latest N alerts from alert_json.txt, then narrow them down by time or text. Click a column header to sort.">
      <div className="toolbar">
        <div className="field">
          <label>Load</label>
          <input className="input input-num" value={alerts}
                 onChange={e => handleAmount(e.target.value)}
                 onKeyDown={e => e.key === 'Enter' && callServer(alerts)} />
          <span className="muted">alerts</span>
          <button className="btn" onClick={() => callServer(alerts)}>Load</button>
        </div>
        <div className="divider" />
        <div className="field">
          <label>From</label>
          <input className="input input-date" placeholder={DATE_HINT} title={DATE_HINT}
                 value={startString} onChange={e => setStartString(e.target.value)} />
          <label>to</label>
          <input className="input input-date" placeholder={DATE_HINT} title={DATE_HINT}
                 value={endString} onChange={e => setEndString(e.target.value)} />
          <button className="btn" onClick={filterByDate}>Apply</button>
        </div>
        <div className="divider" />
        <div className="field field-grow">
          <select className="input" value={mode} onChange={e => updateMode(e.target.value)}>
            <option value="search">include</option>
            <option value="reject">exclude</option>
          </select>
          <input className="input input-grow" placeholder="message or classification contains…"
                 value={filter} onChange={e => filterAlerts(e.target.value, mode)} />
          <button className="btn" title="Group by rule, rarest first" onClick={sortByRarity}>Rarest first</button>
        </div>
      </div>
      <div className="result-count muted">
        {loading ? 'Loading…' : `${alertsToShow.length} of ${alertsArray.length} alerts`}
      </div>
      {alertsToShow.length === 0
        ? (loading || error
            ? <Status error={error} text="Loading alerts…" />
            : <div className="status">No alerts match the filter.</div>)
        : <div className="table-wrap">
            <table className="grid">
              <AlertHeader onSort={sortAlerts} />
              <tbody>
                {alertsToShow.map((e, i) => <Alert key={e.timestamp + i} json={e} />)}
              </tbody>
            </table>
          </div>}
    </Panel>
  )
}

export default Search;
