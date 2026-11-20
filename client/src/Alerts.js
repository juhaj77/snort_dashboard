import React, { useState, useEffect, useRef, useCallback } from 'react'
import Alert, { AlertHeader } from './Alert';
import { Panel, Status, PriorityBadge } from './Panel';
import { getJson } from './api';

const REFRESH_MS = 5000
const keyOf = e => `${e.timestamp}|${e.pkt_num ?? ''}|${e.rule ?? ''}`

function Alerts() {
  const [alertsArray, setAlertsArray] = useState([])
  const [error, setError] = useState(null)
  const [openKey, setOpenKey] = useState(null)
  const [newCount, setNewCount] = useState(0)
  const timeoutId = useRef(0)
  const paused = useRef(false)   // details open: keep fetching, but don't replace the list
  const latest = useRef(null)    // newest fetched list while paused
  const shown = useRef([])
  const openRef = useRef(null)
  paused.current = openKey !== null
  shown.current = alertsArray

  const callServer = useRef(null)
  callServer.current = async () => {
    clearTimeout(timeoutId.current)
    try {
      const data = (await getJson('/alerts')).reverse()
      if (!callServer.alive) return
      setError(null)
      if (paused.current) {
        latest.current = data
        // how many of the fetched alerts are newer than the frozen list
        const seen = new Set(shown.current.map(keyOf))
        const fresh = data.filter(e => !seen.has(keyOf(e))).length
        setNewCount(fresh >= data.length ? `${fresh}+` : fresh)
      } else {
        latest.current = null
        setAlertsArray(data)
      }
    } catch (e) {
      if (callServer.alive) setError(e)
    }
    if (callServer.alive) timeoutId.current = setTimeout(() => callServer.current(), REFRESH_MS)
  }

  useEffect(() => {
    callServer.alive = true
    callServer.current()
    return () => { callServer.alive = false; clearTimeout(timeoutId.current) }
  }, [])

  const toggle = useCallback(key => {
    if (paused.current && openRef.current === key) {
      // closing: show what arrived meanwhile right away, then fetch fresh data
      paused.current = false
      openRef.current = null
      if (latest.current) setAlertsArray(latest.current)
      latest.current = null
      setNewCount(0)
      setOpenKey(null)
      callServer.current()
    } else {
      paused.current = true // before the next render, so a fetch in flight cannot move the row
      openRef.current = key
      setOpenKey(key)
    }
  }, [])

  const status = openKey !== null
    ? <span className="paused" role="status" title="Updates are paused while an alert is open so the row stays put. Close it to see the latest alerts.">
        <span className="paused-icon" aria-hidden="true" /> Paused{newCount ? ` · ${newCount} new` : ''}
      </span>
    : <span className="live live-on"><span className="dot" />live</span>
  const legend = <div className="legend">
    {status}
    {[1, 2, 3, 4].map(p => <PriorityBadge key={p} p={p} />)}
  </div>

  return (
    <Panel title="Alerts · latest" right={legend}
           description="The newest alerts from alert_json.txt, newest first. Refreshes every 5 seconds; updates pause while an alert's details are open. Click a row for details and a Wireshark filter.">
      {alertsArray.length === 0
        ? <Status error={error} />
        : <div className="table-wrap">
            <table className="grid">
              <AlertHeader />
              <tbody>
                {alertsArray.map((e, i) => {
                  const key = keyOf(e) + '#' + i
                  return <Alert key={key} json={e} open={openKey === key} onToggle={() => toggle(key)} />
                })}
              </tbody>
            </table>
          </div>}
    </Panel>
  )
}

export default Alerts;
