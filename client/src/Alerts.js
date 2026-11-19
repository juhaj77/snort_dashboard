import React, { useState, useEffect, useRef } from 'react'
import Alert, { AlertHeader } from './Alert';
import { Panel, Status, PriorityBadge } from './Panel';
import { getJson } from './api';

function Alerts() {
  const [alertsArray, setAlertsArray] = useState([])
  const [error, setError] = useState(null)
  const timeoutId = useRef(0)

  useEffect(() => {
    let alive = true
    const callServer = async () => {
      try {
        const data = await getJson('/alerts')
        if (!alive) return
        setAlertsArray(data.reverse())
        setError(null)
      } catch (e) {
        if (alive) setError(e)
      }
      if (alive) timeoutId.current = setTimeout(callServer, 5000)
    }
    callServer()
    return () => { alive = false; clearTimeout(timeoutId.current) }
  }, [])

  const legend = <div className="legend">
    {[1, 2, 3, 4].map(p => <PriorityBadge key={p} p={p} />)}
  </div>

  return (
    <Panel title="Alerts · latest" right={legend}
           description="The newest alerts from alert_json.txt, newest first. Refreshes every 5 seconds. Click a row for details and a Wireshark filter.">
      {alertsArray.length === 0
        ? <Status error={error} />
        : <div className="table-wrap">
            <table className="grid">
              <AlertHeader />
              <tbody>
                {alertsArray.map((e, i) => <Alert key={e.timestamp + i} json={e} />)}
              </tbody>
            </table>
          </div>}
    </Panel>
  )
}

export default Alerts;
