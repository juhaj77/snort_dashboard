import React, { useState, useEffect, useRef } from 'react'
import { Panel, Status } from './Panel';
import { getJson } from './api';

const parsePerf = (lines) => {
  const rows = lines.map(l => l.split(','))
  const header = rows[0]
  const out = {}
  header.forEach((name, i) => {
    const values = rows.slice(1).map(r => r[i]).filter(v => v !== undefined && v !== '' && !isNaN(v))
    // drop counters that never moved
    if (values.length > 0 && values.every(v => Number(v) === 0)) return
    out[name] = values
  })
  return out
}

const convertTime = (seconds) => {
  const date = new Date(seconds * 1000)
  const time = date.toTimeString().split(' ')
  return (date.getMonth() + 1) + '/' + date.getDate() + ' ' + time[0]
}

function Perf() {
  const [perfObject, setPerfObject] = useState({})
  const [error, setError] = useState(null)
  const timeoutId = useRef(-1)

  useEffect(() => {
    let alive = true
    const callServer = async () => {
      try {
        const lines = await getJson('/perf')
        if (!alive) return
        setPerfObject(lines.length > 1 ? parsePerf(lines) : {})
        setError(null)
      } catch (e) {
        if (alive) setError(e)
      }
      if (alive) timeoutId.current = setTimeout(callServer, 120000)
    }
    callServer()
    return () => { alive = false; clearTimeout(timeoutId.current) }
  }, [])

  const keys = Object.keys(perfObject).filter(k => k !== '#timestamp')
  const stamps = perfObject['#timestamp'] || []

  return (
    <Panel title="Performance · perf_monitor" accent="purple"
           description="Counters from the current Snort run (since the last header in perf_monitor_base.csv). Counters that stayed at zero are hidden. Refreshes every 2 minutes.">
      {stamps.length === 0
        ? <Status error={error} text="Waiting for the first perf_monitor sample…" />
        : <div className="table-wrap">
            <table className="grid perf">
              <thead>
                <tr>
                  <th className="sticky">counter</th>
                  {stamps.map((s, i) => <th key={i} className="num">{convertTime(s)}</th>)}
                </tr>
              </thead>
              <tbody>
                {keys.map(key =>
                  <tr key={key} className="row">
                    <td className="sticky">{key}</td>
                    {perfObject[key].map((v, i) => <td key={i} className="mono num">{v}</td>)}
                  </tr>)}
              </tbody>
            </table>
          </div>}
    </Panel>
  )
}

export default Perf;
