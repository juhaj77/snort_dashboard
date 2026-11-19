import React, { useState, useEffect } from 'react'
import io from 'socket.io-client'
import AppId from './AppId';
import { Panel, Status } from './Panel';
import { SOCKET, getJson } from './api';

const socket = io(SOCKET)
const KEEP = 40          // rows shown
const HISTORY = 400      // lines read from appid.json on open (several lines per session)

// Lines the table can render; anything else (half-written, other shapes) is skipped.
const valid = e => e && typeof e === 'object' && e.pkt_time && e.apps && e.client_info && e.service_info
// AppID logs several lines per session; like before, one row per packet time.
const keyOf = e => `${e.pkt_time}|${e.session_num}`

function AppIds() {
  const [rows, setRows] = useState(null) // null = history not loaded yet
  const [error, setError] = useState(null)
  const [connected, setConnected] = useState(socket.connected)

  useEffect(() => {
    let alive = true
    let buffer = []          // oldest first, numbered by `count`
    let count = 0
    let historyLoaded = false
    const pending = []       // live events that arrive before the history

    const push = list => {
      // history and live stream can overlap while the history request is in flight
      const seen = new Set(buffer.map(keyOf))
      let lastTime = buffer.length ? buffer[buffer.length - 1].pkt_time : null
      list.filter(valid).forEach(e => {
        if (seen.has(keyOf(e)) || e.pkt_time === lastTime) return
        seen.add(keyOf(e))
        lastTime = e.pkt_time
        count += 1
        buffer.push({ ...e, count })
      })
      if (buffer.length > KEEP) buffer = buffer.slice(-KEEP)
      if (alive) setRows([...buffer].reverse())
    }

    getJson(`/appid/${HISTORY}`)
      .then(history => { if (alive) push(Array.isArray(history) ? history : []) })
      .catch(e => { if (alive) { setError(e); setRows(r => r || []) } })
      .finally(() => { historyLoaded = true; if (pending.length) push(pending.splice(0)) })

    const onJson = data => (historyLoaded ? push([data]) : pending.push(data))
    const onConnect = () => setConnected(true)
    const onDisconnect = () => setConnected(false)
    socket.on('json', onJson)
    socket.on('connect', onConnect)
    socket.on('disconnect', onDisconnect)
    return () => {
      alive = false
      socket.off('json', onJson)
      socket.off('connect', onConnect)
      socket.off('disconnect', onDisconnect)
    }
  }, [])

  const live = <span className={connected ? 'live live-on' : 'live'}>
    <span className="dot" />{connected ? 'live' : 'disconnected'}
  </span>

  return (
    <Panel title="AppID · sessions" accent="blue" right={live}
           description="The latest application identification events from appid.json, newest first. New events stream in live as Snort writes them. Unknown services are tagged.">
      {rows === null
        ? <Status text="Loading AppID events…" />
        : rows.length === 0
          ? (error
              ? <Status error={error} />
              : <div className="status">No AppID events in appid.json yet{connected ? ' — waiting for new ones.' : '.'}</div>)
          : <>
              {error && <div className="warn" style={{ marginBottom: 8 }}>Could not load history ({error.message}); showing live events only.</div>}
              <div className="table-wrap">
                <table className="grid">
                  <thead>
                    <tr>
                      <th>#</th><th>Session</th><th>Packet time</th><th>Service</th><th>Client</th>
                      <th>Proto</th><th>Client IP</th><th>Port</th><th>Service IP</th><th>Port</th>
                      <th>DNS host</th><th>TLS host</th>
                    </tr>
                  </thead>
                  <tbody>
                    {rows.map(e => <AppId key={e.count} json={e} />)}
                  </tbody>
                </table>
              </div>
            </>}
    </Panel>
  )
}

export default AppIds;
