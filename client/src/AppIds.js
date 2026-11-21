import React, { useState, useEffect, useMemo } from 'react'
import io from 'socket.io-client'
import AppId from './AppId';
import { Panel, Status } from './Panel';
import { Section } from './overview/ui';
import { SOCKET, getJson } from './api';
import { fmtNum } from './overview/format';
import DomainMap, { kindColor } from './appid/DomainMap';
import HostRhythm from './appid/HostRhythm';
import { toSessions, hostStats, KINDS, KIND_LABEL } from './appid/appidModel';

const socket = io(SOCKET)
const KEEP = 40          // list rows shown
const MAX_EVENTS = 20000 // events kept in memory for the diagrams
const HISTORY = 6000     // lines read from appid.json on open (several lines per session)
const REFRESH = 2000     // live events are batched into the diagrams this often (ms)

const WINDOWS = [
  ['15m', '15 min', 15 * 60e3],
  ['1h', '1 h', 60 * 60e3],
  ['all', 'All loaded', Infinity],
]

// Lines the table can render; anything else (half-written, other shapes) is skipped.
const valid = e => e && typeof e === 'object' && e.pkt_time && e.apps && e.client_info && e.service_info
// AppID logs several lines per session; like before, one row per packet time.
const keyOf = e => `${e.pkt_time}|${e.session_num}`
const sessionKey = e => e.session_num + '|' + e.client_info.port

function AppIds() {
  const [events, setEvents] = useState(null) // null = history not loaded yet
  const [error, setError] = useState(null)
  const [connected, setConnected] = useState(socket.connected)
  const [win, setWin] = useState('1h')
  const [selected, setSelected] = useState(null)
  const [now, setNow] = useState(Date.now())

  useEffect(() => {
    let alive = true
    let buffer = []          // oldest first, numbered by `count`
    let count = 0
    let historyLoaded = false
    let dirty = false
    const pending = []       // live events that arrive before the history
    const seen = new Set()
    let lastTime = null

    const push = list => {
      // history and live stream can overlap while the history request is in flight
      list.filter(valid).forEach(e => {
        if (seen.has(keyOf(e)) || e.pkt_time === lastTime) return
        seen.add(keyOf(e))
        lastTime = e.pkt_time
        count += 1
        buffer.push({ ...e, count })
      })
      if (buffer.length > MAX_EVENTS) {
        buffer.slice(0, buffer.length - MAX_EVENTS).forEach(e => seen.delete(keyOf(e)))
        buffer = buffer.slice(-MAX_EVENTS)
      }
      dirty = true
    }
    const flush = () => { if (alive && dirty) { dirty = false; setEvents(buffer.slice()) } }

    getJson(`/appid/${HISTORY}`)
      .then(history => { if (alive) push(Array.isArray(history) ? history : []) })
      .catch(e => { if (alive) setError(e) })
      .finally(() => {
        historyLoaded = true
        if (pending.length) push(pending.splice(0))
        dirty = true
        flush()
      })

    const timer = setInterval(() => { flush(); if (alive) setNow(Date.now()) }, REFRESH)
    const onJson = data => (historyLoaded ? push([data]) : pending.push(data))
    const onConnect = () => setConnected(true)
    const onDisconnect = () => setConnected(false)
    socket.on('json', onJson)
    socket.on('connect', onConnect)
    socket.on('disconnect', onDisconnect)
    return () => {
      alive = false
      clearInterval(timer)
      socket.off('json', onJson)
      socket.off('connect', onConnect)
      socket.off('disconnect', onDisconnect)
    }
  }, [])

  const sessions = useMemo(() => toSessions(events || []), [events])
  const hostOf = useMemo(() => new Map(sessions.map(s => [s.key, s.host])), [sessions])

  // time window: ends now (or at the newest event if the sensor clock is ahead)
  const newest = sessions.length ? sessions[sessions.length - 1].t : now
  const to = Math.max(now, newest)
  const span = WINDOWS.find(w => w[0] === win)[2]
  const from = Number.isFinite(span) ? to - span : (sessions.length ? sessions[0].t : to - 60e3)
  const hosts = useMemo(() => hostStats(sessions, from, to), [sessions, from, to])
  const hostCount = useMemo(() => new Map(hosts.map(h => [h.host, h.count])), [hosts])
  const regular = hosts.filter(h => h.period).length

  const rows = useMemo(() => {
    if (!events) return null
    const out = []
    for (let i = events.length - 1; i >= 0 && out.length < KEEP; i--) {
      const e = events[i]
      if (!selected || hostOf.get(sessionKey(e)) === selected) out.push(e)
    }
    return out
  }, [events, selected, hostOf])

  const live = <span className={connected ? 'live live-on' : 'live'}>
    <span className="dot" />{connected ? 'live' : 'disconnected'}
  </span>

  const legend =
    <span className="appid-legend">
      {KINDS.map(k => <span key={k}><i className="swatch" style={{ background: kindColor(k) }} />{KIND_LABEL[k]}</span>)}
      <span><i className="am-orbit-swatch" />repeats on a steady rhythm</span>
    </span>

  return (
    <Panel title="AppID · sessions" accent="blue" right={live}
           description="What this machine talks to, from appid.json. Each host is a bubble grouped by its domain, and a row of ticks over time: hosts that come back again and again grow big and draw long tick lines; a steady rhythm (polling, keep-alives, beacons) gets a turning orbit and ↻. The newest events are listed below. New events stream in live.">
      {events === null
        ? <Status text="Loading AppID events…" />
        : events.length === 0
          ? (error
              ? <Status error={error} />
              : <div className="status">No AppID events in appid.json yet{connected ? ' — waiting for new ones.' : '.'}</div>)
          : <>
              {error && <div className="warn" style={{ marginBottom: 8 }}>Could not load history ({error.message}); showing live events only.</div>}
              <div className="ov-filters appid-filters">
                <div className="seg" role="tablist">
                  {WINDOWS.map(([id, label]) =>
                    <button key={id} type="button" role="tab" aria-selected={id === win}
                            className={id === win ? 'seg-on' : ''} onClick={() => setWin(id)}>{label}</button>)}
                </div>
                <span className="muted">
                  {fmtNum(hosts.reduce((a, h) => a + h.count, 0))} sessions · {fmtNum(hosts.length)} hosts
                  {regular > 0 && <> · {fmtNum(regular)} on a steady rhythm</>}
                </span>
                {selected &&
                  <button type="button" className="chip" onClick={() => setSelected(null)} title="Show all hosts">
                    host <strong>{selected}</strong> ✕
                  </button>}
                <span className="ov-filters-right">{legend}</span>
              </div>
              <div className="appid-viz">
                <Section title="Domain map" note="bubble area = sessions · grouped by domain">
                  <DomainMap hosts={hosts} now={now} selected={selected} onSelect={setSelected} />
                </Section>
                <Section title="Host rhythm" note="one tick per session · busiest hosts first">
                  <HostRhythm hosts={hosts} from={from} to={to} selected={selected} onSelect={setSelected} />
                </Section>
              </div>
              <Section title={selected ? `Latest events · ${selected}` : 'Latest events'}
                       note="×N = sessions with this host in the window; click it to focus the host">
                {rows.length === 0
                  ? <div className="viz-empty">No events for this host in memory.</div>
                  : <div className="table-wrap">
                      <table className="grid">
                        <thead>
                          <tr>
                            <th>#</th><th>Session</th><th>Packet time</th><th>Host</th><th>Service</th><th>Client</th>
                            <th>Proto</th><th>Client IP</th><th>Port</th><th>Service IP</th><th>Port</th>
                            <th>DNS host</th><th>TLS host</th>
                          </tr>
                        </thead>
                        <tbody>
                          {rows.map(e => {
                            const host = hostOf.get(sessionKey(e))
                            return <AppId key={e.count} json={e} host={host} seen={hostCount.get(host) || 0}
                                          max={hosts.length ? hosts[0].count : 1}
                                          onPick={() => setSelected(host === selected ? null : host)} />
                          })}
                        </tbody>
                      </table>
                    </div>}
              </Section>
            </>}
    </Panel>
  )
}

export default AppIds;
