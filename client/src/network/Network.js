import React, { useEffect, useMemo, useRef, useState } from 'react'
import { Panel, PriorityBadge, Status } from '../Panel'
import { getJson } from '../api'
import usePoll from '../usePoll'
import { Section, Kpi } from '../overview/ui'
import { useWidth, tipPosition } from '../overview/charts'
import { fmtClock, fmtDateTime, fmtNum, fmtStep } from '../overview/format'
import {
  GROUP_BY, RULES, SCOPE_LABEL, attention, attentionCount, buildPeers, layout, matches, nodeColor, nodeRadius,
  portLabel, providerPrefixes, scopeOf, summary, topLevel,
} from './netModel'

const GRAPH_H = 620
// time window for the Snort and AppID history (the connection list is always "now")
const WINDOWS = [[3600, '1 h', 'last hour'], [21600, '6 h', 'last 6 hours'], [86400, '24 h', 'last 24 hours']]
const WINDOW_KEY = 'net.window'
const initialWindow = () => {
  try { const v = Number(localStorage.getItem(WINDOW_KEY)); if (WINDOWS.some(w => w[0] === v)) return v } catch (e) { /* storage off */ }
  return 3600
}
const winLabel = w => (WINDOWS.find(x => x[0] === w) || WINDOWS[0])
const levelColor = l => (l === 'high' ? 'var(--p1)' : l === 'warn' ? 'var(--amber)' : 'var(--purple)')

// ---------------------------------------------------------------------------
// Graph

const shortName = n => {
  const name = n.name || n.ip
  return name.length > 26 ? name.slice(0, 24) + '…' : name
}

const NetGraph = ({ host, peers, by, selected, onSelect, query, win }) => {
  const [wrapRef, width] = useWidth()
  const svgRef = useRef(null)
  const L = useMemo(() => layout(peers, by), [peers, by])
  const [view, setView] = useState(null) // { k, x, y }
  const [hover, setHover] = useState(null)
  const drag = useRef(null)

  // fit the bounding box of the drawing into the canvas
  const fit = useMemo(() => {
    if (!width) return null
    const b = L.box
    const k = Math.min(2, width / (b.x1 - b.x0), GRAPH_H / (b.y1 - b.y0))
    return { k, x: -((b.x0 + b.x1) / 2) * k, y: -((b.y0 + b.y1) / 2) * k }
  }, [width, L.box])
  // refit when the grouping changes; keep the user's zoom across data refreshes
  useEffect(() => { setView(null) }, [by])
  const v = view || fit

  useEffect(() => {
    const el = svgRef.current
    if (!el) return
    const onWheel = e => {
      e.preventDefault()
      const r = el.getBoundingClientRect()
      const mx = e.clientX - r.left - r.width / 2, my = e.clientY - r.top - GRAPH_H / 2
      setView(cur => {
        const c = cur || fit
        if (!c) return cur
        const k = Math.max(0.15, Math.min(6, c.k * (e.deltaY < 0 ? 1.15 : 1 / 1.15)))
        // keep the point under the cursor in place
        return { k, x: mx - ((mx - c.x) * k) / c.k, y: my - ((my - c.y) * k) / c.k }
      })
    }
    el.addEventListener('wheel', onWheel, { passive: false })
    return () => el.removeEventListener('wheel', onWheel)
  }, [fit])

  if (!width) return <div ref={wrapRef} className="net-graph" style={{ height: GRAPH_H }} />
  const sx = x => width / 2 + v.x + x * v.k
  const sy = y => GRAPH_H / 2 + v.y + y * v.k
  const sel = selected && L.nodes.find(p => p.n.ip === selected)
  const hubOf = new Map(L.hubs.map(h => [h.key, h]))
  const dim = q => q && query.trim() && !matches(q, query)

  const onDown = e => {
    if (e.target.closest('[data-node]')) return
    drag.current = { x: e.clientX, y: e.clientY, v, moved: false }
    e.currentTarget.setPointerCapture(e.pointerId)
  }
  const onMove = e => {
    const d = drag.current
    if (!d) return
    const dx = e.clientX - d.x, dy = e.clientY - d.y
    if (Math.abs(dx) + Math.abs(dy) > 3) d.moved = true
    setView({ ...d.v, x: d.v.x + dx, y: d.v.y + dy })
  }
  const onUp = () => {
    const d = drag.current
    drag.current = null
    if (d && !d.moved) onSelect(null)
  }

  const labelFor = p => {
    const show = p.n.ip === selected || p.n.ip === hover?.n.ip || (query.trim() && matches(p.n, query)) ||
      (v.k > 1.4) || (L.nodes.length <= 24) || topLevel(p.n) === 3 || p.n.gateway
    if (!show) return null
    const right = Math.cos(p.a) >= 0
    const r = nodeRadius(p.n) * Math.min(1.6, Math.max(0.8, v.k)) + 4
    return <text x={sx(p.x) + (right ? r : -r)} y={sy(p.y) + 3.5} textAnchor={right ? 'start' : 'end'}
                 className={'net-label' + (p.n.ip === selected ? ' net-label-on' : '')}>{p.n.gateway ? 'gateway · ' : ''}{shortName(p.n)}</text>
  }

  const scale = Math.min(1.6, Math.max(0.8, v.k))
  return (
    <div ref={wrapRef} className="net-graph" style={{ height: GRAPH_H }}>
      <svg ref={svgRef} width={width} height={GRAPH_H} className="net-svg"
           onPointerDown={onDown} onPointerMove={onMove} onPointerUp={onUp} onPointerLeave={() => { drag.current = null }}
           role="img" aria-label={`Connection graph of ${peers.length} hosts`}>
        {/* rings */}
        {[150, 245].map(r => <circle key={r} cx={sx(0)} cy={sy(0)} r={r * v.k} className="net-ring" />)}
        {/* centre → hub */}
        {L.hubs.map(h => <line key={'h' + h.key} x1={sx(0)} y1={sy(0)} x2={sx(h.x)} y2={sy(h.y)} className="net-edge-hub" />)}
        {/* hub → node */}
        {L.nodes.map(p => {
          const h = hubOf.get(p.hub)
          const on = p.n.ip === selected
          const alerted = p.n.maxSev !== null
          return <line key={'e' + p.n.ip} x1={sx(h.x)} y1={sy(h.y)} x2={sx(p.x)} y2={sy(p.y)}
                       className={'net-edge' + (on ? ' net-edge-on' : '') + (dim(p.n) ? ' net-dim' : '')}
                       style={alerted ? { stroke: nodeColor(p.n), strokeOpacity: on ? 1 : 0.55 } : undefined} />
        })}
        {sel && <line x1={sx(0)} y1={sy(0)} x2={sx(hubOf.get(sel.hub).x)} y2={sy(hubOf.get(sel.hub).y)} className="net-edge-on" />}
        {/* hubs */}
        {L.hubs.map(h => {
          const right = Math.cos(h.a) >= 0
          return <g key={'g' + h.key} className="net-hub">
            <rect x={sx(h.x) - 5} y={sy(h.y) - 5} width={10} height={10} rx={2} transform={`rotate(45 ${sx(h.x)} ${sy(h.y)})`} />
            <text x={sx(h.x) + (right ? 10 : -10)} y={sy(h.y) - 8} textAnchor={right ? 'start' : 'end'}>
              {h.key.length > 22 ? h.key.slice(0, 21) + '…' : h.key} <tspan className="net-hub-count">{h.count}</tspan>
            </text>
          </g>
        })}
        {/* nodes */}
        {L.nodes.map(p => {
          const n = p.n
          const r = nodeRadius(n) * scale
          const on = n.ip === selected
          const color = nodeColor(n)
          return <g key={n.ip} data-node className={'net-node' + (dim(n) ? ' net-dim' : '')}
                    onPointerEnter={() => setHover(p)} onPointerLeave={() => setHover(null)}
                    onClick={() => onSelect(on ? null : n.ip)}>
            <circle cx={sx(p.x)} cy={sy(p.y)} r={r + 7} className="net-hit" />
            {n.inbound > 0 && <circle cx={sx(p.x)} cy={sy(p.y)} r={r + 3} className="net-in" />}
            {n.signals.some(x => x.id === 'new') && <circle cx={sx(p.x)} cy={sy(p.y)} r={r + 6} className="net-new" />}
            <circle cx={sx(p.x)} cy={sy(p.y)} r={r}
                    style={n.live || n.neighbor ? { fill: color } : { fill: 'var(--surface)', stroke: color, strokeWidth: 1.5 }}
                    className={'net-dot' + (on ? ' net-dot-on' : '')} />
            {attentionCount(n) > 0 && <g className="net-badge" transform={`translate(${sx(p.x) + r * 0.8 + 3} ${sy(p.y) - r * 0.8 - 3})`}>
              <circle r={6.5} style={{ fill: topLevel(n) === 3 ? 'var(--p1)' : 'var(--amber)' }} />
              <text y={3} textAnchor="middle">{attentionCount(n)}</text>
            </g>}
          </g>
        })}
        {L.nodes.map(p => <React.Fragment key={'l' + p.n.ip}>{labelFor(p)}</React.Fragment>)}
        {/* this machine */}
        <g className="net-center">
          <circle cx={sx(0)} cy={sy(0)} r={13} />
          <text x={sx(0)} y={sy(0) + 30} textAnchor="middle">{host || 'this machine'}</text>
        </g>
      </svg>
      {hover && !drag.current && <NodeTip p={hover} x={sx(hover.x)} y={sy(hover.y)} width={width} win={win} />}
      <div className="net-zoom">
        <button type="button" className="btn" aria-label="Zoom in" onClick={() => setView(c => ({ ...(c || fit), k: Math.min(6, (c || fit).k * 1.3) }))}>+</button>
        <button type="button" className="btn" aria-label="Zoom out" onClick={() => setView(c => ({ ...(c || fit), k: Math.max(0.15, (c || fit).k / 1.3) }))}>−</button>
        <button type="button" className="btn" onClick={() => setView(null)}>Fit</button>
      </div>
      {peers.length === 0 && <div className="net-empty">No remote hosts with the current filters.</div>}
    </div>
  )
}

const NodeTip = ({ p, x, y, width, win }) => {
  const n = p.n
  const w = 260
  return (
    <div className="viz-tip net-tip" style={{ ...tipPosition(x, y, width, w, 14), width: w }}>
      <div className="tip-msg mono">{n.ip}</div>
      {n.name && <div className="tip-head">{n.name}</div>}
      <div className="tip-row"><strong>{n.conns.length}</strong><span>open connections{n.inbound ? ` (${n.inbound} inbound)` : ''}</span></div>
      {n.process && <div className="tip-row"><strong /><span>{[...n.processes.keys()].slice(0, 3).join(', ')}</span></div>}
      {n.port !== null && <div className="tip-row"><strong /><span>port {portLabel(n.port)}</span></div>}
      {n.alertCount > 0 && <div className="tip-row"><strong>{fmtNum(n.alertCount)}</strong><span>Snort alerts ({win})</span></div>}
      {n.app && <div className="tip-row"><strong /><span>AppID: {[...n.appid.keys()].slice(0, 3).join(', ')}</span></div>}
      {n.signals.map(x => <div key={x.id} className="tip-row"><strong><i className="swatch" style={{ background: levelColor(x.level) }} /></strong><span>{x.label}</span></div>)}
      <div className="tip-foot">{SCOPE_LABEL[n.scope]}{n.live ? '' : ' · no open connection'} · click for details</div>
    </div>
  )
}

// The internet provider's IPv6 prefix of this machine, and whether Snort's HOME_NET still
// covers it. Providers change the prefix now and then; HOME_NET has to follow by hand.
const providerNote = (addrs, homeNet) => {
  const list = providerPrefixes(addrs, (homeNet && homeNet.nets) || [])
  if (!list.length) return null
  const names = list.map(p => p.prefix).join(', ')
  const file = homeNet && homeNet.file
  if (!homeNet) {
    return <div className="muted">Provider IPv6 prefix {names} · the server does not report Snort's HOME_NET yet. Restart the server to check the prefix against it.</div>
  }
  if (homeNet.value === null) {
    return <div className="muted">Provider IPv6 prefix {names} · Snort's HOME_NET was not found in {homeNet.dir}, so it is not checked.</div>
  }
  if (homeNet.value === 'any') {
    return <div className="muted">Provider IPv6 prefix {names} · Snort's HOME_NET is 'any' ({file}). Set it to your networks, including this prefix; see snort/snort.lua.</div>
  }
  const missing = list.filter(p => !p.inHomeNet)
  if (!missing.length) {
    return <div className="muted" title={`HOME_NET = ${homeNet.value}`}>Provider IPv6 prefix {names} · inside Snort's HOME_NET ({file})</div>
  }
  return (
    <div className="warn">
      Provider IPv6 prefix {missing.map(p => p.prefix).join(', ')} is not inside Snort's HOME_NET ({homeNet.value}).
      The internet provider has probably changed it: update HOME_NET in {file} and restart Snort (sudo systemctl restart snort).
    </div>
  )
}

const Legend = () =>
  <div className="net-legend">
    <span><i className="sw" style={{ background: 'var(--teal)' }} />Internet</span>
    <span><i className="sw" style={{ background: 'var(--blue)' }} />Local network</span>
    <span><i className="sw" style={{ background: 'var(--p1)' }} />P1</span>
    <span><i className="sw" style={{ background: 'var(--p2)' }} />P2</span>
    <span><i className="sw" style={{ background: 'var(--p3)' }} />P3</span>
    <span><i className="sw" style={{ background: 'var(--p4)' }} />P4 alert</span>
    <span><i className="sw sw-hollow" />seen by Snort/AppID, no open connection</span>
    <span><i className="sw sw-ring" />inbound connection</span>
    <span><i className="sw sw-hub" />group</span>
    <span><i className="sw-badge" style={{ background: 'var(--p1)' }}>1</i><i className="sw-badge" style={{ background: 'var(--amber)' }}>2</i>signals to check (see Needs attention)</span>
    <span><i className="sw sw-new" />new in the logs</span>
    <span className="muted">size = connections + alerts · scroll to zoom, drag to pan</span>
  </div>

// ---------------------------------------------------------------------------
// Details panel

const Row = ({ k, children }) => <div className="nd-row"><span>{k}</span><div>{children}</div></div>

const TraceResult = ({ r }) => {
  if (r.loading) return <Status text="Tracing… (up to a minute)" />
  if (r.error && !(r.hops || []).length) return <div className="err">{r.error}</div>
  const max = Math.max(1, ...r.hops.flatMap(h => h.rtt))
  return (
    <div className="trace">
      {r.hops.map(h => {
        const avg = h.rtt.length ? h.rtt.reduce((s, x) => s + x, 0) / h.rtt.length : null
        return <div key={h.hop} className="trace-hop">
          <span className="trace-n">{h.hop}</span>
          <span className="mono trace-ip">{h.ip || <span className="muted">no reply</span>}</span>
          <span className="trace-bar">{avg !== null && <span style={{ width: `${Math.max(3, (avg / max) * 100)}%` }} />}</span>
          <span className="trace-ms">{avg !== null ? `${avg < 10 ? avg.toFixed(1) : Math.round(avg)} ms` : '—'}</span>
        </div>
      })}
      {r.note && <div className="card-note">{r.note}</div>}
      <div className="card-note">{r.tool}: routers on the way, round-trip time per hop. "No reply" hops drop probes but still forward traffic.</div>
    </div>
  )
}

const ScanResult = ({ r }) => {
  if (r.loading) return <Status text="Scanning the 100 most common ports… (up to 2 min)" />
  if (r.error && !(r.ports || []).length) return <div className="err">{r.error}</div>
  const open = r.ports.filter(p => p.state !== 'closed')
  return (
    <div>
      {open.length === 0 ? <div className="muted">No open ports among the 100 most common.</div> :
        <table className="grid nd-table">
          <thead><tr><th>Port</th><th>State</th><th>Service</th></tr></thead>
          <tbody>{open.map(p => <tr key={p.proto + p.port}>
            <td className="mono">{p.port}/{p.proto}</td><td>{p.state}</td>
            <td>{p.service || '—'}{p.version && <div className="muted">{p.version}</div>}</td>
          </tr>)}</tbody>
        </table>}
      <div className="card-note">nmap -sV -F: service names and versions as nmap identifies them.</div>
    </div>
  )
}

// Count per time bin over the window, one small bar chart per measure
const Activity = ({ title, h, hist, unit }) => {
  const [ref, width] = useWidth()
  const [hover, setHover] = useState(null)
  const H = 34
  const bins = (h && h.bins) || []
  const n = bins.length || hist.bins
  const band = width / n
  const bw = Math.max(1, band - 2) // 2px surface gap between bars
  const max = Math.max(1, ...bins)
  const t0 = i => hist.since + i * hist.step
  const total = bins.reduce((a, b) => a + b, 0)
  return (
    <div className="nd-act">
      <div className="nd-act-head"><span>{title}</span>
        <span className="muted">{hover !== null ? `${fmtClock(t0(hover), false)}–${fmtClock(t0(hover + 1), false)} · ${fmtNum(bins[hover] || 0)} ${unit}` : `${fmtNum(total)} · max ${fmtNum(max === 1 && !total ? 0 : max)} per ${fmtStep(Math.round(hist.step / 60) * 60)}`}</span></div>
      <div ref={ref} className="nd-act-plot" onMouseLeave={() => setHover(null)}>
        {width > 0 && <svg width={width} height={H} role="img" aria-label={`${title}: ${total} in the window`}>
          <line x1={0} x2={width} y1={H - 0.5} y2={H - 0.5} className="viz-base" />
          {bins.map((v, i) => {
            const bh = v ? Math.max(2, (v / max) * (H - 2)) : 0
            return <g key={i} onMouseEnter={() => setHover(i)}>
              <rect x={i * band} y={0} width={band} height={H} fill="transparent" />
              {bh > 0 && <rect x={i * band + 1} y={H - bh} width={bw} height={bh} rx={Math.min(2, bw / 2)} className={hover === i ? 'nd-act-bar on' : 'nd-act-bar'} />}
            </g>
          })}
        </svg>}
      </div>
    </div>
  )
}

const Signals = ({ n, win }) => (
  <>
    <div className="nd-sec">Why look at this host</div>
    {n.signals.length === 0 ? <div className="muted">Nothing flagged by the rules below in the {win}.</div> :
      <ul className="nd-signals">{n.signals.map(x => <li key={x.id}>
        <span className="sig-tag" style={{ '--sc': levelColor(x.level) }}>{x.label}</span>
        <span>{x.detail}</span>
      </li>)}</ul>}
  </>
)

const OwnerRows = ({ w, whoisTool }) => {
  if (!w) return <Row k="Owner"><span className="muted">looking up…</span></Row>
  if (w.public === false) return null
  if (w.error && !w.name && !w.asn) {
    return <Row k="Owner"><span className="muted">{w.error}{whoisTool === false ? ' · see NETWORK.md' : ''}</span></Row>
  }
  return <>
    <Row k="Owner">{w.name || <span className="muted">unknown</span>}{w.country && <span className="muted"> · {w.country}</span>}
      {(w.netname || w.range) && <div className="muted mono">{[w.netname, w.range].filter(Boolean).join(' · ')}</div>}</Row>
    {w.asn && <Row k="AS"><span className="mono">AS{w.asn}</span>{w.asName && <span className="muted"> · {w.asName}</span>}</Row>}
  </>
}

const Details = ({ n, info, source, results, run, onClose, hist, win }) => {
  const [rdns, setRdns] = useState({})
  // the panel scrolls on its own; start a newly selected host from the top
  const boxRef = useRef(null)
  const ip = n ? n.ip : null
  useEffect(() => { if (boxRef.current) boxRef.current.scrollTop = 0 }, [ip])
  useEffect(() => {
    if (!n) return
    n.addrs.filter(ip => !(ip in rdns)).slice(0, 4).forEach(ip => {
      setRdns(s => (ip in s ? s : { ...s, [ip]: null }))
      getJson('/network/rdns/' + encodeURIComponent(ip))
        .then(r => setRdns(s => ({ ...s, [ip]: r.names || [] })), () => setRdns(s => ({ ...s, [ip]: [] })))
    })
  }, [n, rdns])
  // network owner of public addresses (whois / Team Cymru); one lookup per device is enough
  const [owner, setOwner] = useState({})
  const ownerIp = n ? n.addrs.find(a => scopeOf(a) === 'internet') : null
  useEffect(() => {
    if (!ownerIp || ownerIp in owner) return
    setOwner(s => ({ ...s, [ownerIp]: null }))
    getJson('/network/whois/' + encodeURIComponent(ownerIp))
      .then(r => setOwner(s => ({ ...s, [ownerIp]: r })), e => setOwner(s => ({ ...s, [ownerIp]: { error: 'lookup failed (' + e.message + '); restart the server if it is older than this page' } })))
  }, [ownerIp, owner])
  if (!n) {
    return <div className="nd nd-empty">
      <p>Select a host in the graph or the table to see its connections, Snort alerts and AppID data, and to run a traceroute or a port scan.</p>
    </div>
  }
  const tools = (info && info.tools) || {}
  const tr = results['trace|' + n.ip]
  const sc = results['scan|' + n.ip]
  const local = n.scope === 'lan' || n.scope === 'link-local' || n.scope === 'loopback'
  const names = [...new Set([...n.names, ...n.addrs.flatMap(ip => rdns[ip] || [])])]
  const sigs = n.sigs
  return (
    <div className="nd" ref={boxRef}>
      <div className="nd-head">
        <span className="dot-sw" style={{ background: nodeColor(n) }} />
        <h4 className="mono">{n.ip}</h4>
        <button type="button" className="ed-close" aria-label="Close" onClick={onClose}>×</button>
      </div>

      <div className="nd-sec">Address</div>
      <Row k="Names">{names.length ? names.slice(0, 4).map(x => <div key={x} className="mono">{x}</div>) : <span className="muted">{n.addrs.every(ip => Array.isArray(rdns[ip])) ? 'none known' : 'looking up…'}</span>}</Row>
      {ownerIp && <OwnerRows w={owner[ownerIp]} whoisTool={info && info.tools && info.tools.whois} />}
      {n.addrs.length > 1 && <Row k="Addresses">{n.addrs.map(a => <div key={a} className="mono">{a}</div>)}
        <div className="muted">one device: same MAC address</div></Row>}
      <Row k="Network">{SCOPE_LABEL[n.scope]}{n.gateway && <span className="tag tag-muted" style={{ marginLeft: 6 }}>default gateway</span>}</Row>
      {n.neighbor && <Row k="MAC"><span className="mono">{n.neighbor.mac || '—'}</span>{n.neighbor.state && <span className="muted"> · {n.neighbor.state}</span>}</Row>}
      <Row k="Status">{n.live ? `${n.conns.length} open connection${n.conns.length > 1 ? 's' : ''}` : 'no open connection now'}</Row>
      <Row k="In logs">{n.firstSeen === null ? <span className="muted">not in the Snort / AppID logs in the {win.long}</span>
        : <>{hist && n.firstSeen - hist.since < hist.step ? `from the start of the ${win.long}` : `first ${fmtDateTime(n.firstSeen)}`}<br />last {fmtDateTime(n.lastSeen)}</>}</Row>

      <Signals n={n} win={win.long} />

      {hist && (n.alertHist || n.appHist) && <>
        <div className="nd-sec">Activity · {win.long}</div>
        <Activity title="Snort alerts" unit="alerts" h={n.alertHist} hist={hist} />
        <Activity title="AppID sessions" unit="sessions" h={n.appHist} hist={hist} />
      </>}

      {n.conns.length > 0 && <>
        <div className="nd-sec">Connections</div>
        <table className="grid nd-table">
          <thead><tr><th /><th>Remote</th><th>Local</th><th>State</th><th>Process</th></tr></thead>
          <tbody>{n.conns.slice(0, 30).map((c, i) => <tr key={i}>
            <td title={c.direction === 'in' ? 'inbound: the remote host connected to us' : 'outbound: we connected to the remote host'}>{c.direction === 'in' ? '←' : '→'}</td>
            <td className="mono">{c.proto} {portLabel(c.remotePort)}</td>
            <td className="mono">{c.localPort}</td>
            <td className="muted">{c.state}</td>
            <td>{c.process || <span className="muted">pid {c.pid ?? '?'}</span>}</td>
          </tr>)}</tbody>
        </table>
        {n.conns.length > 30 && <div className="card-note">and {n.conns.length - 30} more</div>}
      </>}

      <div className="nd-sec">Snort alerts · {win.long}</div>
      {n.alertCount === 0 ? <div className="muted">None.</div> : <>
        <div className="nd-sev">{[1, 2, 3, 4, 0].filter(p => n.sev[p]).map(p => <span key={p}><PriorityBadge p={p} /> {fmtNum(n.sev[p])}</span>)}</div>
        <ul className="nd-alerts">{sigs.slice(0, 6).map(g => <li key={g.msg}>
          <PriorityBadge p={g.priority} /> {g.msg} <span className="muted">×{fmtNum(g.count)} · last {fmtClock(g.last)}</span>
        </li>)}</ul>
        {n.sigCount > 6 && <div className="card-note">and {n.sigCount - 6} more signatures; see Overview or Alerts.</div>}
      </>}

      {(n.appSessions > 0) && <>
        <div className="nd-sec">AppID</div>
        <Row k="Sessions">{fmtNum(n.appSessions)}</Row>
        <Row k="Apps">{n.appid.size > 0 ? [...n.appid.entries()].sort((a, b) => b[1] - a[1]).slice(0, 6).map(([k, c]) => <div key={k}>{k} <span className="muted">×{c}</span></div>)
          : <span className="muted">not identified (AppID reported "unknown")</span>}</Row>
        {n.services.length > 0 && <Row k="Offers">{n.services.slice(0, 6).map(x => <div key={x.app + x.port + x.proto}>{x.app} <span className="mono">{x.port}/{x.proto}</span> <span className="muted">×{x.count}</span></div>)}</Row>}
      </>}

      <div className="nd-sec">Investigate</div>
      <div className="nd-actions">
        <button type="button" className="btn" disabled={!tools.traceroute || (tr && tr.loading)}
                title={tools.traceroute ? 'Show the routers between this machine and the host' : 'traceroute / tracert not found, see NETWORK.md'}
                onClick={() => run('trace', n.ip, `/network/trace/${encodeURIComponent(n.ip)}?source=${source}`)}>Traceroute</button>
        <button type="button" className="btn" disabled={!tools.nmap || !local || (sc && sc.loading)}
                title={!tools.nmap ? 'nmap not found, see NETWORK.md' : !local ? 'Only hosts in your own network can be scanned' : 'Find open ports and services (nmap)'}
                onClick={() => run('scan', n.ip, `/network/scan/${encodeURIComponent(n.ip)}`)}>Port scan</button>
      </div>
      {!tools.nmap && <div className="card-note">Port scan needs nmap. See NETWORK.md.</div>}
      {tools.nmap && !local && <div className="card-note">Port scans are limited to your own network.</div>}
      {tr && <div className="nd-result"><div className="nd-sub">Traceroute</div><TraceResult r={tr} /></div>}
      {sc && <div className="nd-result"><div className="nd-sub">Open ports</div><ScanResult r={sc} /></div>}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Tables

const SevBadges = ({ n }) => n.alertCount === 0 ? <span className="muted">—</span>
  : <span className="net-sev">{[1, 2, 3, 4, 0].filter(p => n.sev[p]).map(p => <span key={p}><PriorityBadge p={p} /> {fmtNum(n.sev[p])}</span>)}</span>

const MoreAddrs = ({ n }) => n.addrs.length > 1
  ? <span className="muted" title={n.addrs.slice(1).join('\n')}> +{n.addrs.length - 1}</span> : null

const SignalTags = ({ n }) => n.signals.length === 0 ? <span className="muted">—</span>
  : <span className="sig-tags">{n.signals.map(x => <span key={x.id} className="sig-tag" style={{ '--sc': levelColor(x.level) }} title={x.detail}>{x.label}</span>)}</span>

const AttentionList = ({ peers, selected, onSelect, win }) => {
  const [limit, setLimit] = useState(10)
  const rows = useMemo(() => attention(peers), [peers])
  return (
    <>
      {rows.length === 0 ? <div className="muted">No host matches the rules below in the {win.long}.</div> :
        <div className="table-wrap">
          <table className="grid">
            <thead><tr><th>Address</th><th>Signals</th><th>Alerts ({win.short})</th><th>Name</th><th>Last in logs</th><th>Now</th></tr></thead>
            <tbody>{rows.slice(0, limit).map(n =>
              <tr key={n.ip} className={'row' + (n.ip === selected ? ' row-open' : '')} onClick={() => onSelect(n.ip)}>
                <td className="mono"><span className="dot-sw" style={{ background: nodeColor(n) }} />{n.ip}<MoreAddrs n={n} /></td>
                <td><SignalTags n={n} /></td>
                <td><SevBadges n={n} /></td>
                <td className="net-name">{n.name || <span className="muted">—</span>}</td>
                <td className="muted">{n.lastSeen ? fmtClock(n.lastSeen) : '—'}</td>
                <td>{n.live ? `${n.conns.length} conn${n.process ? ' · ' + n.process : ''}` : <span className="muted">not connected</span>}</td>
              </tr>)}
            </tbody>
          </table>
        </div>}
      {rows.length > limit && <button type="button" className="btn" style={{ marginTop: 8 }} onClick={() => setLimit(limit + 20)}>Show more ({rows.length - limit})</button>}
      <details className="net-rules">
        <summary>How hosts are flagged</summary>
        <p>Each signal is one rule over the Snort and AppID logs of the selected window and the current connection list. Hosts are listed by their most serious signal, then by how many they have. There is no combined risk score: the reasons are shown as they are.</p>
        <ul>{RULES.map(([k, d]) => <li key={k}><strong>{k}</strong>: {d}</li>)}</ul>
      </details>
    </>
  )
}

const HostsTable = ({ peers, selected, onSelect, win }) => {
  const [limit, setLimit] = useState(50)
  const rows = [...peers].sort((a, b) =>
    (a.maxSev === null ? 9 : a.maxSev || 5) - (b.maxSev === null ? 9 : b.maxSev || 5) || b.weight - a.weight || a.ip.localeCompare(b.ip))
  return (
    <>
      <div className="table-wrap">
        <table className="grid">
          <thead><tr><th>Address</th><th>Alerts ({win.short})</th><th>Name</th><th>Network</th><th>Process</th><th className="num">Conns</th><th>Ports</th><th>AppID</th></tr></thead>
          <tbody>{rows.slice(0, limit).map(n =>
            <tr key={n.ip} className={'row' + (n.ip === selected ? ' row-open' : '')} onClick={() => onSelect(n.ip)}>
              <td className="mono"><span className="dot-sw" style={{ background: nodeColor(n) }} />{n.ip}<MoreAddrs n={n} /></td>
              <td><SevBadges n={n} /></td>
              <td className="net-name">{n.name || <span className="muted">—</span>}</td>
              <td>{SCOPE_LABEL[n.scope]}{n.gateway ? ' · gateway' : ''}</td>
              <td>{n.process || <span className="muted">{n.live ? '?' : 'not connected'}</span>}</td>
              <td className="num">{n.conns.length ? <>{n.conns.length}{n.inbound ? <span className="muted"> ({n.inbound} in)</span> : null}</> : '—'}</td>
              <td className="mono">{[...n.remotePorts.keys()].slice(0, 4).join(' ') || '—'}</td>
              <td>{n.app || <span className="muted">—</span>}</td>
            </tr>)}
          </tbody>
        </table>
      </div>
      {rows.length > limit && <button type="button" className="btn" style={{ marginTop: 8 }} onClick={() => setLimit(limit + 100)}>Show more ({rows.length - limit})</button>}
    </>
  )
}

const ListeningTable = ({ listening }) => {
  const rows = useMemo(() => {
    const m = new Map()
    ;(listening || []).forEach(l => {
      const k = `${l.proto}|${l.port}`
      const r = m.get(k) || { ...l, addrs: new Set(), procs: new Set() }
      r.addrs.add(l.ip); if (l.process) r.procs.add(l.process)
      m.set(k, r)
    })
    return [...m.values()].sort((a, b) => a.port - b.port || a.proto.localeCompare(b.proto))
  }, [listening])
  const exposed = r => [...r.addrs].some(a => !a.startsWith('127.') && a !== '::1')
  return (
    <div className="table-wrap net-listen">
      <table className="grid">
        <thead><tr><th>Port</th><th>Address</th><th>Process</th></tr></thead>
        <tbody>{rows.map(r => <tr key={r.proto + r.port}>
          <td className="mono">{r.proto} {portLabel(r.port)}</td>
          <td className="mono">{[...new Set([...r.addrs].map(a => (a === '0.0.0.0' || a === '::' ? 'all interfaces' : a)))].join(', ')}
            {!exposed(r) && <span className="tag tag-muted" style={{ marginLeft: 6 }}>local only</span>}</td>
          <td>{[...r.procs].join(', ') || <span className="muted">—</span>}</td>
        </tr>)}</tbody>
      </table>
    </div>
  )
}

// ---------------------------------------------------------------------------

function Network() {
  const [info, setInfo] = useState(null)
  const [source, setSource] = useState(null)
  const [by, setBy] = useState('process')
  const [opts, setOpts] = useState({ seen: true, lan: true, loopback: false })
  const [auto, setAuto] = useState(true)
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState(null)
  const [results, setResults] = useState({})
  const [discovered, setDiscovered] = useState(null)
  const [windowS, setWindowS] = useState(initialWindow)
  const pickWindow = w => { setWindowS(w); try { localStorage.setItem(WINDOW_KEY, String(w)) } catch (e) { /* storage off */ } }
  const [, short, long] = winLabel(windowS)
  const win = { short, long }

  useEffect(() => {
    getJson('/network').then(i => { setInfo(i); setSource(s => s || (i.sources[0] && i.sources[0].id)) }, e => setInfo({ error: e }))
  }, [])

  const [snap, reloadSnap] = usePoll(() => ({ path: `/network/snapshot?source=${source || ''}` }), auto ? 10000 : 3600000, `${source}|${auto}`)
  const [histState] = usePoll(() => ({ path: `/network/history?window=${windowS}` }), windowS > 3600 ? 60000 : 30000, `hist|${windowS}`)
  // keep showing the previous window's data until the new one arrives
  const hist = histState.data && histState.data.hosts && histState.data.window === windowS ? histState.data : null
  const snapshot = snap.data && !snap.data.error ? snap.data : null
  const peers = useMemo(() => buildPeers(snapshot, hist,
    { ...opts, discovered: discovered && discovered.hosts }), [snapshot, hist, opts, discovered])
  const cover = hist && hist.coverage
  const s = summary(snapshot, peers)
  const node = peers.find(n => n.ip === selected) || null

  const run = (kind, ip, path) => {
    const key = kind + '|' + ip
    setResults(r => ({ ...r, [key]: { loading: true } }))
    getJson(path).then(res => setResults(r => ({ ...r, [key]: res })),
      e => setResults(r => ({ ...r, [key]: { error: e.message } })))
  }
  const discover = () => {
    setDiscovered({ loading: true })
    getJson('/network/discover').then(setDiscovered, e => setDiscovered({ error: e.message }))
  }

  if (info && info.error) return <Panel title="Network" accent="teal"><Status error={info.error} /></Panel>
  const toggle = k => setOpts(o => ({ ...o, [k]: !o[k] }))
  const tools = (info && info.tools) || {}

  // Informational notes, shown under Listening ports where the narrow column has room
  const notes = [
    snapshot && providerNote(snapshot.host.addrs, info && info.homeNet),
    ...(cover ? [['Snort alert log', cover.alerts], ['AppID log', cover.appid]] : []).map(([k, c]) =>
      c.from !== null && c.from > hist.since + 60 &&
      <div className="muted">{k} starts at {fmtDateTime(c.from)} (Snort restart or log rotation), so it covers only part of the {long}.</div>),
    !tools.tshark && info && info.platform !== 'windows' && info.wire &&
      <div className="muted">Tip: with tshark installed, hostnames from DNS answers and TLS SNI captured on {info.wire.iface} are shown for every address. See NETWORK.md.</div>,
  ].filter(Boolean).map((el, i) => React.cloneElement(el, { key: i }))

  return (
    <div className="ov">
      <div className="ov-filters">
        {info && info.sources.length > 1 && <div className="seg" role="group" aria-label="Machine">
          {info.sources.map(x => <button key={x.id} type="button" className={source === x.id ? 'seg-on' : ''} onClick={() => setSource(x.id)}>{x.label}</button>)}
        </div>}
        <div className="seg" role="group" aria-label="Group by">
          {GROUP_BY.map(([id, label]) => <button key={id} type="button" className={by === id ? 'seg-on' : ''} onClick={() => setBy(id)}>{label}</button>)}
        </div>
        <div className="seg" role="group" aria-label="Log window">
          {WINDOWS.map(([w, l, d]) => <button key={w} type="button" title={`Snort and AppID logs of the ${d}`} className={windowS === w ? 'seg-on' : ''} onClick={() => pickWindow(w)}>{l}</button>)}
        </div>
        <label className="net-check"><input type="checkbox" checked={opts.seen} onChange={() => toggle('seen')} /> Snort/AppID peers</label>
        <label className="net-check"><input type="checkbox" checked={opts.lan} onChange={() => toggle('lan')} /> LAN devices</label>
        <label className="net-check"><input type="checkbox" checked={opts.loopback} onChange={() => toggle('loopback')} /> loopback</label>
        <input className="input" placeholder="find IP, name, process" value={query} onChange={e => setQuery(e.target.value)} />
        <div className="ov-filters-right">
          <button type="button" className="btn" disabled={!tools.nmap || (discovered && discovered.loading)} onClick={discover}
                  title={tools.nmap ? 'Ping-sweep your local network with nmap to find devices' : 'nmap not found, see NETWORK.md'}>
            {discovered && discovered.loading ? 'Discovering…' : 'Discover LAN'}</button>
          <label className="net-check"><input type="checkbox" checked={auto} onChange={() => setAuto(!auto)} /> auto 10 s</label>
          <button type="button" className="btn" onClick={reloadSnap}>Refresh</button>
          <span className="muted">{snap.updated ? 'updated ' + fmtClock(snap.updated / 1000) : ''}</span>
        </div>
      </div>

      {snap.error && <Status error={snap.error} />}
      {histState.error && <div className="warn">Snort / AppID history: {String(histState.error.message || histState.error)}</div>}
      {!hist && !histState.error && <div className="muted">Reading the Snort and AppID logs of the {long}…</div>}
      {discovered && discovered.error && <div className="warn">LAN discovery: {discovered.error}</div>}
      {discovered && discovered.hosts && <div className="muted">LAN discovery found {discovered.hosts.length} devices in {discovered.networks.join(', ')}.</div>}

      {!snapshot ? (!snap.error && <Status text="Reading connections…" />) : <>
        <div className="kpis kpis-6">
          <Kpi label="Remote hosts" value={fmtNum(s.hosts)} sub={`${s.netHosts} internet · ${s.lanHosts} local`} />
          <Kpi label="Connections" value={fmtNum(s.connections)} sub={`${s.outbound} out · ${s.inbound} in`} />
          <Kpi label="Listening ports" value={fmtNum(s.listening)} sub="services this machine offers" />
          <Kpi label="LAN neighbours" value={fmtNum(s.neighbors)} sub="ARP / neighbour table" />
          <Kpi label="Hosts with alerts" value={fmtNum(s.alerted)} sub={s.p1 ? `⚠ ${s.p1} with P1 · ${long}` : long} status={s.p1 ? 'warn' : undefined} />
          <Kpi label="Need attention" value={fmtNum(s.attention)} sub={`flagged by the rules · ${short}`} status={s.attentionHigh ? 'warn' : undefined} />
        </div>

        <div className="net-main">
          <Section title="Connection map" note={`${snapshot.host.name} · ${peers.length} hosts · via ${snapshot.via.join(', ')}`} className="net-card">
            <NetGraph host={snapshot.host.name} peers={peers} by={by} selected={selected} onSelect={setSelected} query={query} win={short} />
            <Legend />
          </Section>
          <Section title="Host details" className="net-side">
            <Details n={node} info={info} source={source} results={results} run={run} onClose={() => setSelected(null)} hist={hist} win={win} />
          </Section>
        </div>

        <Section title="Needs attention" note={`hosts flagged by the rules below · ${long} · click a row to select`}>
          <AttentionList peers={peers} selected={selected} onSelect={setSelected} win={win} />
        </Section>

        <div className="net-tables">
          <Section title="Hosts" note="alerted first, then by activity · click a row to select">
            <HostsTable peers={peers} selected={selected} onSelect={setSelected} win={win} />
          </Section>
          <div className="net-aside">
            <Section title="Listening ports" note="who can connect to this machine">
              <ListeningTable listening={snapshot.listening} />
            </Section>
            {notes.length > 0 && <Section title="Notes" className="net-notes">{notes}</Section>}
          </div>
        </div>
        {tools.tshark && info.wire && info.wire.error && <div className="warn">tshark: {info.wire.error}</div>}
      </>}
    </div>
  )
}

export default Network
