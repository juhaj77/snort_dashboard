import React, { useState } from 'react'
import { PriorityBadge } from '../Panel'
import { wiresharkFilter } from '../Alert'
import { addrScope } from './aggregate'
import { sevLabel } from './severity'
import { fmtDateTime, hostPort } from './format'

const Field = ({ label, children }) =>
  <><dt>{label}</dt><dd>{children ?? <span className="muted">—</span>}</dd></>

const Scope = ({ ip }) => {
  const s = addrScope(ip)
  return s ? <span className="scope">{s}</span> : null
}

/** Details of one alert. `onFocus(field, value)` adds a dashboard filter. */
const EventDetails = ({ alert, onFocus, onClose }) => {
  const [showRaw, setShowRaw] = useState(false)
  if (!alert) {
    return <div className="ed ed-empty">Select an event in the timeline or the list to see its details.</div>
  }
  const r = alert.raw
  const filter = wiresharkFilter(r)
  return (
    <div className="ed">
      <div className="ed-head">
        <PriorityBadge p={alert.priority} />
        <span className="muted">{sevLabel(alert.priority)} severity</span>
        <button type="button" className="ed-close" onClick={onClose} aria-label="Close details">×</button>
      </div>
      <div className="ed-msg">{alert.msg || '(no message)'}</div>
      <dl className="ed-grid">
        <Field label="Time">
          <span className="mono">{r.timestamp}</span>
          <span className="muted"> · {fmtDateTime(alert.seconds)}</span>
        </Field>
        <Field label="Rule">
          {alert.rule && <button type="button" className="link mono" onClick={() => onFocus('rule', alert.rule)}>{alert.rule}</button>}
          {r.gid !== undefined && <span className="muted"> gid {r.gid} · sid {r.sid} · rev {r.rev}</span>}
        </Field>
        <Field label="Class">{alert.cls}</Field>
        <Field label="Protocol">
          {alert.proto && <button type="button" className="link" onClick={() => onFocus('proto', alert.proto)}>{alert.proto}</button>}
          {r.service && r.service !== 'unknown' && <span className="muted"> · service {r.service}</span>}
        </Field>
        <Field label="Source">
          {alert.srcIp && <>
            <button type="button" className="link mono" onClick={() => onFocus('src', alert.srcIp)}>{hostPort(alert.srcIp, alert.srcPort)}</button>
            <Scope ip={alert.srcIp} />
          </>}
        </Field>
        <Field label="Destination">
          {alert.dstIp && <>
            <button type="button" className="link mono" onClick={() => onFocus('dst', alert.dstIp)}>{hostPort(alert.dstIp, alert.dstPort)}</button>
            <Scope ip={alert.dstIp} />
          </>}
        </Field>
        {(r.eth_src || r.eth_dst) && <Field label="MAC"><span className="mono">{r.eth_src || '?'} → {r.eth_dst || '?'}</span></Field>}
        <Field label="Direction">{r.dir}</Field>
        <Field label="Action">{r.action}</Field>
        <Field label="Interface">{r.iface}</Field>
      </dl>
      {filter &&
        <>
          <div className="label">Find with Wireshark</div>
          <code className="filter">{filter}</code>
        </>}
      <button type="button" className="link ed-raw-toggle" onClick={() => setShowRaw(!showRaw)}>
        {showRaw ? 'Hide' : 'Show'} all {Object.keys(r).length} fields
      </button>
      {showRaw &&
        <dl className="kv">
          {Object.entries(r).map(([k, v]) =>
            <React.Fragment key={k}><dt>{k}</dt><dd>{String(v)}</dd></React.Fragment>)}
        </dl>}
    </div>
  )
}

export default EventDetails
