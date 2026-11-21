import React, { useState } from 'react'
import { PriorityBadge } from './Panel'

const Row = ({ className, onClick, json, open }) =>
  <tr className={`row ${className}${open ? ' row-open' : ''}`} onClick={onClick}>
    <td className="mono">{json.timestamp}</td>
    <td><PriorityBadge p={json.priority} /></td>
    <td className="mono">{json.rule}</td>
    <td>{json.proto}</td>
    <td className="mono">{json.src_ap}</td>
    <td className="mono">{json.dst_ap}</td>
    <td className="msg">{json.msg}</td>
    <td className="muted">{json.class}</td>
  </tr>

/** Wireshark display filter matching the alert's packet time (1 µs window). */
export const wiresharkFilter = (json) => {
  if (!json || json.seconds === undefined || typeof json.timestamp !== 'string') return null
  const d = new Date(json.seconds * 1000)
  const d_array = d.toString().split(" ")
  const stamp = json.timestamp.split(".")
  const f = (parseFloat('0.' + stamp[1]) + 0.000001).toFixed(6)
  const stamp2 = f.toString().split(".")
  const filter = 'frame.time >= "' + d_array[1] + ' ' + d_array[2] + ', ' + d_array[3] +
    ' ' + d_array[4] + '.' + stamp[1] + '" && frame.time <= "' + d_array[1] + ' ' + d_array[2] +
    ', ' + d_array[3] + ' ' + d_array[4] + '.' + stamp2[1] + '"'
  return filter
}

/** Row + expandable details. Pass `open`/`onToggle` to control it from the parent. */
const Alert = ({ json, open, onToggle, isNew }) => {
  const [own, setOwn] = useState(false)
  const showDetails = open === undefined ? own : open
  const bg = 'prio prio-' + json.priority + (isNew ? ' row-new' : '')
  const filter = wiresharkFilter(json)

  const toggle = () => (onToggle ? onToggle() : setOwn(!own))

  return <>
    <Row className={bg} onClick={toggle} json={json} open={showDetails} />
    {showDetails &&
      <tr className="details-row">
        <td colSpan="8">
          <div className="details">
            <div className="label">Find with Wireshark</div>
            <code className="filter">{filter}</code>
            <dl className="kv">
              {Object.entries(json).map(([k, v]) =>
                <React.Fragment key={k}><dt>{k}</dt><dd>{String(v)}</dd></React.Fragment>)}
            </dl>
          </div>
        </td>
      </tr>}
  </>
}

export const AlertHeader = ({ onSort }) => {
  const cols = [['timestamp', 'Timestamp'], ['priority', 'P'], ['rule', 'Rule'], ['proto', 'Proto'],
    ['src_ap', 'Source'], ['dst_ap', 'Destination'], ['msg', 'Alert message'], ['class', 'Classification']]
  return <thead>
    <tr>
      {cols.map(([k, label]) => onSort
        ? <th key={k} className="sortable" onClick={() => onSort(k)}>{label}</th>
        : <th key={k}>{label}</th>)}
    </tr>
  </thead>
}

export default Alert;
