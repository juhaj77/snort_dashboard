import React, { useState } from 'react'

// Repeat counter: the more often a host comes back, the stronger the chip.
const Seen = ({ host, seen, max, onPick }) => {
  if (!host) return null
  const level = seen <= 1 ? 0 : Math.min(1, Math.log(seen) / Math.log(Math.max(2, max)))
  return <button type="button" className={seen > 1 ? 'seen seen-repeat' : 'seen'} title={`${seen} sessions with ${host} — click to focus`}
                 style={{ '--lvl': level }}
                 onClick={e => { e.stopPropagation(); onPick() }}>
    <span className="seen-host">{host}</span>
    {seen > 1 && <span className="seen-n">×{seen}</span>}
  </button>
}

const AppIdRow = ({ json, onClick, open, host, seen, max, onPick }) => {
  const unknown = json.apps.service === 'unknown'
  return <tr className={`row prio prio-none${open ? ' row-open' : ''}`} onClick={onClick}>
    <td className="mono muted">{json.count}</td>
    <td className="mono">{json.session_num}</td>
    <td className="mono">{json.pkt_time}</td>
    <td><Seen host={host} seen={seen} max={max} onPick={onPick} /></td>
    <td>{unknown ? <span className="tag tag-muted">unknown</span> : json.apps.service}</td>
    <td>{json.apps.client}</td>
    <td>{json.proto}</td>
    <td className="mono">{json.client_info.ip}</td>
    <td className="mono muted">{':' + json.client_info.port}</td>
    <td className="mono">{json.service_info.ip}</td>
    <td className="mono muted">{':' + json.service_info.port}</td>
    <td>{json.dns_host}</td>
    <td>{json.tls_host}</td>
  </tr>
}

const AppId = ({ json, host, seen, max, onPick }) => {
  const [showDetails, setShowDetails] = useState(false)

  const d = json.pkt_time.split(' ')
  const date = new Date(d[0] + 'T' + d[1])
  const dt = date.toDateString().split(' ')
  const stamp = d[1].split('.')[1]
  const f = (parseFloat('0.' + stamp) + 0.000001).toFixed(6)
  const stamp2 = f.toString().split(".")[1]
  const filter = 'frame.time >= "' + dt[1] + ' ' + dt[2] + ', ' + dt[3] + ' ' + d[1] +
    '" && frame.time <= "' + dt[1] + ' ' + dt[2] + ', ' + dt[3] +
    ' ' + d[1].split('.')[0] + '.' + stamp2 + '"'

  const toggle = () => setShowDetails(!showDetails)
  return <>
    <AppIdRow onClick={toggle} json={json} open={showDetails} host={host} seen={seen} max={max} onPick={onPick} />
    {showDetails &&
      <tr className="details-row">
        <td colSpan="13">
          <div className="details">
            <div className="label">Find with Wireshark</div>
            <code className="filter">{filter}</code>
          </div>
        </td>
      </tr>}
  </>
}

export default AppId;
