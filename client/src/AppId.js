import React, { useState } from 'react'

const AppIdRow = ({ json, onClick, open }) => {
  const unknown = json.apps.service === 'unknown'
  return <tr className={`row prio prio-none${open ? ' row-open' : ''}`} onClick={onClick}>
    <td className="mono muted">{json.count}</td>
    <td className="mono">{json.session_num}</td>
    <td className="mono">{json.pkt_time}</td>
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

const AppId = ({ json }) => {
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
    <AppIdRow onClick={toggle} json={json} open={showDetails} />
    {showDetails &&
      <tr className="details-row">
        <td colSpan="12">
          <div className="details">
            <div className="label">Find with Wireshark</div>
            <code className="filter">{filter}</code>
          </div>
        </td>
      </tr>}
  </>
}

export default AppId;
