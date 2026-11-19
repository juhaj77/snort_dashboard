import React, { useMemo, useState } from 'react'
import { BarList } from './charts'
import { appIdSessions, appDistribution } from './aggregate'
import { fmtNum } from './format'

const FIELDS = [
  ['service', 'Service'],
  ['client', 'Client'],
  ['payload', 'Payload'],
]

/** AppID application distribution, counted per session (last known value). */
const AppIdSummary = ({ events }) => {
  const [field, setField] = useState('service')
  const sessions = useMemo(() => appIdSessions(events), [events])
  const dist = useMemo(() => appDistribution(sessions, field, 10), [sessions, field])
  return (
    <>
      <div className="seg" role="tablist">
        {FIELDS.map(([f, label]) =>
          <button key={f} type="button" role="tab" aria-selected={f === field}
                  className={f === field ? 'seg-on' : ''} onClick={() => setField(f)}>{label}</button>)}
      </div>
      <BarList rows={dist.rows} other={dist.other}
               missing={dist.pending} missingLabel={`sessions with no ${field} identified`}
               empty={`No ${field} identified`} />
      <div className="card-note">
        {fmtNum(dist.sessions)} sessions in the last {fmtNum(events.length)} AppID events
      </div>
    </>
  )
}

export default AppIdSummary
