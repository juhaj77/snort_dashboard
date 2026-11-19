import React from 'react'

export const Panel = ({ title, accent = 'teal', description, right, children }) =>
  <section className={`panel panel-${accent}`}>
    <header className="panel-head">
      <div>
        <h2 className="panel-title">{title}</h2>
        {description && <p className="panel-desc">{description}</p>}
      </div>
      {right && <div className="panel-right">{right}</div>}
    </header>
    {children}
  </section>

export const Status = ({ error, text = 'Waiting for data…' }) =>
  <div className={error ? 'status status-error' : 'status'}>
    {error
      ? <>Cannot reach the server: <code>{String(error.message || error)}</code></>
      : <><span className="spinner" />{text}</>}
  </div>

export const PriorityBadge = ({ p }) =>
  <span className={`badge badge-p${p}`}>P{p}</span>
