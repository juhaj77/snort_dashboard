import React from 'react'

/** Dashboard card with an uppercase title and an optional note / right-hand slot. */
export const Section = ({ title, note, right, className = '', children }) =>
  <section className={'card ' + className}>
    <header className="card-head">
      <h3>{title}</h3>
      {note && <span className="card-sub">{note}</span>}
      {right && <span className="card-right">{right}</span>}
    </header>
    {children}
  </section>

/** Headline number with label and sub-line. */
export const Kpi = ({ label, value, sub, status }) =>
  <div className={'kpi' + (status ? ' kpi-' + status : '')}>
    <div className="kpi-label">{label}</div>
    <div className="kpi-value">{value}</div>
    {sub && <div className="kpi-sub">{sub}</div>}
  </div>
