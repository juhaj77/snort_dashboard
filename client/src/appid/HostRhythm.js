import React, { useState } from 'react'
import { useWidth, Tip } from '../overview/charts'
import { fmtClock, fmtNum } from '../overview/format'
import { fmtPeriod } from './appidModel'
import { kindColor, HostTip } from './DomainMap'

const ROWS = 18
const ROW_H = 20
const LABEL_W = 210
const RIGHT_W = 92
const AXIS_H = 22

/**
 * One row per host (most sessions first), one tick per session on a shared time axis.
 * A host that repeats shows up as a dotted line; a steady rhythm looks like a barcode
 * and is marked with ↻ and its period.
 */
const HostRhythm = ({ hosts, from, to, selected, onSelect }) => {
  const [ref, width] = useWidth()
  const [hover, setHover] = useState(null)
  let rows = hosts.slice(0, ROWS)
  // keep the selected host visible even if it is not in the top rows
  if (selected && !rows.some(h => h.host === selected)) {
    const h = hosts.find(x => x.host === selected)
    if (h) rows = [...rows.slice(0, ROWS - 1), h]
  }
  const plotL = LABEL_W, plotR = Math.max(plotL + 50, width - RIGHT_W)
  const height = rows.length * ROW_H + AXIS_H
  const x = t => plotL + ((t - from) / Math.max(1, to - from)) * (plotR - plotL)
  const nTicks = Math.max(2, Math.min(7, Math.floor((plotR - plotL) / 90)))
  const span = to - from

  return (
    <div className="viz" ref={ref} onMouseLeave={() => setHover(null)}>
      {width > 0 && rows.length > 0 &&
        <svg width={width} height={height} role="img" aria-label="Sessions per host over time">
          {Array.from({ length: nTicks + 1 }, (_, i) => from + (span * i) / nTicks).map((t, i) =>
            <g key={i}>
              <line x1={x(t)} x2={x(t)} y1={0} y2={rows.length * ROW_H} className="viz-grid" />
              <text x={x(t)} y={height - 6} className="viz-tick"
                    textAnchor={i === 0 ? 'start' : i === nTicks ? 'end' : 'middle'}>
                {fmtClock(t / 1000, span < 30 * 60e3)}
              </text>
            </g>)}
          {rows.map((h, i) => {
            const y0 = i * ROW_H
            const isSel = selected === h.host
            const dim = selected && !isSel
            return (
              <g key={h.host} opacity={dim ? 0.4 : 1} className="ar-row"
                 onMouseMove={e => setHover({ h, x: e.nativeEvent.offsetX, y: e.nativeEvent.offsetY })}
                 onClick={() => onSelect(isSel ? null : h.host)}>
                <rect x={0} y={y0} width={width} height={ROW_H}
                      className={isSel ? 'ar-hit ar-hit-sel' : 'ar-hit'} />
                <line x1={plotL} x2={plotR} y1={y0 + ROW_H / 2} y2={y0 + ROW_H / 2} className="ar-lane" />
                <text x={plotL - 8} y={y0 + ROW_H / 2} dy="0.35em" textAnchor="end"
                      className={h.named ? 'ar-label' : 'ar-label mono'}>
                  {h.host.length > 30 ? '…' + h.host.slice(-29) : h.host}
                </text>
                {h.times.map((t, k) =>
                  <rect key={k} x={x(t) - 1} y={y0 + 4} width={2} height={ROW_H - 8} rx={1}
                        style={{ fill: kindColor(h.sessionKinds[k]) }} />)}
                <text x={plotR + 8} y={y0 + ROW_H / 2} dy="0.35em" className="ar-count">{fmtNum(h.count)}</text>
                {h.period &&
                  <text x={plotR + 40} y={y0 + ROW_H / 2} dy="0.35em" className="ar-period">↻ {fmtPeriod(h.period)}</text>}
              </g>
            )
          })}
        </svg>}
      {width > 0 && rows.length === 0 && <div className="viz-empty">No sessions in this window.</div>}
      {hover &&
        <Tip x={hover.x} y={hover.y} width={width}>
          <HostTip h={hover.h} />
          <div className="tip-foot">{selected === hover.h.host ? 'Click to clear' : 'Click to show only this host'}</div>
        </Tip>}
    </div>
  )
}

export default HostRhythm
