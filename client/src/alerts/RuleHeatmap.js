import React, { useState } from 'react'
import { useWidth, Tip } from '../overview/charts'
import { fmtClock, fmtDay, fmtNum } from '../overview/format'
import { sevColor } from '../overview/severity'

const ROW_H = 18
const LABEL_W = 320
const RIGHT_W = 64
const AXIS_H = 20

/** Fill for one cell: nothing, "as usual" (neutral) or a single-hue ramp by surprise. */
export const cellFill = s => {
  if (!s || s.count === 0) return null
  if (s.surprise < 1) return 'var(--hm-usual)'
  const k = Math.min(1, (s.surprise - 1) / 4) // ×2 … ×32
  return `color-mix(in srgb, var(--hm-hot) ${Math.round(28 + k * 72)}%, var(--surface))`
}

const ratio = s => (s.expected < 0.05 ? 'normally none' : `×${(s.count / s.expected).toFixed(s.count / s.expected < 10 ? 1 : 0)} the usual ~${fmtNum(+s.expected.toFixed(s.expected < 10 ? 1 : 0))}`)

/**
 * One row per rule, one cell per time bin. Colour = how far the count is from what
 * this rule usually does in the window, so a steady flood stays calm and a burst of
 * a normally quiet rule lights up. Unusual cells are outlined.
 */
const RuleHeatmap = ({ rules, since, step, bins, focus, onFocus, limit }) => {
  const [ref, width] = useWidth()
  const [hover, setHover] = useState(null)
  const rows = rules.slice(0, limit)
  const plotL = LABEL_W, plotR = Math.max(plotL + 60, width - RIGHT_W)
  const cw = (plotR - plotL) / Math.max(1, bins)
  const height = rows.length * ROW_H + AXIS_H
  const multiDay = fmtDay(since) !== fmtDay(since + bins * step)
  const labelEvery = Math.max(1, Math.ceil(bins / Math.max(1, Math.floor((plotR - plotL) / 70))))
  const now = Date.now() / 1000

  return (
    <div className="viz" ref={ref} onMouseLeave={() => setHover(null)}>
      {width > 0 &&
        <svg width={width} height={height} role="img" aria-label="Alert rules over time, coloured by how unusual each period is for the rule">
          {rows.map((r, i) => {
            const y = i * ROW_H
            const rowFocus = focus && focus.rule === r.rule
            return (
              <g key={r.rule} opacity={focus && !rowFocus ? 0.45 : 1}>
                <rect x={0} y={y} width={width} height={ROW_H} className={rowFocus ? 'hm-row hm-row-sel' : 'hm-row'} />
                <circle cx={6} cy={y + ROW_H / 2} r={4} style={{ fill: sevColor(r.priority) }} />
                <text x={16} y={y + ROW_H / 2} dy="0.35em" className="hm-label">
                  <tspan className="hm-prio">P{r.priority}</tspan>{' '}
                  {(r.msg || r.rule).length > 44 ? (r.msg || r.rule).slice(0, 43) + '…' : (r.msg || r.rule)}
                </text>
                {r.scores.map((s, b) => {
                  const fill = cellFill(s)
                  if (!fill) return null
                  return <rect key={b} x={plotL + b * cw + 0.5} y={y + 2} width={Math.max(1, cw - 1)} height={ROW_H - 4}
                               rx={2} style={{ fill }} className={s.unusual ? 'hm-cell hm-unusual' : 'hm-cell'} />
                })}
                <text x={plotR + 8} y={y + ROW_H / 2} dy="0.35em" className="hm-total">{fmtNum(r.total)}</text>
                {/* hit areas per cell, over the whole row height */}
                {r.scores.map((s, b) =>
                  <rect key={'h' + b} x={plotL + b * cw} y={y} width={cw} height={ROW_H} fill="transparent"
                        style={{ cursor: s.count ? 'pointer' : 'default' }}
                        onMouseMove={e => setHover({ r, b, s, x: e.nativeEvent.offsetX, y: e.nativeEvent.offsetY })}
                        onClick={() => s.count && onFocus({ rule: r.rule, msg: r.msg, priority: r.priority,
                          from: since + b * step, to: since + (b + 1) * step })} />)}
              </g>
            )
          })}
          {focus && focus.rule && (() => {
            const i = rows.findIndex(r => r.rule === focus.rule)
            if (i < 0) return null
            const b0 = Math.max(0, Math.round((focus.from - since) / step))
            const b1 = Math.min(bins, Math.round((focus.to - since) / step))
            return <rect x={plotL + b0 * cw - 1} y={i * ROW_H} width={(b1 - b0) * cw + 2} height={ROW_H}
                         rx={3} className="hm-focus" />
          })()}
          {now < since + bins * step &&
            <rect x={plotL + ((now - since) / step) * cw} y={0} width={Math.max(0, plotR - plotL - ((now - since) / step) * cw)}
                  height={rows.length * ROW_H} className="hm-future" />}
          {Array.from({ length: bins }, (_, b) => b).filter(b => b % labelEvery === 0).map(b => {
            const t = since + b * step
            return <text key={b} x={plotL + b * cw} y={height - 5} className="viz-tick">
              {(multiDay && (b === 0 || fmtDay(t) !== fmtDay(t - labelEvery * step)) ? fmtDay(t) + ' ' : '') + fmtClock(t, false)}
            </text>
          })}
        </svg>}
      {hover &&
        <Tip x={hover.x} y={hover.y} width={width}>
          <div className="tip-head">
            {fmtClock(since + hover.b * step, false)}–{fmtClock(since + (hover.b + 1) * step, false)} · {hover.r.rule}
          </div>
          <div className="tip-msg">{hover.r.msg}</div>
          <div className="tip-row"><strong>{fmtNum(hover.s.count)}</strong><span>alerts</span></div>
          {hover.s.count > 0 && <div className="tip-row"><strong /><span>{ratio(hover.s)}</span></div>}
          {hover.r.cells && hover.r.cells[hover.b] && hover.r.cells[hover.b].src.length > 0 &&
            <div className="tip-foot mono">
              {hover.r.cells[hover.b].src.map(([ip, n]) => `${ip} ×${n}`).join(', ')}
            </div>}
          {hover.s.count > 0 && <div className="tip-foot">Click to list these alerts</div>}
        </Tip>}
    </div>
  )
}

export default RuleHeatmap
