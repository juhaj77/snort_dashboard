// Small hand-written SVG/HTML charts (no chart library dependency).
import React, { useLayoutEffect, useRef, useState } from 'react'
import { SEVERITIES, sevColor, sevLabel } from './severity'
import { fmtClock, fmtDay, fmtNum, fmtStep, hostPort } from './format'

/** Track an element's content width. */
export const useWidth = () => {
  const ref = useRef(null)
  const [width, setWidth] = useState(0)
  useLayoutEffect(() => {
    const el = ref.current
    if (!el) return
    setWidth(el.clientWidth)
    if (typeof ResizeObserver === 'undefined') return
    const ro = new ResizeObserver(([e]) => setWidth(Math.floor(e.contentRect.width)))
    ro.observe(el)
    return () => ro.disconnect()
  }, [])
  return [ref, width]
}

/** Tooltip positioned inside a relatively-positioned container, kept within its width. */
export const Tip = ({ x, y, width, children }) => {
  const tipW = 220
  const left = Math.max(0, Math.min(x + 12, width - tipW))
  return <div className="viz-tip" style={{ left, top: Math.max(0, y - 8), width: tipW }}>{children}</div>
}

const niceMax = v => {
  if (v <= 0) return 1
  const exp = Math.pow(10, Math.floor(Math.log10(v)))
  const f = v / exp
  const nf = f <= 1 ? 1 : f <= 2 ? 2 : f <= 2.5 ? 2.5 : f <= 5 ? 5 : 10
  return nf * exp
}

// Rect with rounded top corners only (data end), square at the baseline.
const topRounded = (x, y, w, h, r) => {
  r = Math.min(r, w / 2, h)
  return `M${x},${y + h}V${y + r}Q${x},${y} ${x + r},${y}H${x + w - r}Q${x + w},${y} ${x + w},${y + r}V${y + h}Z`
}

const STACK_ORDER = [1, 2, 3, 4, 0] // most severe sits on the baseline

/**
 * Alert activity: one column per time bin, stacked by severity.
 * Click a column to select that time slice; click again to clear.
 */
export const ActivityChart = ({ bins, step, selectedT, onSelect, height = 180 }) => {
  const [ref, width] = useWidth()
  const [hover, setHover] = useState(null)
  const m = { l: 44, r: 8, t: 10, b: 24 }
  const plotW = Math.max(0, width - m.l - m.r)
  const plotH = height - m.t - m.b
  const n = bins.length
  const band = n ? plotW / n : 0
  const barW = Math.max(1, Math.min(24, band - 2))
  const yMax = niceMax(Math.max(1, ...bins.map(b => b.total)))
  const y = v => m.t + plotH - (v / yMax) * plotH
  const ticks = [0, 0.25, 0.5, 0.75, 1].map(k => k * yMax)
  const multiDay = n > 0 && fmtDay(bins[0].t) !== fmtDay(bins[n - 1].t + step)
  const labelEvery = Math.max(1, Math.ceil(n / Math.max(1, Math.floor(plotW / 80))))

  return (
    <div className="viz" ref={ref} onMouseLeave={() => setHover(null)}>
      {width > 0 &&
        <svg width={width} height={height} role="img" aria-label="Alerts over time, stacked by severity">
          {ticks.map(t =>
            <g key={t}>
              <line x1={m.l} x2={width - m.r} y1={y(t)} y2={y(t)} className={t === 0 ? 'viz-base' : 'viz-grid'} />
              <text x={m.l - 6} y={y(t) + 4} className="viz-tick" textAnchor="end">{fmtNum(t)}</text>
            </g>)}
          {bins.map((b, i) => {
            const x0 = m.l + i * band + (band - barW) / 2
            const dim = selectedT !== null && selectedT !== b.t
            let acc = 0
            const visible = STACK_ORDER.filter(p => b.counts[p] > 0)
            return (
              <g key={b.t} opacity={dim ? 0.35 : 1}>
                {visible.map((p, k) => {
                  const yTop = y(acc + b.counts[p])
                  const yBot = y(acc) - (k > 0 ? 2 : 0) // 2px surface gap between segments
                  acc += b.counts[p]
                  const h = Math.max(0, yBot - yTop)
                  if (h <= 0) return null
                  return k === visible.length - 1
                    ? <path key={p} d={topRounded(x0, yTop, barW, h, 4)} style={{ fill: sevColor(p) }} />
                    : <rect key={p} x={x0} y={yTop} width={barW} height={h} style={{ fill: sevColor(p) }} />
                })}
                <rect x={m.l + i * band} y={m.t} width={band} height={plotH} fill="transparent"
                      style={{ cursor: 'pointer' }}
                      onMouseMove={e => setHover({ i, x: e.nativeEvent.offsetX, y: e.nativeEvent.offsetY })}
                      onClick={() => onSelect(selectedT === b.t ? null : b)} />
              </g>
            )
          })}
          {bins.map((b, i) => i % labelEvery === 0 &&
            <text key={'x' + b.t} x={m.l + i * band + band / 2} y={height - 6} className="viz-tick" textAnchor="middle">
              {(multiDay && (i === 0 || fmtDay(b.t) !== fmtDay(bins[i - labelEvery]?.t ?? b.t)) ? fmtDay(b.t) + ' ' : '') +
                fmtClock(b.t, step < 60)}
            </text>)}
        </svg>}
      {hover && bins[hover.i] &&
        <Tip x={hover.x} y={hover.y} width={width}>
          <div className="tip-head">{fmtDay(bins[hover.i].t)} {fmtClock(bins[hover.i].t)} · {fmtStep(step)}</div>
          <div className="tip-row"><strong>{fmtNum(bins[hover.i].total)}</strong><span>alerts</span></div>
          {SEVERITIES.filter(s => bins[hover.i].counts[s.p] > 0).map(s =>
            <div className="tip-row" key={s.p}>
              <strong>{fmtNum(bins[hover.i].counts[s.p])}</strong>
              <span><i className="swatch" style={{ background: sevColor(s.p) }} />{s.label}</span>
            </div>)}
          <div className="tip-foot">{selectedT === bins[hover.i].t ? 'Click to clear' : 'Click to focus this interval'}</div>
        </Tip>}
    </div>
  )
}

/**
 * Ranked horizontal bars. With `stacked`, each bar is split by severity.
 * Rows are buttons: clicking one calls onPick(key).
 */
export const BarList = ({ rows, other = 0, missing = 0, missingLabel = 'without a value', stacked = false,
                          onPick, activeKey, renderLabel = k => k, renderMeta, empty = 'No data' }) => {
  if (rows.length === 0) return <div className="viz-empty">{empty}{missing > 0 && ` (${fmtNum(missing)} ${missingLabel})`}</div>
  const max = Math.max(...rows.map(r => r.total))
  return (
    <div className="barlist">
      {rows.map(r => {
        const title = stacked
          ? `${r.key}: ${fmtNum(r.total)} — ` + SEVERITIES.filter(s => r.counts[s.p]).map(s => `${s.label} ${fmtNum(r.counts[s.p])}`).join(', ')
          : `${r.key}: ${fmtNum(r.total)}`
        const segs = stacked ? STACK_ORDER.filter(p => r.counts[p] > 0) : [null]
        const Tag = onPick ? 'button' : 'div'
        return (
          <Tag key={r.key} type={onPick ? 'button' : undefined} title={title}
               className={'bar-row' + (activeKey === r.key ? ' bar-active' : '') + (onPick ? ' bar-click' : '')}
               onClick={onPick ? () => onPick(r.key, r) : undefined}>
            <span className="bar-label">{renderLabel(r.key, r)}{renderMeta && renderMeta(r.key, r)}</span>
            <span className="bar-track">
              <span className="bar-fill" style={{ width: `${(r.total / max) * 100}%` }}>
                {segs.map(p =>
                  <span key={p ?? 'one'} className="bar-seg"
                        style={{ flexGrow: p === null ? 1 : r.counts[p], background: p === null ? 'var(--bar)' : sevColor(p) }} />)}
              </span>
            </span>
            <span className="bar-value">{fmtNum(r.total)}</span>
          </Tag>
        )
      })}
      {(other > 0 || missing > 0) &&
        <div className="bar-foot">
          {other > 0 && <span>+{fmtNum(other)} in other values</span>}
          {missing > 0 && <span>{fmtNum(missing)} {missingLabel}</span>}
        </div>}
    </div>
  )
}

/** Part-to-whole severity bar (≤5 segments) with labelled counts underneath. */
export const SeverityBar = ({ counts, total, activeSev, onPick }) => {
  const present = STACK_ORDER.filter(p => counts[p] > 0)
  return (
    <div className="sevbar">
      <div className="sevbar-track">
        {present.map(p =>
          <span key={p} style={{ flexGrow: counts[p], background: sevColor(p) }}
                title={`${sevLabel(p)}: ${fmtNum(counts[p])}`} />)}
      </div>
      <div className="sevbar-legend">
        {STACK_ORDER.map(p =>
          <button key={p} type="button" disabled={!counts[p]}
                  className={'sev-item' + (activeSev === p ? ' sev-active' : '')}
                  onClick={() => onPick(p)}>
            <i className="swatch" style={{ background: sevColor(p) }} />
            <span className="sev-name">P{p} {sevLabel(p)}</span>
            <strong>{fmtNum(counts[p])}</strong>
            <span className="muted">{total ? Math.round((counts[p] / total) * 100) : 0}%</span>
          </button>)}
      </div>
    </div>
  )
}

/**
 * Event timeline: one lane per severity, one dot per alert.
 * Hover snaps to the nearest dot in the lane; click selects it.
 */
export const SwimLane = ({ alerts, range, selectedId, onSelect }) => {
  const [ref, width] = useWidth()
  const [hover, setHover] = useState(null)
  const lanes = STACK_ORDER.filter(p => alerts.some(a => a.priority === p))
  const laneH = 24
  const m = { l: 88, r: 12, t: 4, b: 22 }
  const height = m.t + lanes.length * laneH + m.b
  const plotW = Math.max(1, width - m.l - m.r)
  const [t0, t1] = range
  const span = Math.max(1, t1 - t0)
  const x = s => m.l + ((s - t0) / span) * plotW
  const byLane = Object.fromEntries(lanes.map(p => [p, alerts.filter(a => a.priority === p)]))

  const nearest = (lane, px) => {
    const list = byLane[lane]
    if (!list || !list.length) return null
    const target = t0 + ((px - m.l) / plotW) * span
    let lo = 0, hi = list.length - 1
    while (lo < hi) { const mid = (lo + hi) >> 1; if (list[mid].seconds < target) lo = mid + 1; else hi = mid }
    const cands = [list[lo], list[lo - 1]].filter(Boolean)
    const best = cands.reduce((a, b) => (Math.abs(x(a.seconds) - px) <= Math.abs(x(b.seconds) - px) ? a : b))
    return Math.abs(x(best.seconds) - px) <= 14 ? best : null
  }

  const onMove = e => {
    const { offsetX, offsetY } = e.nativeEvent
    const li = Math.floor((offsetY - m.t) / laneH)
    const lane = lanes[li]
    const a = lane !== undefined ? nearest(lane, offsetX) : null
    setHover(a ? { a, x: offsetX, y: offsetY } : null)
  }

  const ticks = 6
  const sel = alerts.find(a => a.id === selectedId)

  return (
    <div className="viz" ref={ref} onMouseLeave={() => setHover(null)}>
      {width > 0 && lanes.length > 0 &&
        <svg width={width} height={height} onMouseMove={onMove}
             onClick={() => hover && onSelect(hover.a)} style={{ cursor: hover ? 'pointer' : 'default' }}
             role="img" aria-label="Alert timeline by severity">
          {lanes.map((p, i) =>
            <g key={p}>
              <line x1={m.l} x2={width - m.r} y1={m.t + (i + 1) * laneH} y2={m.t + (i + 1) * laneH} className="viz-grid" />
              <text x={m.l - 8} y={m.t + i * laneH + laneH / 2 + 4} className="viz-tick" textAnchor="end">P{p} {sevLabel(p)}</text>
              {byLane[p].map(a =>
                <circle key={a.id} cx={x(a.seconds)} cy={m.t + i * laneH + laneH / 2} r={4}
                        style={{ fill: sevColor(p) }} className="dot" />)}
            </g>)}
          {sel && lanes.includes(sel.priority) &&
            <circle cx={x(sel.seconds)} cy={m.t + lanes.indexOf(sel.priority) * laneH + laneH / 2} r={7} className="dot-sel" />}
          {Array.from({ length: ticks + 1 }, (_, i) => t0 + (span * i) / ticks).map((t, i) =>
            <text key={i} x={x(t)} y={height - 6} className="viz-tick"
                  textAnchor={i === 0 ? 'start' : i === ticks ? 'end' : 'middle'}>{fmtClock(t, span < 600)}</text>)}
        </svg>}
      {hover &&
        <Tip x={hover.x} y={hover.y} width={width}>
          <div className="tip-head">{hover.a.timestamp || fmtClock(hover.a.seconds)}</div>
          <div className="tip-msg">{hover.a.msg || '(no message)'}</div>
          <div className="tip-row mono"><span>{hostPort(hover.a.srcIp, hover.a.srcPort)} → {hostPort(hover.a.dstIp, hover.a.dstPort)}</span></div>
          <div className="tip-foot">Click for details</div>
        </Tip>}
    </div>
  )
}

/**
 * Time series on one y-axis.
 * mode 'step': values[i] is an average over (t[i-1], t[i]] (perf_monitor intervals),
 *              drawn as a horizontal segment across that interval; values[0] is ignored.
 * mode 'line': values[i] is an instantaneous reading at t[i].
 * series: [{ key, label, color, values }], ≥2 series get a legend.
 */
export const TimeSeries = ({ t, series, mode = 'step', format = v => fmtNum(Math.round(v)), height = 150 }) => {
  const [ref, width] = useWidth()
  const [hover, setHover] = useState(null)
  const m = { l: 52, r: 10, t: 8, b: 22 }
  const n = t.length
  const plotW = Math.max(1, width - m.l - m.r)
  const plotH = height - m.t - m.b
  const t0 = n ? t[0] : 0
  const t1 = n ? t[n - 1] : 1
  const span = Math.max(1, t1 - t0)
  const x = s => m.l + ((s - t0) / span) * plotW
  const all = series.flatMap(s => s.values.filter((v, i) => v !== null && (mode === 'line' || i > 0)))
  const yMax = niceMax(Math.max(0, ...all) || 1)
  const y = v => m.t + plotH - (v / yMax) * plotH
  const ticks = [0, 0.5, 1].map(k => k * yMax)
  const single = series.length === 1

  const pathOf = values => {
    let d = ''
    let pen = false
    for (let i = mode === 'step' ? 1 : 0; i < n; i++) {
      const v = values[i]
      if (v === null || v === undefined) { pen = false; continue }
      if (mode === 'step') {
        d += (pen ? 'L' : 'M') + x(t[i - 1]) + ',' + y(v) + 'L' + x(t[i]) + ',' + y(v)
      } else {
        d += (pen ? 'L' : 'M') + x(t[i]) + ',' + y(v)
      }
      pen = true
    }
    return d
  }
  const areaOf = values => {
    // close the line path down to the baseline, segment by segment
    const segs = pathOf(values).split('M').filter(Boolean)
    return segs.map(s => {
      const pts = s.split('L')
      const first = pts[0].split(',')[0], last = pts[pts.length - 1].split(',')[0]
      return `M${first},${y(0)}L${s}L${last},${y(0)}Z`
    }).join('')
  }

  const onMove = e => {
    const px = e.nativeEvent.offsetX
    const ts = t0 + ((px - m.l) / plotW) * span
    let i
    if (mode === 'step') {
      i = t.findIndex((tt, k) => k > 0 && ts > t[k - 1] && ts <= tt)
      if (i === -1) i = ts <= t0 ? 1 : n - 1
    } else {
      i = 0
      t.forEach((tt, k) => { if (Math.abs(tt - ts) < Math.abs(t[i] - ts)) i = k })
    }
    if (i < 0 || i >= n || (mode === 'step' && i === 0)) return setHover(null)
    setHover({ i, x: px, y: e.nativeEvent.offsetY })
  }

  const hasData = all.length > 0
  const xTickCount = Math.max(2, Math.min(6, Math.floor(plotW / 90)))
  const xTicks = Array.from({ length: xTickCount }, (_, k) => t0 + (span * k) / (xTickCount - 1))

  return (
    <div className="viz" ref={ref} onMouseLeave={() => setHover(null)}>
      {!single &&
        <div className="ts-legend">
          {series.map(s => <span key={s.key}><i className="swatch" style={{ background: s.color }} />{s.label}</span>)}
        </div>}
      {!hasData && <div className="viz-empty">Not enough samples yet.</div>}
      {width > 0 && hasData &&
        <svg width={width} height={height} onMouseMove={onMove} role="img"
             aria-label={series.map(s => s.label).join(', ') + ' over time'}>
          {ticks.map(tk =>
            <g key={tk}>
              <line x1={m.l} x2={width - m.r} y1={y(tk)} y2={y(tk)} className={tk === 0 ? 'viz-base' : 'viz-grid'} />
              <text x={m.l - 6} y={y(tk) + 4} className="viz-tick" textAnchor="end">{format(tk)}</text>
            </g>)}
          {xTicks.map((tk, k) =>
            <text key={k} x={x(tk)} y={height - 6} className="viz-tick"
                  textAnchor={k === 0 ? 'start' : k === xTicks.length - 1 ? 'end' : 'middle'}>
              {(span > 86400 ? fmtDay(tk) + ' ' : '') + fmtClock(tk, false)}
            </text>)}
          {single && <path d={areaOf(series[0].values)} style={{ fill: series[0].color, opacity: 0.1 }} />}
          {series.map(s =>
            <path key={s.key} d={pathOf(s.values)} fill="none" style={{ stroke: s.color }}
                  strokeWidth="2" strokeLinejoin="round" strokeLinecap="round" />)}
          {hover && <>
            {mode === 'step'
              ? <rect x={x(t[hover.i - 1])} y={m.t} width={Math.max(1, x(t[hover.i]) - x(t[hover.i - 1]))} height={plotH} className="ts-band" />
              : <line x1={x(t[hover.i])} x2={x(t[hover.i])} y1={m.t} y2={m.t + plotH} className="ts-cross" />}
            {series.map(s => s.values[hover.i] !== null && s.values[hover.i] !== undefined &&
              <circle key={s.key} cx={x(t[hover.i])} cy={y(s.values[hover.i])} r={4}
                      style={{ fill: s.color }} className="dot" />)}
          </>}
        </svg>}
      {hover &&
        <Tip x={hover.x} y={hover.y} width={width}>
          <div className="tip-head">
            {mode === 'step'
              ? <>{fmtClock(t[hover.i - 1])} – {fmtClock(t[hover.i])} · avg over {fmtNum(t[hover.i] - t[hover.i - 1])} s</>
              : <>{fmtDay(t[hover.i])} {fmtClock(t[hover.i])}</>}
          </div>
          {series.map(s =>
            <div className="tip-row" key={s.key}>
              <strong>{s.values[hover.i] === null || s.values[hover.i] === undefined ? '—' : format(s.values[hover.i])}</strong>
              <span>{!single && <i className="swatch" style={{ background: s.color }} />}{s.label}</span>
            </div>)}
        </Tip>}
    </div>
  )
}

/** Tiny step sparkline for per-interval values (no axes; trend only). */
export const Sparkline = ({ t, values, width = 96, height = 20, color = 'var(--bar)' }) => {
  const n = t.length
  if (n < 2) return <svg width={width} height={height} />
  const t0 = t[0], span = Math.max(1, t[n - 1] - t0)
  const max = Math.max(...values.filter(v => v !== null), 0) || 1
  const x = s => ((s - t0) / span) * (width - 2) + 1
  const y = v => height - 2 - (v / max) * (height - 4)
  let d = ''
  for (let i = 1; i < n; i++) {
    const v = values[i]
    if (v === null) continue
    d += (d ? 'L' : 'M') + x(t[i - 1]) + ',' + y(v) + 'L' + x(t[i]) + ',' + y(v)
  }
  return <svg width={width} height={height} aria-hidden="true">
    <line x1="0" x2={width} y1={height - 1.5} y2={height - 1.5} className="viz-grid" />
    <path d={d} fill="none" style={{ stroke: color }} strokeWidth="1.5" />
  </svg>
}
