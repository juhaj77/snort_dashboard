import React, { useMemo, useState } from 'react'
import { useWidth, Tip } from '../overview/charts'
import { fmtNum } from '../overview/format'
import { groupHosts, packCircles, fmtPeriod, KINDS, KIND_LABEL, LOCAL_GROUP, NONAME_GROUP } from './appidModel'

const MAX_HOSTS = 70
const HEIGHT = 400

export const kindColor = k => `var(--kind-${k})`

/** First label of a host name for the in-bubble label: "sockjs-us3.pusher.com" -> "sockjs-us3". */
const shortName = h => {
  if (!h.named) return h.host.includes(':') ? '…' + h.host.split(':').slice(-2).join(':') : h.host
  const rest = h.host.slice(0, Math.max(0, h.host.length - h.group.length - 1))
  return rest || h.host.split('.')[0]
}

/**
 * Bubble map: one bubble per host (area = sessions), packed into one cluster per base
 * domain. Hosts that repeat on a steady rhythm carry a turning dashed orbit; hosts that
 * just had a session pulse.
 */
const DomainMap = ({ hosts, now, selected, onSelect }) => {
  const [ref, width] = useWidth()
  const [hover, setHover] = useState(null)

  // DNS lookups without a logged name say little about *who* we talk to and would
  // dwarf every other bubble; they stay in the rhythm chart and the list.
  const drawable = useMemo(() => hosts.filter(h => !h.unnamedDns), [hosts])
  const shown = useMemo(() => drawable.slice(0, MAX_HOSTS), [drawable])
  const hidden = drawable.length - shown.length
  const unnamedDns = hosts.filter(h => h.unnamedDns).reduce((a, h) => a + h.count, 0)

  const layout = useMemo(() => {
    const groups = groupHosts(shown).map(g => {
      const inner = packCircles(g.hosts.map(h => ({ h, r: 4 + Math.sqrt(h.count) * 4 })), 3)
      return { ...g, inner: inner.items, r: Math.max(inner.radius + 6, 14) }
    })
    const outer = packCircles(groups, 8)
    const pad = 22 // room for group labels
    const scale = width > 0 && outer.width > 0
      ? Math.min((width - 8) / outer.width, (HEIGHT - pad) / outer.height, 1.6)
      : 1
    return { groups: outer.items, scale, pad }
  }, [shown, width])

  const cx = width / 2
  const cy = (HEIGHT + layout.pad) / 2
  const s = layout.scale
  const sel = selected

  return (
    <div className="viz appid-map" ref={ref} onMouseLeave={() => setHover(null)}>
      {width > 0 && shown.length > 0 &&
        <svg width={width} height={HEIGHT} role="img"
             aria-label="Hosts grouped by domain; bubble size is the number of sessions">
          {layout.groups.map(g => {
            const special = g.group === LOCAL_GROUP || g.group === NONAME_GROUP
            const gx = cx + g.x * s, gy = cy + g.y * s, gr = g.r * s
            const groupDim = sel && !g.hosts.some(h => h.host === sel)
            return (
              <g key={g.group} className="am-group" style={{ transform: `translate(${gx}px, ${gy}px)` }}
                 opacity={groupDim ? 0.35 : 1}>
                <circle r={gr} className={special ? 'am-cluster am-cluster-special' : 'am-cluster'} />
                {g.inner.map(c => {
                  const h = c.h
                  const r = c.r * s
                  const fresh = now - h.last < 8000
                  const isSel = sel === h.host
                  return (
                    <g key={h.host} className="am-host" data-selectable="" style={{ transform: `translate(${c.x * s}px, ${c.y * s}px)` }}
                       onMouseMove={e => setHover({ h, x: e.nativeEvent.offsetX, y: e.nativeEvent.offsetY })}
                       onClick={() => onSelect(isSel ? null : h.host)}>
                      {h.period && <circle r={r + 4} className="am-orbit" />}
                      {fresh && <circle r={r} className="am-pulse" style={{ stroke: kindColor(h.kind) }} />}
                      <circle r={r} className="am-bubble" style={{ fill: kindColor(h.kind) }} />
                      {isSel && <circle r={r + 2} className="am-sel" />}
                      {r >= 20 &&
                        <text className="am-label" textAnchor="middle" dy="0.35em">
                          {(t => (t.length * 6.2 > r * 1.8 ? t.slice(0, Math.max(3, Math.floor(r * 1.8 / 6.2) - 1)) + '…' : t))(shortName(h))}
                        </text>}
                    </g>
                  )
                })}
              </g>
            )
          })}
          {layout.groups.map(g => {
            const special = g.group === LOCAL_GROUP || g.group === NONAME_GROUP
            const gr = g.r * s
            const groupDim = sel && !g.hosts.some(h => h.host === sel)
            return gr >= 22 &&
              <text key={g.group} className={special ? 'am-group-label am-group-special' : 'am-group-label'}
                    style={{ transform: `translate(${cx + g.x * s}px, ${cy + (g.y - g.r) * s - 4}px)` }}
                    opacity={groupDim ? 0.35 : 1} textAnchor="middle">{g.group}</text>
          })}
        </svg>}
      {width > 0 && shown.length === 0 && <div className="viz-empty" style={{ height: HEIGHT }}>No sessions in this window.</div>}
      {hover &&
        <Tip x={hover.x} y={hover.y} width={width}>
          <HostTip h={hover.h} />
          <div className="tip-foot">{sel === hover.h.host ? 'Click to clear' : 'Click to show only this host'}</div>
        </Tip>}
      {(hidden > 0 || unnamedDns > 0) &&
        <div className="card-note">
          {hidden > 0 && <>{fmtNum(hidden)} hosts with fewer sessions are not drawn. </>}
          {unnamedDns > 0 && <>{fmtNum(unnamedDns)} DNS lookups without a logged name are left out. </>}
          They are in the rhythm chart and the list.
        </div>}
    </div>
  )
}

export const HostTip = ({ h }) =>
  <>
    <div className="tip-msg mono">{h.host}</div>
    <div className="tip-head">
      {h.group}{h.groupGuessed ? ' (guessed from address)' : ''}{h.inferred ? ' · name from an earlier TLS session' : ''}
    </div>
    <div className="tip-row"><strong>{fmtNum(h.count)}</strong><span>sessions</span></div>
    {KINDS.filter(k => h.kinds[k] > 0).map(k =>
      <div className="tip-row" key={k}>
        <strong>{fmtNum(h.kinds[k])}</strong>
        <span><i className="swatch" style={{ background: kindColor(k) }} />{KIND_LABEL[k]}</span>
      </div>)}
    {h.period && <div className="tip-row"><strong>↻</strong><span>repeats every {fmtPeriod(h.period)}</span></div>}
    {h.ips.size > 0 &&
      <div className="tip-foot mono">{[...h.ips].slice(0, 3).join(', ')}{h.ips.size > 3 ? ` +${h.ips.size - 3}` : ''}</div>}
    {h.services.size > 0 && <div className="tip-foot">{[...h.services].join(', ')}</div>}
  </>

export default DomainMap
