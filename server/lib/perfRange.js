// perf_monitor_base.csv for a time range of the current Snort run, downsampled.
//
// The file can hold a run of months (one row per sample, hundreds of columns). This module
// - remembers where the newest '#timestamp' header is (found once by a forward scan, then
//   only newly appended bytes are scanned), so the header never has to be searched again;
// - reads the file backwards from the end only down to `since`;
// - folds rows into at most `points` buckets: counters (per-interval values) are summed,
//   gauges (current_*, max_*, ...) keep the newest value. Rates computed from a bucket
//   (sum / bucket interval) stay correct because each bucket's timestamp is its newest row.
// One row older than `since` is returned first as an anchor: it marks where the first
// interval starts and is not part of the totals.
const fs = require('fs')
const { eachLineBackwards } = require('./readTail')

const CHUNK = 256 * 1024
const GAUGE = /(^|\.)(current_|concurrent_|max_concurrent|bytes_in_use|items_in_use|memory$|max$|max_)/

const cache = new Map() // file → { ino, scanned, offset, line, runStart }

/** Find (or update) the newest header by scanning only bytes not scanned before. */
const headerOf = async file => {
  const st = await fs.promises.stat(file)
  let c = cache.get(file)
  if (!c || c.ino !== st.ino || st.size < c.scanned) c = { ino: st.ino, scanned: 0, offset: -1, line: null, runStart: null }
  if (st.size > c.scanned) {
    const fh = await fs.promises.open(file, 'r')
    try {
      const MARK = '#timestamp'
      const found = off => { c.offset = off; c.line = null; c.runStart = null }
      // line starts at absolute offsets; the previous scan ended at a line boundary unless
      // Snort was mid-write, in which case the first partial line is skipped
      let pos = c.scanned, lineStart = 0
      if (pos > 0) {
        const prev = Buffer.alloc(1)
        await fh.read(prev, 0, 1, pos - 1)
        lineStart = prev[0] === 10 ? pos : -1
      }
      while (pos < st.size) {
        const len = Math.min(CHUNK, st.size - pos)
        const buf = Buffer.alloc(len)
        await fh.read(buf, 0, len, pos)
        const text = buf.toString('latin1') // 1 byte = 1 char keeps offsets exact
        let i = 0
        for (;;) {
          if (lineStart >= pos) {
            const rel = lineStart - pos
            if (rel + MARK.length <= text.length) { if (text.startsWith(MARK, rel)) found(lineStart) }
            else { // header possibly split across chunks: peek directly
              const peek = Buffer.alloc(MARK.length)
              const { bytesRead } = await fh.read(peek, 0, MARK.length, lineStart)
              if (peek.toString('latin1', 0, bytesRead) === MARK) found(lineStart)
            }
          }
          const nl = text.indexOf('\n', i)
          if (nl === -1) break
          lineStart = pos + nl + 1
          i = nl + 1
        }
        pos += len
      }
      c.scanned = st.size
      if (c.offset >= 0 && (c.line === null || c.runStart === null)) {
        const buf = Buffer.alloc(Math.min(1024 * 1024, st.size - c.offset))
        await fh.read(buf, 0, buf.length, c.offset)
        const lines = buf.toString('utf8').split('\n')
        c.line = lines[0].replace(/\r$/, '')
        const first = lines.slice(1).find(l => /^\d/.test(l))
        c.runStart = first ? Number(first.slice(0, first.indexOf(','))) : null
      }
    } finally { await fh.close() }
  }
  cache.set(file, c)
  return { ...c, size: st.size }
}

/**
 * @returns {Promise<{lines: string[], runStart: number|null, runEnd: number|null,
 *           rows: number, bucketed: boolean, anchor: boolean, step: number|null}>}
 */
const perfRange = async (file, since, points = 600) => {
  const h = await headerOf(file)
  const empty = { lines: [], runStart: null, runEnd: null, rows: 0, bucketed: false, anchor: false, step: null }
  if (h.offset < 0 || !h.line) return empty
  const columns = h.line.replace(/^#/, '').split(',')
  const gauge = columns.map((c, i) => i > 0 && GAUGE.test(c))
  const dataStart = h.offset + Buffer.byteLength(h.line) + 1

  // newest complete row gives the end of the range
  let runEnd = null
  await eachLineBackwards(file, h.size, dataStart, l => {
    const t = Number(l.slice(0, l.indexOf(',')))
    if (Number.isFinite(t)) { runEnd = t; return false }
    return true
  })
  if (runEnd === null) return { ...empty, lines: [h.line], runStart: h.runStart }

  const from = Math.max(since || 0, h.runStart || 0)
  const step = Math.max(1, (runEnd - from) / Math.max(1, points))
  const buckets = new Map() // index → { t, values }
  let anchor = null, rows = 0
  await eachLineBackwards(file, h.size, dataStart, l => {
    const r = l.split(',')
    if (r.length !== columns.length) return true // malformed / half-written
    const t = Number(r[0])
    if (!Number.isFinite(t)) return true
    if (t < from) { anchor = r; return false }
    rows += 1
    const k = Math.floor((runEnd - t) / step)
    const b = buckets.get(k)
    if (!b) { buckets.set(k, { t, values: r.map(Number) }); return true }
    for (let i = 1; i < r.length; i++) {
      if (gauge[i]) continue // newest value already there
      const v = Number(r[i])
      if (Number.isFinite(v)) b.values[i] = (Number.isFinite(b.values[i]) ? b.values[i] : 0) + v
    }
    return true
  })
  const out = [...buckets.values()].sort((a, b) => a.t - b.t)
    .map(b => [b.t, ...b.values.slice(1).map(v => (Number.isFinite(v) ? v : ''))].join(','))
  if (anchor) out.unshift(anchor.join(','))
  return {
    lines: [h.line, ...out], runStart: h.runStart, runEnd, rows,
    bucketed: buckets.size < rows, anchor: !!anchor, step: buckets.size < rows ? step : null,
  }
}

module.exports = { perfRange, headerOf }
