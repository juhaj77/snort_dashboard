// Finds alert bursts that are unusual *for their own rule*: a rule firing 500 times
// every 5 minutes is normal noise, the same rule jumping to 2000, or a rule that is
// normally silent firing 20 times, is not. Works on the per-rule bin counts from
// /alerts_stats. Pure functions, unit-tested.

const median = xs => {
  if (!xs.length) return 0
  const s = [...xs].sort((a, b) => a - b)
  const m = Math.floor(s.length / 2)
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2
}

/** Weight of a Snort priority in the ranking: P1 counts most, P0 (no priority) least. */
const PRIO_WEIGHT = { 1: 1.6, 2: 1.3, 3: 1, 4: 0.9, 0: 0.8 }

export const SURPRISE_MIN = 2   // log2 ratio: ≥ 4× the expected count
export const EXCESS_MIN = 5     // and at least this many alerts above it

/**
 * Score every bin of one rule against what the rule usually does in this window.
 * expected = mean of (median, leave-one-out mean): the median ignores the burst, the
 * mean keeps sparse-but-regular rules from lighting up on every single alert.
 * surprise = log2((count + 1) / (expected + 1)); 0 = as usual, 1 = twice, 3 = 8 ×.
 */
export const scoreRule = (counts, priority = 3) => {
  const n = counts.length
  const total = counts.reduce((a, c) => a + c, 0)
  const med = median(counts)
  const highPrio = priority === 1 || priority === 2
  return counts.map(c => {
    const loo = n > 1 ? (total - c) / (n - 1) : 0
    const expected = (med + loo) / 2
    const surprise = Math.log2((c + 1) / (expected + 1))
    const excess = c - expected
    // a high-priority rule that is otherwise silent is worth a look even once
    const rareHigh = highPrio && c > 0 && expected < 0.5
    const unusual = c > 0 && ((surprise >= SURPRISE_MIN && excess >= EXCESS_MIN) || rareHigh)
    return { count: c, expected, surprise: c > 0 ? Math.max(0, surprise) : 0, unusual }
  })
}

/**
 * Per-rule scores plus episodes: runs of unusual bins (a one-bin gap is bridged).
 * Returns { rules, episodes }, rules sorted with the most unusual first.
 */
export const analyse = stats => {
  if (!stats || !Array.isArray(stats.rules)) return { rules: [], episodes: [] }
  const { since, step } = stats
  const episodes = []
  const rules = stats.rules.map(r => {
    const cells = scoreRule(r.counts, r.priority)
    const firstBin = r.counts.findIndex(c => c > 0)
    let run = null
    const close = () => {
      if (!run) return
      const bins = run.bins
      const count = bins.reduce((a, b) => a + cells[b].count, 0)
      const expected = bins.reduce((a, b) => a + cells[b].expected, 0)
      const peak = Math.max(...bins.map(b => cells[b].surprise))
      const src = new Map(), dst = new Map()
      for (const b of bins) {
        const c = r.cells && r.cells[b]
        if (!c) continue
        c.src.forEach(([ip, k]) => src.set(ip, (src.get(ip) || 0) + k))
        c.dst.forEach(([ip, k]) => dst.set(ip, (dst.get(ip) || 0) + k))
      }
      const topOf = m => [...m.entries()].sort((a, b) => b[1] - a[1]).slice(0, 3)
      // the rule had not fired earlier in the window
      const isNew = bins[0] === firstBin && firstBin > 0
      // a P1/P2 rule that is otherwise silent ranks high however few alerts it has
      const rareHigh = (r.priority === 1 || r.priority === 2) && expected / bins.length < 0.5
      episodes.push({
        id: `${r.rule}@${bins[0]}`, rule: r.rule, msg: r.msg, priority: r.priority, cls: r.cls,
        fromBin: bins[0], toBin: bins[bins.length - 1],
        from: since + bins[0] * step, to: since + (bins[bins.length - 1] + 1) * step,
        count, expected, peak,
        isNew, rareHigh,
        score: peak * PRIO_WEIGHT[r.priority ?? 0] * (1 + Math.log10(1 + count) / 2) +
          (isNew ? 2 : 0) + (rareHigh ? 6 : 0),
        src: topOf(src), dst: topOf(dst),
      })
      run = null
    }
    cells.forEach((c, b) => {
      if (c.unusual) {
        if (run && b - run.last <= 2) { run.bins.push(b); run.last = b }
        else { close(); run = { bins: [b], last: b } }
      }
    })
    close()
    const maxSurprise = Math.max(0, ...cells.map(c => c.surprise))
    const unusualBins = cells.filter(c => c.unusual).length
    return {
      ...r, scores: cells, maxSurprise, unusualBins,
      rare: r.total > 0 && r.total <= 3,
      rank: maxSurprise * PRIO_WEIGHT[r.priority ?? 0] + (unusualBins ? 10 : 0),
    }
  }).sort((a, b) => b.rank - a.rank || b.total - a.total)
  episodes.sort((a, b) => b.score - a.score)
  return { rules, episodes }
}

/** Bin size giving roughly `target` columns for a window: 1 min, 2, 5, 10, 15, 20, 30, 60 … */
export const pickStep = (seconds, target = 72) => {
  const steps = [60, 120, 300, 600, 900, 1200, 1800, 3600, 7200]
  return steps.find(s => seconds / s <= target) || steps[steps.length - 1]
}
