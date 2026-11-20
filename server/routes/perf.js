const express = require('express')
const { readTail } = require('../lib/readTail')
const { perfRange } = require('../lib/perfRange')

const router = express.Router()
const FILE = '/var/log/snort/perf_monitor_base.csv'

// Snort appends to the CSV on every start and writes a new '#timestamp,...' header
// each time. Return the newest header and the rows after it.
const findLastHeader = lines => {
  for (let i = lines.length - 1; i >= 0; i--) {
    if (lines[i].startsWith('#timestamp')) return i
  }
  return -1
}

// GET /perf                         header + every row of the current run (as before)
// GET /perf?since=<epoch s>&points=N rows of the current run from `since` (0 = whole run),
//                                    folded into at most N buckets (default 600), plus run
//                                    start / end: { lines, runStart, runEnd, rows, bucketed, anchor, step }
router.get('/', async (req, res) => {
  try {
    if (req.query.since !== undefined) {
      const since = Number(req.query.since)
      const points = req.query.points === undefined ? 600 : Number(req.query.points)
      if (!Number.isFinite(since) || since < 0) return res.status(400).json({ error: 'since must be epoch seconds' })
      if (!Number.isInteger(points) || points < 10 || points > 5000) return res.status(400).json({ error: 'points must be 10…5000' })
      return res.json(await perfRange(FILE, since, points))
    }
    res.json(await readTail(FILE, findLastHeader))
  } catch (e) {
    console.log(e.message)
    res.status(500).json({ error: e.message })
  }
})

module.exports = router
