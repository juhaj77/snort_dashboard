const express = require('express')
const { alertStats } = require('../lib/alertStats')

const router = express.Router()
const FILE = '/var/log/snort/alert_json.txt'
const MAX_BINS = 500
const MAX_SPAN = 7 * 86400

// GET /alerts_stats?since=<s>&step=<s>[&until=<s>]
//   -> alert counts per rule and time bin (see lib/alertStats.js)
router.get('/', async (req, res) => {
  const now = Date.now() / 1000
  const since = Number(req.query.since)
  const step = Number(req.query.step)
  const until = req.query.until === undefined ? now : Number(req.query.until)
  if (![since, step, until].every(Number.isFinite) || step <= 0 || until <= since) {
    return res.status(400).json({ error: 'since, step (and until) must be epoch seconds, since < until, step > 0' })
  }
  if (until - since > MAX_SPAN || (until - since) / step > MAX_BINS) {
    return res.status(400).json({ error: `at most ${MAX_SPAN / 86400} days and ${MAX_BINS} bins` })
  }
  try {
    res.json(await alertStats(FILE, { since, until, step }))
  } catch (e) {
    if (e.code === 'ENOENT') {
      return res.json({ since, until, step, bins: Math.ceil((until - since) / step), total: 0, rules: [] })
    }
    console.log(e.message)
    res.status(500).json({ error: e.message })
  }
})

module.exports = router
