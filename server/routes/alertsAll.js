const express = require('express')
const { lastLines, linesSince, parseJsonLines } = require('../lib/readTail')
const { alertsBetween } = require('../lib/alertStats')

const router = express.Router()
const FILE = '/var/log/snort/alert_json.txt'
const MAX = 200000

// GET /alerts_all/:amount            -> the newest `amount` alerts
// GET /alerts_all/:amount?since=<s>  -> alerts with seconds >= s (epoch seconds),
//                                       newest `amount` at most
// GET /alerts_all/:amount?since=<s>&until=<s>&rule=<gid:sid:rev>
//                                    -> alerts in [since, until], optionally of one rule
router.get('/:amount', async (req, res) => {
  const amount = parseInt(req.params.amount, 10)
  if (!(amount > 0)) return res.status(400).json({ error: 'amount must be a positive number' })
  const cap = Math.min(amount, MAX)
  let since = null
  if (req.query.since !== undefined) {
    since = Number(req.query.since)
    if (!Number.isFinite(since)) return res.status(400).json({ error: 'since must be epoch seconds' })
  }
  const until = req.query.until === undefined ? null : Number(req.query.until)
  const rule = req.query.rule ? String(req.query.rule) : null
  if (until !== null && !Number.isFinite(until)) return res.status(400).json({ error: 'until must be epoch seconds' })
  try {
    if (until !== null || rule) {
      return res.json(await alertsBetween(FILE, { since: since ?? 0, until: until ?? Infinity, rule, cap }))
    }
    const lines = since === null ? await lastLines(FILE, cap) : await linesSince(FILE, since, cap)
    res.json(parseJsonLines(lines))
  } catch (e) {
    console.log(e.message)
    res.status(500).json({ error: e.message })
  }
})

module.exports = router
