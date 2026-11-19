const express = require('express')
const { lastLines, linesSince, parseJsonLines } = require('../lib/readTail')

const router = express.Router()
const FILE = '/var/log/snort/alert_json.txt'
const MAX = 200000

// GET /alerts_all/:amount            -> the newest `amount` alerts
// GET /alerts_all/:amount?since=<s>  -> alerts with seconds >= s (epoch seconds),
//                                       newest `amount` at most
router.get('/:amount', async (req, res) => {
  const amount = parseInt(req.params.amount, 10)
  if (!(amount > 0)) return res.status(400).json({ error: 'amount must be a positive number' })
  const cap = Math.min(amount, MAX)
  let since = null
  if (req.query.since !== undefined) {
    since = Number(req.query.since)
    if (!Number.isFinite(since)) return res.status(400).json({ error: 'since must be epoch seconds' })
  }
  try {
    const lines = since === null ? await lastLines(FILE, cap) : await linesSince(FILE, since, cap)
    res.json(parseJsonLines(lines))
  } catch (e) {
    console.log(e.message)
    res.status(500).json({ error: e.message })
  }
})

module.exports = router
