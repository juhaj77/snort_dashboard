const express = require('express')
const { lastLines, parseJsonLines } = require('../lib/readTail')

const router = express.Router()
const FILE = '/var/log/snort/appid.json'
const MAX = 100000

// Recent AppID events from appid.json (the live socket only delivers new lines).
// Note: appid_listener truncates this file when Snort restarts.
router.get('/:amount', async (req, res) => {
  const amount = parseInt(req.params.amount, 10)
  if (!(amount > 0)) return res.status(400).json({ error: 'amount must be a positive number' })
  try {
    res.json(parseJsonLines(await lastLines(FILE, Math.min(amount, MAX))))
  } catch (e) {
    if (e.code === 'ENOENT') return res.json([])
    console.log(e.message)
    res.status(500).json({ error: e.message })
  }
})

module.exports = router
