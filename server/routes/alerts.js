const express = require('express')
const { lastLines, parseJsonLines } = require('../lib/readTail')

const router = express.Router()
const FILE = '/var/log/snort/alert_json.txt'

router.get('/', async (req, res) => {
  try {
    res.json(parseJsonLines(await lastLines(FILE, 100)))
  } catch (e) {
    console.log(e.message)
    res.status(500).json({ error: e.message })
  }
})

module.exports = router
