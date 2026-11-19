const express = require('express')
const { readTail } = require('../lib/readTail')

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

router.get('/', async (req, res) => {
  try {
    res.json(await readTail(FILE, findLastHeader))
  } catch (e) {
    console.log(e.message)
    res.status(500).json({ error: e.message })
  }
})

module.exports = router
