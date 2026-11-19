const fs = require('fs')

const CHUNK = 64 * 1024

/**
 * Read lines from the end of a file without loading the whole file.
 * Reads backwards in chunks and stops as soon as `stop(lines)` is satisfied,
 * where `lines` are the complete lines collected so far (oldest first).
 *
 * @param {string} file
 * @param {(lines: string[]) => number | -1} findStart
 *        returns the index in `lines` where the result starts, or -1 to keep reading
 * @returns {Promise<string[]>}
 */
async function readTail(file, findStart) {
  const fh = await fs.promises.open(file, 'r')
  try {
    const { size } = await fh.stat()
    let pos = size
    let carry = Buffer.alloc(0) // bytes of a line cut by the chunk boundary
    let lines = []
    while (pos > 0) {
      const len = Math.min(CHUNK, pos)
      pos -= len
      const buf = Buffer.alloc(len)
      await fh.read(buf, 0, len, pos)
      const data = Buffer.concat([buf, carry])
      const text = data.toString('utf8')
      const firstNl = pos > 0 ? text.indexOf('\n') : -1
      if (pos > 0 && firstNl === -1) {
        carry = data
        continue
      }
      // keep the (possibly partial) first line for the next round
      carry = pos > 0 ? Buffer.from(text.slice(0, firstNl)) : Buffer.alloc(0)
      const complete = (pos > 0 ? text.slice(firstNl + 1) : text)
        .split('\n')
        .filter(l => l.trim() !== '')
      lines = complete.concat(lines)
      const start = findStart(lines)
      if (start !== -1) return lines.slice(start)
    }
    if (carry.length) lines = [carry.toString('utf8')].concat(lines)
    const start = findStart(lines)
    return start === -1 ? lines : lines.slice(start)
  } finally {
    await fh.close()
  }
}

/** Last `n` non-empty lines of a file. */
const lastLines = (file, n) =>
  readTail(file, lines => (lines.length >= n ? lines.length - n : -1))

/** Parse JSON lines, skipping any line that is incomplete or malformed. */
const parseJsonLines = lines =>
  lines.reduce((out, l) => {
    try {
      out.push(JSON.parse(l))
    } catch (e) {
      /* half-written line while Snort is appending */
    }
    return out
  }, [])

module.exports = { readTail, lastLines, parseJsonLines }
