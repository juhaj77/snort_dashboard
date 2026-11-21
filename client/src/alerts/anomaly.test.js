import { scoreRule, analyse, pickStep } from './anomaly'

test('a steady flood is normal, a jump of the same rule is unusual', () => {
  const counts = Array(20).fill(400); counts[12] = 2000
  const s = scoreRule(counts, 3)
  expect(s[0]).toMatchObject({ count: 400, unusual: false })
  expect(s[0].surprise).toBeLessThan(0.1)
  expect(s[12].unusual).toBe(true)
  expect(s[12].surprise).toBeGreaterThan(2)
})

test('a sparse but regular rule does not light up on every alert', () => {
  const counts = Array(40).fill(0).map((_, i) => (i % 3 === 0 ? 1 : 0))
  expect(scoreRule(counts, 3).some(c => c.unusual)).toBe(false)
  counts[20] = 12
  expect(scoreRule(counts, 3)[20].unusual).toBe(true)
})

test('a silent P1/P2 rule firing once is unusual; a P3 one is not', () => {
  const counts = Array(30).fill(0); counts[29] = 1
  expect(scoreRule(counts, 2)[29].unusual).toBe(true)
  expect(scoreRule(counts, 3)[29].unusual).toBe(false)
})

test('analyse merges neighbouring unusual bins into one episode and ranks it', () => {
  const quiet = Array(30).fill(0); quiet[10] = 9; quiet[11] = 0; quiet[12] = 7
  const noisy = Array(30).fill(100)
  const res = analyse({ since: 1000, step: 60, bins: 30, rules: [
    { rule: 'n', msg: 'noise', priority: 3, total: 3000, counts: noisy, cells: {} },
    { rule: 'q', msg: 'quiet', priority: 3, total: 16, counts: quiet,
      cells: { 10: { src: [['a', 9]], dst: [['b', 9]] }, 12: { src: [['a', 3], ['c', 4]], dst: [] } } },
  ] })
  expect(res.rules.map(r => r.rule)).toEqual(['q', 'n'])
  expect(res.episodes).toHaveLength(1)
  expect(res.episodes[0]).toMatchObject({ rule: 'q', fromBin: 10, toBin: 12, count: 16, from: 1600, to: 1780, isNew: true })
  expect(res.episodes[0].src[0]).toEqual(['a', 12])
})

test('analyse tolerates missing data and pickStep gives ~72 columns', () => {
  expect(analyse(null)).toEqual({ rules: [], episodes: [] })
  expect(analyse([])).toEqual({ rules: [], episodes: [] })
  expect(pickStep(3600)).toBe(60)
  expect(pickStep(6 * 3600)).toBe(300)
  expect(pickStep(86400)).toBe(1200)
})
