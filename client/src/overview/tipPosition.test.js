import { tipPosition } from './charts'

// the tooltip box [left, left + w] must never contain the pointer's x on the pointer's row
const covers = (p, x, y, w) => x >= p.left && x <= p.left + w && y >= p.top

test('tooltip sits right of the pointer when there is room', () => {
  expect(tipPosition(100, 50, 1000, 220)).toEqual({ left: 112, top: 42 })
})

test('near the right edge the tooltip flips to the left of the pointer', () => {
  const p = tipPosition(990, 50, 1000, 220)
  expect(p).toEqual({ left: 990 - 12 - 220, top: 42 })
  expect(covers(p, 990, 50, 220)).toBe(false)
})

test('never covers the pointer anywhere across the container', () => {
  for (let x = 0; x <= 1000; x += 7) {
    const p = tipPosition(x, 50, 1000, 220)
    expect(covers(p, x, 50, 220)).toBe(false)
    expect(p.left).toBeGreaterThanOrEqual(0)
    expect(p.left + 220).toBeLessThanOrEqual(1000)
  }
})

test('a container too narrow for either side puts the tooltip below the pointer', () => {
  const p = tipPosition(150, 50, 300, 220)
  expect(p.top).toBeGreaterThan(50)
  expect(p.left).toBeGreaterThanOrEqual(0)
})
