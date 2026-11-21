import { isEmptyClick } from './useClearOnEmptyClick'

const click = (el, button = 0) => ({ target: el, button })

test('isEmptyClick ignores controls, selectable items and kept areas', () => {
  document.body.innerHTML = `
    <div id="empty"><span id="text">text</span></div>
    <button id="btn"><span id="inbtn">x</span></button>
    <input id="inp" />
    <svg><g data-selectable=""><circle id="bubble" /></g><rect id="bg" /></svg>
    <div data-keep-selection=""><table><tbody><tr><td id="cell">1</td></tr></tbody></table></div>`
  const $ = id => document.getElementById(id)
  expect(isEmptyClick(click($('empty')))).toBe(true)
  expect(isEmptyClick(click($('text')))).toBe(true)
  expect(isEmptyClick(click($('bg')))).toBe(true)
  expect(isEmptyClick(click($('inbtn')))).toBe(false)
  expect(isEmptyClick(click($('inp')))).toBe(false)
  expect(isEmptyClick(click($('bubble')))).toBe(false)
  expect(isEmptyClick(click($('cell')))).toBe(false)
  expect(isEmptyClick(click($('empty'), 2))).toBe(false) // right click
})
