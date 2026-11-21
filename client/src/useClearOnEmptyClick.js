import { useEffect } from 'react'

// Clicks on these keep the current selection: controls, things that select something
// themselves (mark them with data-selectable) and content areas where clicking is for
// reading or copying, such as tables (mark them with data-keep-selection).
const KEEP = [
  'button', 'a', 'input', 'select', 'textarea', 'label', 'summary', 'option',
  '[role="tab"]', '[role="button"]', '[data-selectable]', '[data-keep-selection]',
].join(', ')

/** True when a click should clear the selection: on empty space or something not selectable. */
export const isEmptyClick = e => {
  if (e.button !== 0) return false
  const t = e.target
  if (!t || typeof t.closest !== 'function' || t.closest(KEEP)) return false
  // the click that ends a text selection (e.g. copying an address) is not a "click away"
  const sel = typeof window.getSelection === 'function' ? window.getSelection() : null
  return !(sel && !sel.isCollapsed && String(sel).trim())
}

/**
 * While `active`, a click anywhere on the page that does not hit a control or a
 * selectable item calls `clear`. The listener sits on the document, so it runs after
 * React's own click handlers: clicking another item selects it instead.
 */
const useClearOnEmptyClick = (active, clear) => {
  useEffect(() => {
    if (!active) return
    const onClick = e => { if (isEmptyClick(e)) clear() }
    document.addEventListener('click', onClick)
    return () => document.removeEventListener('click', onClick)
  }, [active, clear])
}

export default useClearOnEmptyClick
