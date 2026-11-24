import { useCallback, useEffect, useRef, useState } from 'react'
import { getJson } from './api'

/**
 * Poll a JSON endpoint; keeps the previous data while refetching.
 * `request()` is called on every load and returns { path, meta }; `meta` is kept
 * next to the data it produced (e.g. the `since` used for that fetch).
 * The poll restarts whenever `key` changes. A `request()` returning null fetches nothing
 * (the state is cleared) until the next key change.
 */
export const usePoll = (request, intervalMs, key) => {
  const [state, setState] = useState({ data: null, meta: null, error: null, loading: true, updated: null })
  const timer = useRef(0)
  const alive = useRef(true)
  const requestRef = useRef(request)
  requestRef.current = request
  const load = useCallback(async () => {
    clearTimeout(timer.current)
    const req = requestRef.current()
    if (!req) { setState({ data: null, meta: null, error: null, loading: false, updated: null }); return }
    setState(s => ({ ...s, loading: true }))
    const { path, meta } = req
    try {
      const data = await getJson(path)
      if (alive.current) setState({ data, meta, error: null, loading: false, updated: Date.now() })
    } catch (error) {
      if (alive.current) setState(s => ({ ...s, error, loading: false }))
    }
    if (alive.current) timer.current = setTimeout(load, intervalMs)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, intervalMs])
  useEffect(() => {
    alive.current = true
    load()
    return () => { alive.current = false; clearTimeout(timer.current) }
  }, [load])
  return [state, load]
}

export default usePoll
