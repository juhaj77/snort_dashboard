// REST API (server/bin/www, default port 9000) and the AppID socket (port 3009).
const host = window.location.hostname || 'localhost'
export const API = process.env.REACT_APP_API || `http://${host}:9000`
export const SOCKET = process.env.REACT_APP_SOCKET || `ws://${host}:3009`

export const getJson = async (path) => {
  const res = await fetch(API + path)
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`)
  return res.json()
}
