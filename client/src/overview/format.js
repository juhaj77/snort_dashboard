const pad = n => String(n).padStart(2, '0')

export const fmtNum = n => (n ?? 0).toLocaleString('en-US')

export const fmtClock = (sec, withSeconds = true) => {
  const d = new Date(sec * 1000)
  return pad(d.getHours()) + ':' + pad(d.getMinutes()) + (withSeconds ? ':' + pad(d.getSeconds()) : '')
}

export const fmtDay = sec => {
  const d = new Date(sec * 1000)
  return (d.getMonth() + 1) + '/' + d.getDate()
}

export const fmtDateTime = sec => fmtDay(sec) + ' ' + fmtClock(sec)

export const fmtSpan = s => {
  if (!(s > 0)) return '0 s'
  if (s < 90) return Math.round(s) + ' s'
  if (s < 5400) return Math.round(s / 60) + ' min'
  if (s < 172800) return (s / 3600).toFixed(1).replace(/\.0$/, '') + ' h'
  return (s / 86400).toFixed(1).replace(/\.0$/, '') + ' d'
}

export const fmtStep = s => (s < 60 ? s + ' s' : s < 3600 ? s / 60 + ' min' : s < 86400 ? s / 3600 + ' h' : s / 86400 + ' d')

export const hostPort = (ip, port) => {
  if (!ip) return '—'
  if (port === null || port === undefined) return ip
  return ip.includes(':') ? `[${ip}]:${port}` : `${ip}:${port}`
}

/** 0.42 · 7.5 · 312 · 4.2k · 1.3M · 2.1G */
export const fmtCompact = v => {
  if (v === null || v === undefined || !Number.isFinite(v)) return '—'
  const a = Math.abs(v)
  if (a >= 1e9) return (v / 1e9).toFixed(1).replace(/\.0$/, '') + 'G'
  if (a >= 1e6) return (v / 1e6).toFixed(1).replace(/\.0$/, '') + 'M'
  if (a >= 1e4) return Math.round(v / 1e3) + 'k'
  if (a >= 1e3) return (v / 1e3).toFixed(1).replace(/\.0$/, '') + 'k'
  if (a >= 10) return String(Math.round(v))
  if (a === 0) return '0'
  return v.toFixed(a < 1 ? 2 : 1).replace(/\.?0+$/, '')
}

export const fmtBytes = b => {
  if (b === null || b === undefined || !Number.isFinite(b)) return '—'
  const u = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  while (b >= 1024 && i < u.length - 1) { b /= 1024; i++ }
  return (i === 0 ? b : b.toFixed(b < 10 ? 1 : 0)) + ' ' + u[i]
}

export const fmtPct = p => (p === null || p === undefined || !Number.isFinite(p) ? '—'
  : p === 0 ? '0%' : p < 0.01 ? '<0.01%' : p < 1 ? p.toFixed(2) + '%' : p.toFixed(1) + '%')
