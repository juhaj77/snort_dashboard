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
