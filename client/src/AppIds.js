import React, { useState, useEffect, useRef } from 'react'
import io from 'socket.io-client'
import AppId from './AppId';
import { Panel, Status } from './Panel';
import { SOCKET } from './api';

const socket = io(SOCKET)

function AppIds() {
  const [appIdArray, setAppIdArray] = useState([])
  const [connected, setConnected] = useState(socket.connected)
  const count = useRef(0)

  useEffect(() => {
    const array = []
    const onJson = data => {
      if (array.length > 0 && array[array.length - 1].pkt_time === data.pkt_time) return
      count.current += 1
      data.count = count.current
      array.push(data)
      if (array.length > 40) array.shift()
      setAppIdArray([...array].reverse())
    }
    const onConnect = () => setConnected(true)
    const onDisconnect = () => setConnected(false)
    socket.on('json', onJson)
    socket.on('connect', onConnect)
    socket.on('disconnect', onDisconnect)
    return () => {
      socket.off('json', onJson)
      socket.off('connect', onConnect)
      socket.off('disconnect', onDisconnect)
    }
  }, [])

  const live = <span className={connected ? 'live live-on' : 'live'}>
    <span className="dot" />{connected ? 'live' : 'disconnected'}
  </span>

  return (
    <Panel title="AppID · live sessions" accent="blue" right={live}
           description="Application identification events streamed from appid.json as Snort writes them, newest first. Unknown services are highlighted.">
      {appIdArray.length === 0
        ? <Status text={connected ? 'Connected, waiting for AppID events…' : 'Connecting to the AppID stream…'} />
        : <div className="table-wrap">
            <table className="grid">
              <thead>
                <tr>
                  <th>#</th><th>Session</th><th>Packet time</th><th>Service</th><th>Client</th>
                  <th>Proto</th><th>Client IP</th><th>Port</th><th>Service IP</th><th>Port</th>
                  <th>DNS host</th><th>TLS host</th>
                </tr>
              </thead>
              <tbody>
                {appIdArray.map(e => <AppId key={e.count} json={e} />)}
              </tbody>
            </table>
          </div>}
    </Panel>
  )
}

export default AppIds;
