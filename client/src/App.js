import React, { useState } from 'react'
import './App.css';
import AlertsTab from './alerts/AlertsTab';
import AppIds from './AppIds';
import Perf from './Perf';
import Overview from './overview/Overview';
import Network from './network/Network';

const TABS = [
  ['OVERVIEW', 'Overview', Overview],
  ['NETWORK', 'Network', Network],
  ['ALERTS', 'Alerts', AlertsTab],
  ['APPID', 'AppID', AppIds],
  ['PERF', 'Performance', Perf],
]

const App = () => {
  const [show, setShow] = useState('OVERVIEW')
  const View = TABS.find(t => t[0] === show)[2]
  return (
    <div className="app">
      <nav className="tabs">
        <span className="brand">Snort log</span>
        {TABS.map(([id, label]) =>
          <button key={id}
                  className={id === show ? 'tab tab-active' : 'tab'}
                  onClick={() => setShow(id)}>{label}</button>)}
      </nav>
      <main className="content">
        <View />
      </main>
    </div>
  )
}

export default App;
