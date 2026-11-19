import React, { useState } from 'react'
import './App.css';
import Alerts from './Alerts';
import AppIds from './AppIds';
import Search from './Search';
import Perf from './Perf';

const TABS = [
  ['ALERTS', 'Alerts', Alerts],
  ['APPID', 'AppID', AppIds],
  ['SEARCH', 'Search', Search],
  ['PERF', 'Performance', Perf],
]

const App = () => {
  const [show, setShow] = useState('ALERTS')
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
