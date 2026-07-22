import { useState } from 'react'
import Subscriptions from './views/Subscriptions'
import Connections from './views/Connections'

type Tab = 'subs' | 'conns'

export default function App() {
  const [tab, setTab] = useState<Tab>('subs')
  return (
    <div className="app">
      <header className="topbar">
        <div className="brand">
          trust-proxy <span className="brand-sub">console</span>
        </div>
        <nav className="tabs">
          <button className={tab === 'subs' ? 'tab active' : 'tab'} onClick={() => setTab('subs')}>
            订阅 / 节点
          </button>
          <button className={tab === 'conns' ? 'tab active' : 'tab'} onClick={() => setTab('conns')}>
            连接
          </button>
        </nav>
      </header>
      <main className="content">{tab === 'subs' ? <Subscriptions /> : <Connections />}</main>
    </div>
  )
}
