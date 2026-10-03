import React from 'react'
import ReactDOM from 'react-dom/client'
import App from './App'
import './index.css'

const container = document.getElementById('root')

if (!container) {
  throw new Error('#root not found in index.html')
}

// StrictMode double-invokes effects in development; that is intentional and
// catches the races this panel is prone to (query cancellation on unmount).
ReactDOM.createRoot(container).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)