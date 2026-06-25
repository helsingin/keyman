import React from 'react'
import { createRoot } from 'react-dom/client'
import { FocusStyleManager } from '@blueprintjs/core'
import 'normalize.css'
import '@blueprintjs/core/lib/css/blueprint.css'
import '@blueprintjs/icons/lib/css/blueprint-icons.css'
import './styles/alliance.css'
import './styles/console.css'
import { App } from './App'

FocusStyleManager.onlyShowFocusOnTabs()

createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
)
