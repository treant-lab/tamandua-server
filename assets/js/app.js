// Phoenix LiveView JavaScript
import "phoenix_html"
import {Socket} from "phoenix"
import {LiveSocket} from "phoenix_live_view"
import topbar from "../vendor/topbar"

// Import graph visualization
import { CorrelationGraphViz } from './graph_viz.js'
import { InvestigationGraphViz } from './investigation_graph.js'

// Hooks for LiveView
let Hooks = {}

// Alert Trend Chart Hook
Hooks.AlertTrendChart = {
  mounted() {
    this.renderChart()
  },

  updated() {
    this.renderChart()
  },

  renderChart() {
    const chartData = JSON.parse(this.el.dataset.chart)
    if (!chartData || !chartData.labels || chartData.labels.length === 0) {
      return
    }

    // Clear existing chart
    this.el.innerHTML = ''

    // Create canvas element for chart
    const canvas = document.createElement('canvas')
    canvas.width = this.el.offsetWidth
    canvas.height = this.el.offsetHeight
    this.el.appendChild(canvas)

    const ctx = canvas.getContext('2d')
    const width = canvas.width
    const height = canvas.height

    // Chart configuration
    const padding = { top: 20, right: 20, bottom: 40, left: 50 }
    const chartWidth = width - padding.left - padding.right
    const chartHeight = height - padding.top - padding.bottom

    // Calculate max value for Y-axis
    const maxValue = Math.max(...chartData.total_data, 1)
    const yScale = chartHeight / maxValue
    const xStep = chartWidth / (chartData.labels.length - 1 || 1)

    // Clear canvas
    ctx.clearRect(0, 0, width, height)

    // Draw grid lines
    ctx.strokeStyle = '#e5e7eb'
    ctx.lineWidth = 1
    for (let i = 0; i <= 5; i++) {
      const y = padding.top + (chartHeight / 5) * i
      ctx.beginPath()
      ctx.moveTo(padding.left, y)
      ctx.lineTo(width - padding.right, y)
      ctx.stroke()

      // Y-axis labels
      const value = Math.round(maxValue - (maxValue / 5) * i)
      ctx.fillStyle = '#6b7280'
      ctx.font = '10px sans-serif'
      ctx.textAlign = 'right'
      ctx.fillText(value.toString(), padding.left - 10, y + 4)
    }

    // Draw stacked areas
    const datasets = chartData.datasets.reverse() // Reverse to draw from top to bottom
    let cumulativeData = new Array(chartData.labels.length).fill(0)

    datasets.forEach((dataset) => {
      ctx.fillStyle = dataset.color + '99' // Add transparency
      ctx.beginPath()

      // Draw area path
      chartData.labels.forEach((label, i) => {
        const x = padding.left + i * xStep
        const y = height - padding.bottom - (cumulativeData[i] * yScale)

        if (i === 0) {
          ctx.moveTo(x, y)
        } else {
          ctx.lineTo(x, y)
        }
      })

      // Add dataset values to cumulative
      const newCumulative = cumulativeData.map((cum, i) => cum + dataset.data[i])

      // Complete the area by going back along the new cumulative line
      for (let i = chartData.labels.length - 1; i >= 0; i--) {
        const x = padding.left + i * xStep
        const y = height - padding.bottom - (newCumulative[i] * yScale)
        ctx.lineTo(x, y)
      }

      ctx.closePath()
      ctx.fill()

      cumulativeData = newCumulative
    })

    // Draw X-axis labels
    ctx.fillStyle = '#6b7280'
    ctx.font = '10px sans-serif'
    ctx.textAlign = 'center'
    chartData.labels.forEach((label, i) => {
      if (i % Math.ceil(chartData.labels.length / 8) === 0) {
        const x = padding.left + i * xStep
        ctx.fillText(label, x, height - padding.bottom + 20)
      }
    })
  }
}

// Bulk Alert Actions Hook
Hooks.BulkAlertModal = {
  mounted() {
    this.handleEvent("show-modal", () => {
      this.el.classList.remove("hidden")
    })

    this.handleEvent("hide-modal", () => {
      this.el.classList.add("hidden")
    })

    // Sync form inputs with phx-value attributes on confirm button
    const confirmButton = document.getElementById("confirm-button")
    if (confirmButton) {
      const statusSelect = document.getElementById("status-select")
      const userIdInput = document.getElementById("user-id-input")
      const tagsInput = document.getElementById("tags-input")

      if (statusSelect) {
        statusSelect.addEventListener("change", (e) => {
          confirmButton.setAttribute("phx-value-status", e.target.value)
        })
      }

      if (userIdInput) {
        userIdInput.addEventListener("input", (e) => {
          confirmButton.setAttribute("phx-value-user_id", e.target.value)
        })
      }

      if (tagsInput) {
        tagsInput.addEventListener("input", (e) => {
          confirmButton.setAttribute("phx-value-tags", e.target.value)
        })
      }
    }
  },

  updated() {
    // Re-attach event listeners after update
    const confirmButton = document.getElementById("confirm-button")
    if (confirmButton) {
      const statusSelect = document.getElementById("status-select")
      const userIdInput = document.getElementById("user-id-input")
      const tagsInput = document.getElementById("tags-input")

      if (statusSelect) {
        statusSelect.addEventListener("change", (e) => {
          confirmButton.setAttribute("phx-value-status", e.target.value)
        })
      }

      if (userIdInput) {
        userIdInput.addEventListener("input", (e) => {
          confirmButton.setAttribute("phx-value-user_id", e.target.value)
        })
      }

      if (tagsInput) {
        tagsInput.addEventListener("input", (e) => {
          confirmButton.setAttribute("phx-value-tags", e.target.value)
        })
      }
    }
  }
}

Hooks.MonacoEditor = {
  mounted() {
    // Load Monaco Editor dynamically
    this.loadMonaco().then(() => {
      this.initEditor()
    })
  },

  loadMonaco() {
    return new Promise((resolve) => {
      if (window.monaco) {
        resolve()
        return
      }

      // Load Monaco from CDN
      const script = document.createElement('script')
      script.src = 'https://cdn.jsdelivr.net/npm/monaco-editor@0.45.0/min/vs/loader.js'
      script.onload = () => {
        require.config({ paths: { vs: 'https://cdn.jsdelivr.net/npm/monaco-editor@0.45.0/min/vs' } })
        require(['vs/editor/editor.main'], function() {
          resolve()
        })
      }
      document.head.appendChild(script)
    })
  },

  initEditor() {
    const initialContent = this.el.dataset.content || ''

    this.editor = monaco.editor.create(this.el, {
      value: initialContent,
      language: 'yaml',
      theme: 'vs-dark',
      automaticLayout: true,
      minimap: { enabled: true },
      fontSize: 14,
      lineNumbers: 'on',
      roundedSelection: false,
      scrollBeyondLastLine: false,
      readOnly: false,
      formatOnPaste: true,
      formatOnType: true
    })

    // Debounced validation on content change
    let debounceTimer
    this.editor.onDidChangeModelContent(() => {
      clearTimeout(debounceTimer)
      debounceTimer = setTimeout(() => {
        const content = this.editor.getValue()
        this.pushEvent("validate_yaml", { yaml: content })
      }, 500)
    })

    // Listen for external content updates
    this.handleEvent("load-yaml", ({ content }) => {
      if (this.editor) {
        this.editor.setValue(content)
      }
    })

    // Listen for validation results to show markers
    this.handleEvent("validation-result", ({ status, errors, warnings }) => {
      this.updateMarkers(status, errors, warnings)
    })

    // Store editor value for form submission
    window.getMonacoContent = () => {
      return this.editor ? this.editor.getValue() : ''
    }
  },

  updateMarkers(status, errors, warnings) {
    if (!this.editor) return

    const model = this.editor.getModel()
    if (!model) return

    const markers = []

    // Add error markers
    if (errors && errors.length > 0) {
      errors.forEach((error, index) => {
        markers.push({
          severity: monaco.MarkerSeverity.Error,
          message: error,
          startLineNumber: 1,
          startColumn: 1,
          endLineNumber: 1,
          endColumn: 100
        })
      })
    }

    // Add warning markers
    if (warnings && warnings.length > 0) {
      warnings.forEach((warning, index) => {
        markers.push({
          severity: monaco.MarkerSeverity.Warning,
          message: warning,
          startLineNumber: 1,
          startColumn: 1,
          endLineNumber: 1,
          endColumn: 100
        })
      })
    }

    monaco.editor.setModelMarkers(model, 'yaml-validator', markers)
  },

  destroyed() {
    if (this.editor) {
      this.editor.dispose()
    }
  }
}

// Correlation Graph Hook
Hooks.CorrelationGraph = {
  mounted() {
    // Initialize graph visualization
    this.graph = new CorrelationGraphViz(this.el)
    this.graph.initialize()

    // Load initial data
    const graphData = JSON.parse(this.el.dataset.graph || '{"nodes":[],"links":[]}')
    this.graph.setData(graphData)

    // Set up event handlers
    this.graph.onNodeClick = (node) => {
      this.pushEvent("node_clicked", { node: node })
    }

    this.graph.onLinkClick = (link) => {
      this.pushEvent("link_clicked", { link: link })
    }

    // Listen for LiveView events
    this.handleEvent("update-graph", ({ graph_data }) => {
      this.graph.setData(graph_data)
    })

    this.handleEvent("reset-view", () => {
      this.graph.resetView()
    })

    this.handleEvent("zoom-to-fit", () => {
      this.graph.zoomToFit()
    })

    this.handleEvent("apply-filter", ({ filter }) => {
      this.graph.applyFilter(filter)
    })

    this.handleEvent("clear-filter", () => {
      this.graph.clearFilter()
    })

    this.handleEvent("export-svg", () => {
      const url = this.graph.exportAsSVG()
      const a = document.createElement('a')
      a.href = url
      a.download = `attack-graph-${Date.now()}.svg`
      a.click()
      URL.revokeObjectURL(url)
    })

    this.handleEvent("export-png", () => {
      this.graph.exportAsPNG().then(url => {
        const a = document.createElement('a')
        a.href = url
        a.download = `attack-graph-${Date.now()}.png`
        a.click()
        URL.revokeObjectURL(url)
      })
    })

    // Handle window resize
    this.resizeObserver = new ResizeObserver(() => {
      if (this.graph) {
        this.graph.destroy()
        this.graph.initialize()
        const graphData = JSON.parse(this.el.dataset.graph || '{"nodes":[],"links":[]}')
        this.graph.setData(graphData)
      }
    })
    this.resizeObserver.observe(this.el)
  },

  updated() {
    // Update graph data if changed
    const graphData = JSON.parse(this.el.dataset.graph || '{"nodes":[],"links":[]}')
    if (this.graph) {
      this.graph.setData(graphData)
    }
  },

  destroyed() {
    if (this.resizeObserver) {
      this.resizeObserver.disconnect()
    }
    if (this.graph) {
      this.graph.destroy()
    }
  }
}

// Investigation Graph Hook
Hooks.InvestigationGraph = {
  mounted() {
    // Initialize graph visualization
    this.graph = new InvestigationGraphViz(this.el)
    this.graph.initialize()

    // Set up event handlers
    this.graph.onNodeClick = (node) => {
      this.pushEvent("select_node", { node_id: node.id })
    }

    this.graph.onEdgeClick = (edge) => {
      this.pushEvent("select_edge", { edge_id: edge.id })
    }

    // Listen for LiveView events
    this.handleEvent("initialize-graph", ({ graph }) => {
      this.graph.setData(graph)
    })

    this.handleEvent("update-graph", ({ graph }) => {
      this.graph.setData(graph)
    })

    this.handleEvent("reset-view", () => {
      this.graph.resetView()
    })

    this.handleEvent("zoom-in", () => {
      this.graph.zoomIn()
    })

    this.handleEvent("zoom-out", () => {
      this.graph.zoomOut()
    })

    this.handleEvent("fit-to-screen", () => {
      this.graph.zoomToFit()
    })

    this.handleEvent("export-svg", () => {
      const url = this.graph.exportAsSVG()
      const a = document.createElement('a')
      a.href = url
      a.download = `investigation-graph-${Date.now()}.svg`
      a.click()
      URL.revokeObjectURL(url)
    })

    this.handleEvent("export-png", () => {
      this.graph.exportAsPNG().then(url => {
        const a = document.createElement('a')
        a.href = url
        a.download = `investigation-graph-${Date.now()}.png`
        a.click()
        URL.revokeObjectURL(url)
      })
    })

    this.handleEvent("download-file", ({ filename, content, mime_type }) => {
      const blob = new Blob([content], { type: mime_type })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filename
      a.click()
      URL.revokeObjectURL(url)
    })

    // Handle window resize
    this.resizeObserver = new ResizeObserver(() => {
      if (this.graph) {
        this.graph.destroy()
        this.graph.initialize()
        // Re-render with current data would happen automatically
      }
    })
    this.resizeObserver.observe(this.el)
  },

  destroyed() {
    if (this.resizeObserver) {
      this.resizeObserver.disconnect()
    }
    if (this.graph) {
      this.graph.destroy()
    }
  }
}

let csrfToken = document.querySelector("meta[name='csrf-token']").getAttribute("content")
let liveSocket = new LiveSocket("/live", Socket, {
  params: {_csrf_token: csrfToken},
  hooks: Hooks
})

// Show progress bar on live navigation and form submits
topbar.config({barColors: {0: "#29d"}, shadowColor: "rgba(0, 0, 0, .3)"})
window.addEventListener("phx:page-loading-start", _info => topbar.show(300))
window.addEventListener("phx:page-loading-stop", _info => topbar.hide())

// connect if there are any LiveViews on the page
liveSocket.connect()

// expose liveSocket on window for web console debug logs and latency simulation:
// >> liveSocket.enableDebug()
// >> liveSocket.enableLatencySim(1000)  // enabled for duration of browser session
// >> liveSocket.disableLatencySim()
window.liveSocket = liveSocket

function walletProvider(providerName) {
  const solana = window.solana

  if (providerName === 'phantom' && solana?.isPhantom) {
    return solana
  }

  if (providerName === 'backpack' && window.backpack?.solana) {
    return window.backpack.solana
  }

  if (providerName === 'solflare') {
    return window.solflare || (solana?.isSolflare ? solana : null)
  }

  if (providerName === 'metamask') {
    return solana?.isMetaMask ? solana : null
  }

  return null
}

function shortWallet(address) {
  if (!address || address.length < 12) return address
  return `${address.slice(0, 4)}...${address.slice(-4)}`
}

function bytesToBase64(bytes) {
  let binary = ''
  bytes.forEach((byte) => {
    binary += String.fromCharCode(byte)
  })
  return window.btoa(binary)
}

async function postWalletForm(url, payload) {
  const body = new URLSearchParams(payload)

  const response = await fetch(url, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded;charset=UTF-8',
      'x-csrf-token': csrfToken
    },
    body
  })

  const contentType = response.headers.get('content-type') || ''
  const data = contentType.includes('application/json') ? await response.json() : null
  return { response, data }
}

function setWalletStatus(root, message, state = '') {
  const status = root.querySelector('[data-wallet-status]')
  if (!status) return
  status.textContent = message
  status.dataset.state = state
}

function setRegisterWalletFields(root, payload) {
  Object.entries({
    wallet_address: payload.wallet_address,
    wallet_provider: payload.provider,
    wallet_message: payload.message,
    wallet_signature: payload.signature
  }).forEach(([name, value]) => {
    const input = document.querySelector(`[data-wallet-field="${name}"]`)
    if (input) input.value = value || ''
  })

  root.querySelectorAll('[data-wallet-provider]').forEach((button) => {
    button.dataset.walletConnected = String(button.dataset.walletProvider === payload.provider)
  })
}

function savePendingWallet(wallet) {
  window.sessionStorage?.setItem('tamandua.pendingWallet', JSON.stringify({
    wallet_address: wallet.wallet_address,
    provider: wallet.provider,
    message: wallet.message,
    signature: wallet.signature
  }))
}

function takePendingWallet() {
  const storage = window.sessionStorage
  if (!storage) return null

  const raw = storage.getItem('tamandua.pendingWallet')
  if (!raw) return null

  storage.removeItem('tamandua.pendingWallet')

  try {
    return JSON.parse(raw)
  } catch (_error) {
    return null
  }
}

async function connectAndSign(providerName) {
  const provider = walletProvider(providerName)
  if (!provider) {
    throw new Error(`${providerName} Solana provider is not available in this browser`)
  }

  const connectResult = await provider.connect()
  const publicKey = connectResult?.publicKey || provider.publicKey
  const walletAddress = publicKey?.toString()

  if (!walletAddress) {
    throw new Error('Wallet did not return a public key')
  }

  const { response, data } = await postWalletForm('/wallet/challenge', {
    wallet_address: walletAddress,
    provider: providerName
  })

  if (!response.ok) {
    throw new Error(data?.error || 'Could not create wallet challenge')
  }

  const encodedMessage = new TextEncoder().encode(data.message)
  const signed = await provider.signMessage(encodedMessage, 'utf8')
  const signatureBytes = signed?.signature || signed
  const signature = `base64:${bytesToBase64(signatureBytes)}`

  return {
    wallet_address: walletAddress,
    provider: providerName,
    message: data.message,
    signature
  }
}

function initWalletAuth() {
  document.querySelectorAll('[data-wallet-auth]').forEach((root) => {
    const mode = root.dataset.walletAuth

    if (mode === 'register') {
      const pendingWallet = takePendingWallet()

      if (pendingWallet?.wallet_address && pendingWallet?.message && pendingWallet?.signature) {
        setRegisterWalletFields(root, pendingWallet)
        setWalletStatus(root, `Linked ${shortWallet(pendingWallet.wallet_address)} for sign-up`, 'success')
      }
    }

    root.querySelectorAll('[data-wallet-provider]').forEach((button) => {
      const providerName = button.dataset.walletProvider
      const provider = walletProvider(providerName)

      if (!provider) {
        button.disabled = true
        button.title =
          providerName === 'metamask'
            ? 'MetaMask Solana provider was not detected'
            : `${button.textContent} was not detected`
      }

      button.addEventListener('click', async () => {
        button.disabled = true
        setWalletStatus(root, `Connecting ${button.textContent}...`)

        try {
          const wallet = await connectAndSign(providerName)

          if (mode === 'register') {
            setRegisterWalletFields(root, wallet)
            setWalletStatus(root, `Linked ${shortWallet(wallet.wallet_address)} for sign-up`, 'success')
            return
          }

          setWalletStatus(root, `Verifying ${shortWallet(wallet.wallet_address)}...`)
          const { response, data } = await postWalletForm('/wallet/login', wallet)

          if (response.redirected) {
            window.location.href = response.url
            return
          }

          if (response.ok) {
            window.location.href = '/app/dashboard'
            return
          }

          if (response.status === 404 && data?.register_url) {
            savePendingWallet(wallet)
            window.location.href = data.register_url
            return
          }

          throw new Error(data?.error || 'Wallet sign-in failed')
        } catch (error) {
          setWalletStatus(root, error.message, 'error')
        } finally {
          button.disabled = !walletProvider(providerName)
        }
      })
    })
  })
}

initWalletAuth()
