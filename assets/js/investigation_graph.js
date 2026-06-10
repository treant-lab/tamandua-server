/**
 * Investigation Graph Visualization using D3.js
 *
 * Renders interactive force-directed graph showing:
 * - Process execution trees
 * - File operations
 * - Network connections
 * - DNS queries
 * - Registry modifications
 * - Module loads
 * - User contexts
 */

import * as d3 from 'd3'

export class InvestigationGraphViz {
  constructor(container) {
    this.container = container
    this.svg = null
    this.simulation = null
    this.nodes = []
    this.edges = []
    this.width = 0
    this.height = 0
    this.transform = d3.zoomIdentity

    // Node colors by type
    this.nodeColors = {
      process: '#3b82f6',     // blue
      file: '#10b981',        // green
      network: '#a855f7',     // purple
      dns: '#eab308',         // yellow
      registry: '#ef4444',    // red
      user: '#06b6d4',        // cyan
      module: '#f97316',      // orange
      alert: '#ec4899'        // pink
    }

    // Edge colors by type
    this.edgeColors = {
      spawns: '#10b981',
      executes: '#3b82f6',
      creates: '#10b981',
      writes: '#eab308',
      reads: '#06b6d4',
      deletes: '#ef4444',
      modifies: '#eab308',
      connects_to: '#a855f7',
      resolves: '#eab308',
      loads: '#f97316'
    }

    // Callbacks
    this.onNodeClick = null
    this.onEdgeClick = null
  }

  initialize() {
    // Get container dimensions
    this.width = this.container.clientWidth
    this.height = this.container.clientHeight

    // Create SVG
    this.svg = d3.select(this.container)
      .append('svg')
      .attr('width', this.width)
      .attr('height', this.height)
      .attr('class', 'investigation-graph')

    // Create container groups
    this.g = this.svg.append('g')
      .attr('class', 'graph-container')

    this.edgesGroup = this.g.append('g').attr('class', 'edges')
    this.nodesGroup = this.g.append('g').attr('class', 'nodes')

    // Add zoom behavior
    const zoom = d3.zoom()
      .scaleExtent([0.1, 10])
      .on('zoom', (event) => {
        this.transform = event.transform
        this.g.attr('transform', event.transform)
      })

    this.svg.call(zoom)
    this.zoomBehavior = zoom

    // Initialize force simulation
    this.simulation = d3.forceSimulation()
      .force('link', d3.forceLink().id(d => d.id).distance(100))
      .force('charge', d3.forceManyBody().strength(-300))
      .force('center', d3.forceCenter(this.width / 2, this.height / 2))
      .force('collision', d3.forceCollide().radius(30))
      .on('tick', () => this.ticked())
  }

  setData(graphData) {
    // Clear existing data
    this.nodes = []
    this.edges = []

    if (!graphData || !graphData.nodes || !graphData.edges) {
      this.render()
      return
    }

    // Process nodes
    this.nodes = graphData.nodes.map(node => ({
      ...node,
      id: node.id,
      type: node.type,
      label: node.label,
      suspicious: node.suspicious || false,
      mitre_techniques: node.mitre_techniques || [],
      metadata: node.metadata || {}
    }))

    // Process edges
    this.edges = graphData.edges.map(edge => ({
      ...edge,
      source: edge.source,
      target: edge.target,
      type: edge.type,
      label: edge.label || edge.type
    }))

    this.render()
  }

  render() {
    // Update simulation
    this.simulation.nodes(this.nodes)
    this.simulation.force('link').links(this.edges)
    this.simulation.alpha(1).restart()

    // Render edges
    const edgeSelection = this.edgesGroup
      .selectAll('g.edge')
      .data(this.edges, d => d.id || `${d.source.id || d.source}-${d.target.id || d.target}`)

    edgeSelection.exit().remove()

    const edgeEnter = edgeSelection.enter()
      .append('g')
      .attr('class', 'edge')
      .style('cursor', 'pointer')
      .on('click', (event, d) => {
        event.stopPropagation()
        if (this.onEdgeClick) {
          this.onEdgeClick(d)
        }
      })

    edgeEnter.append('line')
      .attr('stroke', d => this.edgeColors[d.type] || '#9ca3af')
      .attr('stroke-width', 2)
      .attr('stroke-opacity', 0.6)
      .attr('marker-end', 'url(#arrowhead)')

    edgeEnter.append('title')
      .text(d => d.label)

    const edgeMerged = edgeEnter.merge(edgeSelection)

    // Render nodes
    const nodeSelection = this.nodesGroup
      .selectAll('g.node')
      .data(this.nodes, d => d.id)

    nodeSelection.exit().remove()

    const nodeEnter = nodeSelection.enter()
      .append('g')
      .attr('class', 'node')
      .style('cursor', 'pointer')
      .call(this.drag())
      .on('click', (event, d) => {
        event.stopPropagation()
        if (this.onNodeClick) {
          this.onNodeClick(d)
        }
      })

    // Add node circles
    nodeEnter.append('circle')
      .attr('r', 12)
      .attr('fill', d => this.nodeColors[d.type] || '#9ca3af')
      .attr('stroke', d => d.suspicious ? '#ef4444' : '#ffffff')
      .attr('stroke-width', d => d.suspicious ? 3 : 2)

    // Add node labels
    nodeEnter.append('text')
      .attr('dx', 15)
      .attr('dy', 5)
      .attr('font-size', '12px')
      .attr('font-family', 'sans-serif')
      .attr('fill', '#374151')
      .text(d => this.truncateLabel(d.label, 20))

    // Add node tooltips
    nodeEnter.append('title')
      .text(d => {
        let tooltip = `${d.type}: ${d.label}\n`
        if (d.suspicious) tooltip += 'SUSPICIOUS\n'
        if (d.mitre_techniques.length > 0) {
          tooltip += `MITRE: ${d.mitre_techniques.join(', ')}\n`
        }
        tooltip += `Time: ${new Date(d.timestamp).toLocaleString()}`
        return tooltip
      })

    const nodeMerged = nodeEnter.merge(nodeSelection)

    // Store selections for tick updates
    this.nodeElements = nodeMerged
    this.edgeElements = edgeMerged

    // Add arrow marker definition
    this.svg.select('defs').remove()
    const defs = this.svg.append('defs')
    defs.append('marker')
      .attr('id', 'arrowhead')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 20)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', '#9ca3af')
  }

  ticked() {
    if (!this.edgeElements || !this.nodeElements) return

    // Update edge positions
    this.edgeElements.select('line')
      .attr('x1', d => d.source.x)
      .attr('y1', d => d.source.y)
      .attr('x2', d => d.target.x)
      .attr('y2', d => d.target.y)

    // Update node positions
    this.nodeElements
      .attr('transform', d => `translate(${d.x},${d.y})`)
  }

  drag() {
    return d3.drag()
      .on('start', (event, d) => {
        if (!event.active) this.simulation.alphaTarget(0.3).restart()
        d.fx = d.x
        d.fy = d.y
      })
      .on('drag', (event, d) => {
        d.fx = event.x
        d.fy = event.y
      })
      .on('end', (event, d) => {
        if (!event.active) this.simulation.alphaTarget(0)
        d.fx = null
        d.fy = null
      })
  }

  resetView() {
    this.svg.transition()
      .duration(750)
      .call(this.zoomBehavior.transform, d3.zoomIdentity)
  }

  zoomIn() {
    this.svg.transition()
      .duration(300)
      .call(this.zoomBehavior.scaleBy, 1.3)
  }

  zoomOut() {
    this.svg.transition()
      .duration(300)
      .call(this.zoomBehavior.scaleBy, 0.7)
  }

  zoomToFit() {
    if (this.nodes.length === 0) return

    // Calculate bounds
    const padding = 50
    const xExtent = d3.extent(this.nodes, d => d.x)
    const yExtent = d3.extent(this.nodes, d => d.y)

    const width = xExtent[1] - xExtent[0] + padding * 2
    const height = yExtent[1] - yExtent[0] + padding * 2

    const scale = Math.min(this.width / width, this.height / height, 2)
    const translateX = this.width / 2 - (xExtent[0] + xExtent[1]) / 2 * scale
    const translateY = this.height / 2 - (yExtent[0] + yExtent[1]) / 2 * scale

    this.svg.transition()
      .duration(750)
      .call(
        this.zoomBehavior.transform,
        d3.zoomIdentity.translate(translateX, translateY).scale(scale)
      )
  }

  applyFilter(filter) {
    // Filter nodes by type
    this.nodeElements.style('opacity', d => {
      if (filter.type && d.type !== filter.type) return 0.1
      if (filter.severity && filter.severity.length > 0) {
        // Check if node has matching severity (for alerts)
        if (d.metadata && d.metadata.severity) {
          if (!filter.severity.includes(d.metadata.severity)) return 0.1
        }
      }
      if (filter.technique && filter.technique.length > 0) {
        // Check if node has matching MITRE technique
        const hasMatch = d.mitre_techniques.some(t => filter.technique.includes(t))
        if (!hasMatch) return 0.1
      }
      return 1.0
    })

    // Filter edges based on visible nodes
    this.edgeElements.style('opacity', d => {
      const sourceOpacity = this.nodeElements.filter(n => n.id === d.source.id).style('opacity')
      const targetOpacity = this.nodeElements.filter(n => n.id === d.target.id).style('opacity')
      return (parseFloat(sourceOpacity) + parseFloat(targetOpacity)) / 2
    })
  }

  clearFilter() {
    this.nodeElements.style('opacity', 1.0)
    this.edgeElements.style('opacity', 0.6)
  }

  exportAsSVG() {
    // Clone SVG for export
    const svgNode = this.svg.node()
    const svgString = new XMLSerializer().serializeToString(svgNode)
    const blob = new Blob([svgString], { type: 'image/svg+xml' })
    return URL.createObjectURL(blob)
  }

  exportAsPNG() {
    return new Promise((resolve) => {
      const svgNode = this.svg.node()
      const svgString = new XMLSerializer().serializeToString(svgNode)

      const canvas = document.createElement('canvas')
      canvas.width = this.width * 2
      canvas.height = this.height * 2

      const ctx = canvas.getContext('2d')
      ctx.scale(2, 2)

      const img = new Image()
      const blob = new Blob([svgString], { type: 'image/svg+xml' })
      const url = URL.createObjectURL(blob)

      img.onload = () => {
        ctx.fillStyle = '#ffffff'
        ctx.fillRect(0, 0, this.width, this.height)
        ctx.drawImage(img, 0, 0)
        URL.revokeObjectURL(url)

        canvas.toBlob((blob) => {
          resolve(URL.createObjectURL(blob))
        })
      }

      img.src = url
    })
  }

  truncateLabel(label, maxLength) {
    if (!label) return ''
    if (label.length <= maxLength) return label
    return label.substring(0, maxLength - 3) + '...'
  }

  destroy() {
    if (this.simulation) {
      this.simulation.stop()
    }
    if (this.svg) {
      this.svg.remove()
    }
  }
}

export default InvestigationGraphViz
