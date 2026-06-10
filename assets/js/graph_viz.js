/**
 * D3.js Force-Directed Graph Visualization for Attack Correlation
 *
 * Handles rendering and interaction for cross-agent attack correlation graphs.
 */

import * as d3 from 'd3';

export class CorrelationGraphViz {
  constructor(container) {
    this.container = container;
    this.svg = null;
    this.simulation = null;
    this.nodes = [];
    this.links = [];
    this.width = 0;
    this.height = 0;

    // Configuration
    this.config = {
      nodeRadius: {
        agent: 12,
        alert: 10,
        ioc: 8,
        user: 10,
        process: 9
      },
      colors: {
        agent: '#3b82f6',      // blue
        alert: {
          critical: '#dc2626', // red
          high: '#ea580c',     // orange
          medium: '#f59e0b',   // amber
          low: '#eab308',      // yellow
          info: '#6b7280'      // gray
        },
        ioc: '#8b5cf6',        // purple
        user: '#06b6d4',       // cyan
        process: '#10b981'     // green
      },
      linkColors: {
        lateral_movement: '#dc2626',
        shared_credentials: '#f59e0b',
        similar_techniques: '#8b5cf6',
        parent_child: '#10b981',
        network: '#3b82f6',
        technique: '#8b5cf6',
        ioc: '#f59e0b',
        temporal: '#6b7280'
      },
      forces: {
        charge: -300,
        linkDistance: 80,
        collideRadius: 30
      }
    };

    this.selectedNode = null;
    this.onNodeClick = null;
    this.onLinkClick = null;
    this.transform = d3.zoomIdentity;
  }

  initialize() {
    // Clear container
    this.container.innerHTML = '';

    // Get dimensions
    const rect = this.container.getBoundingClientRect();
    this.width = rect.width || 800;
    this.height = rect.height || 600;

    // Create SVG
    this.svg = d3.select(this.container)
      .append('svg')
      .attr('width', this.width)
      .attr('height', this.height)
      .attr('viewBox', [0, 0, this.width, this.height]);

    // Add defs for markers (arrows)
    const defs = this.svg.append('defs');

    // Create arrow markers for different link types
    Object.entries(this.config.linkColors).forEach(([type, color]) => {
      defs.append('marker')
        .attr('id', `arrow-${type}`)
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', 20)
        .attr('refY', 0)
        .attr('markerWidth', 6)
        .attr('markerHeight', 6)
        .attr('orient', 'auto')
        .append('path')
        .attr('d', 'M0,-5L10,0L0,5')
        .attr('fill', color);
    });

    // Create container groups
    this.g = this.svg.append('g');
    this.linkGroup = this.g.append('g').attr('class', 'links');
    this.nodeGroup = this.g.append('g').attr('class', 'nodes');

    // Setup zoom behavior
    const zoom = d3.zoom()
      .scaleExtent([0.1, 4])
      .on('zoom', (event) => {
        this.transform = event.transform;
        this.g.attr('transform', event.transform);
      });

    this.svg.call(zoom);

    // Initialize force simulation
    this.simulation = d3.forceSimulation()
      .force('link', d3.forceLink().id(d => d.id).distance(this.config.forces.linkDistance))
      .force('charge', d3.forceManyBody().strength(this.config.forces.charge))
      .force('center', d3.forceCenter(this.width / 2, this.height / 2))
      .force('collide', d3.forceCollide().radius(this.config.forces.collideRadius))
      .on('tick', () => this.tick());

    return this;
  }

  setData(graphData) {
    // Store data
    this.nodes = graphData.nodes || [];
    this.links = graphData.links || [];

    // Calculate node importance scores (used for sizing)
    this.calculateImportanceScores();

    // Update simulation
    this.simulation.nodes(this.nodes);
    this.simulation.force('link').links(this.links);

    // Render
    this.render();

    // Restart simulation
    this.simulation.alpha(1).restart();

    return this;
  }

  calculateImportanceScores() {
    // Calculate degree centrality for nodes
    const degree = new Map();

    this.nodes.forEach(node => {
      degree.set(node.id, 0);
    });

    this.links.forEach(link => {
      const sourceId = typeof link.source === 'object' ? link.source.id : link.source;
      const targetId = typeof link.target === 'object' ? link.target.id : link.target;

      degree.set(sourceId, (degree.get(sourceId) || 0) + 1);
      degree.set(targetId, (degree.get(targetId) || 0) + 1);
    });

    // Assign importance scores
    this.nodes.forEach(node => {
      const nodeDegree = degree.get(node.id) || 0;
      node.importance = nodeDegree;

      // Add severity weight for alerts
      if (node.type === 'alert') {
        const severityWeight = {
          critical: 10,
          high: 7,
          medium: 4,
          low: 2,
          info: 1
        };
        node.importance += severityWeight[node.severity] || 0;
      }
    });
  }

  render() {
    // Render links
    const linkElements = this.linkGroup
      .selectAll('line')
      .data(this.links, d => `${d.source.id || d.source}-${d.target.id || d.target}`);

    linkElements.exit().remove();

    const linkEnter = linkElements.enter()
      .append('line')
      .attr('class', 'link')
      .attr('stroke', d => this.config.linkColors[d.type] || '#999')
      .attr('stroke-width', d => d.weight || 1.5)
      .attr('stroke-opacity', 0.6)
      .attr('marker-end', d => `url(#arrow-${d.type})`)
      .on('click', (event, d) => {
        event.stopPropagation();
        if (this.onLinkClick) {
          this.onLinkClick(d);
        }
      })
      .on('mouseover', function(event, d) {
        d3.select(this)
          .attr('stroke-width', 3)
          .attr('stroke-opacity', 1);

        // Show tooltip
        showTooltip(event, d, 'link');
      })
      .on('mouseout', function(event, d) {
        d3.select(this)
          .attr('stroke-width', d.weight || 1.5)
          .attr('stroke-opacity', 0.6);

        hideTooltip();
      });

    this.linkElements = linkEnter.merge(linkElements);

    // Render nodes
    const nodeElements = this.nodeGroup
      .selectAll('g.node')
      .data(this.nodes, d => d.id);

    nodeElements.exit().remove();

    const nodeEnter = nodeElements.enter()
      .append('g')
      .attr('class', 'node')
      .call(this.drag());

    // Add circles
    nodeEnter.append('circle')
      .attr('r', d => this.getNodeRadius(d))
      .attr('fill', d => this.getNodeColor(d))
      .attr('stroke', '#fff')
      .attr('stroke-width', 2);

    // Add labels
    nodeEnter.append('text')
      .attr('dx', d => this.getNodeRadius(d) + 5)
      .attr('dy', 4)
      .attr('font-size', '10px')
      .attr('fill', '#333')
      .text(d => this.getNodeLabel(d));

    // Add event handlers
    nodeEnter
      .on('click', (event, d) => {
        event.stopPropagation();
        this.selectNode(d);
        if (this.onNodeClick) {
          this.onNodeClick(d);
        }
      })
      .on('mouseover', function(event, d) {
        d3.select(this).select('circle')
          .attr('stroke', '#000')
          .attr('stroke-width', 3);

        showTooltip(event, d, 'node');
      })
      .on('mouseout', function(event, d) {
        if (!d.selected) {
          d3.select(this).select('circle')
            .attr('stroke', '#fff')
            .attr('stroke-width', 2);
        }

        hideTooltip();
      });

    this.nodeElements = nodeEnter.merge(nodeElements);
  }

  tick() {
    if (this.linkElements) {
      this.linkElements
        .attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x)
        .attr('y2', d => d.target.y);
    }

    if (this.nodeElements) {
      this.nodeElements
        .attr('transform', d => `translate(${d.x},${d.y})`);
    }
  }

  drag() {
    return d3.drag()
      .on('start', (event, d) => {
        if (!event.active) this.simulation.alphaTarget(0.3).restart();
        d.fx = d.x;
        d.fy = d.y;
      })
      .on('drag', (event, d) => {
        d.fx = event.x;
        d.fy = event.y;
      })
      .on('end', (event, d) => {
        if (!event.active) this.simulation.alphaTarget(0);
        d.fx = null;
        d.fy = null;
      });
  }

  getNodeRadius(node) {
    const baseRadius = this.config.nodeRadius[node.type] || 10;
    // Scale by importance
    const importanceScale = 1 + (node.importance || 0) / 20;
    return baseRadius * Math.min(importanceScale, 2);
  }

  getNodeColor(node) {
    if (node.type === 'alert') {
      return this.config.colors.alert[node.severity] || this.config.colors.alert.info;
    }
    return this.config.colors[node.type] || '#999';
  }

  getNodeLabel(node) {
    if (node.type === 'agent') {
      return node.hostname || node.id.substring(0, 8);
    } else if (node.type === 'alert') {
      return node.title?.substring(0, 20) || `Alert ${node.id.substring(0, 8)}`;
    } else if (node.type === 'ioc') {
      return node.value?.substring(0, 15) || 'IOC';
    } else if (node.type === 'user') {
      return node.username || 'User';
    } else if (node.type === 'process') {
      return node.name || 'Process';
    }
    return node.id.substring(0, 8);
  }

  selectNode(node) {
    // Deselect previous
    if (this.selectedNode) {
      this.selectedNode.selected = false;
    }

    // Select new
    this.selectedNode = node;
    node.selected = true;

    // Update visuals
    this.nodeElements.select('circle')
      .attr('stroke', d => d.selected ? '#000' : '#fff')
      .attr('stroke-width', d => d.selected ? 3 : 2);

    // Highlight connected links
    this.linkElements
      .attr('stroke-opacity', d => {
        const sourceId = d.source.id || d.source;
        const targetId = d.target.id || d.target;
        return (sourceId === node.id || targetId === node.id) ? 1 : 0.2;
      });
  }

  resetView() {
    this.svg.transition()
      .duration(750)
      .call(
        d3.zoom().transform,
        d3.zoomIdentity
      );
  }

  zoomToFit() {
    if (!this.nodes.length) return;

    const bounds = {
      minX: d3.min(this.nodes, d => d.x),
      maxX: d3.max(this.nodes, d => d.x),
      minY: d3.min(this.nodes, d => d.y),
      maxY: d3.max(this.nodes, d => d.y)
    };

    const graphWidth = bounds.maxX - bounds.minX;
    const graphHeight = bounds.maxY - bounds.minY;

    const scale = 0.8 / Math.max(graphWidth / this.width, graphHeight / this.height);
    const translateX = (this.width - scale * (bounds.minX + graphWidth / 2)) - this.width / 2;
    const translateY = (this.height - scale * (bounds.minY + graphHeight / 2)) - this.height / 2;

    this.svg.transition()
      .duration(750)
      .call(
        d3.zoom().transform,
        d3.zoomIdentity.translate(translateX, translateY).scale(scale)
      );
  }

  exportAsSVG() {
    const svgData = this.svg.node().outerHTML;
    const blob = new Blob([svgData], { type: 'image/svg+xml' });
    return URL.createObjectURL(blob);
  }

  exportAsPNG() {
    return new Promise((resolve) => {
      const svgData = this.svg.node().outerHTML;
      const canvas = document.createElement('canvas');
      canvas.width = this.width;
      canvas.height = this.height;
      const ctx = canvas.getContext('2d');

      const img = new Image();
      const svgBlob = new Blob([svgData], { type: 'image/svg+xml;charset=utf-8' });
      const url = URL.createObjectURL(svgBlob);

      img.onload = function() {
        ctx.fillStyle = '#ffffff';
        ctx.fillRect(0, 0, canvas.width, canvas.height);
        ctx.drawImage(img, 0, 0);
        URL.revokeObjectURL(url);

        canvas.toBlob(blob => {
          resolve(URL.createObjectURL(blob));
        });
      };

      img.src = url;
    });
  }

  applyFilter(filter) {
    // Filter nodes and links based on criteria
    const { dateRange, severity, technique, campaign, type } = filter;

    this.nodeElements.style('opacity', d => {
      let visible = true;

      if (type && d.type !== type) {
        visible = false;
      }

      if (severity && d.type === 'alert' && !severity.includes(d.severity)) {
        visible = false;
      }

      if (technique && d.type === 'alert' && d.techniques &&
          !d.techniques.some(t => technique.includes(t))) {
        visible = false;
      }

      if (campaign && d.campaign_id !== campaign) {
        visible = false;
      }

      if (dateRange && d.timestamp) {
        const ts = new Date(d.timestamp);
        if (ts < dateRange.start || ts > dateRange.end) {
          visible = false;
        }
      }

      return visible ? 1 : 0.1;
    });

    this.linkElements.style('opacity', d => {
      const sourceVisible = this.nodeElements.filter(n => n.id === d.source.id)
        .style('opacity') === '1';
      const targetVisible = this.nodeElements.filter(n => n.id === d.target.id)
        .style('opacity') === '1';

      return (sourceVisible && targetVisible) ? 0.6 : 0.1;
    });
  }

  clearFilter() {
    this.nodeElements.style('opacity', 1);
    this.linkElements.style('opacity', 0.6);
  }

  destroy() {
    if (this.simulation) {
      this.simulation.stop();
    }
    if (this.svg) {
      this.svg.remove();
    }
  }
}

// Tooltip functions
let tooltip = null;

function showTooltip(event, data, type) {
  if (!tooltip) {
    tooltip = d3.select('body')
      .append('div')
      .attr('class', 'graph-tooltip')
      .style('position', 'absolute')
      .style('background', 'rgba(0, 0, 0, 0.8)')
      .style('color', '#fff')
      .style('padding', '8px 12px')
      .style('border-radius', '4px')
      .style('font-size', '12px')
      .style('pointer-events', 'none')
      .style('z-index', '1000')
      .style('opacity', 0);
  }

  let content = '';

  if (type === 'node') {
    content = `<strong>${data.type.toUpperCase()}</strong><br/>`;
    if (data.hostname) content += `Host: ${data.hostname}<br/>`;
    if (data.ip) content += `IP: ${data.ip}<br/>`;
    if (data.title) content += `Title: ${data.title}<br/>`;
    if (data.severity) content += `Severity: ${data.severity}<br/>`;
    if (data.username) content += `User: ${data.username}<br/>`;
    if (data.name) content += `Name: ${data.name}<br/>`;
    content += `Connections: ${data.importance || 0}`;
  } else if (type === 'link') {
    content = `<strong>${data.type.replace('_', ' ').toUpperCase()}</strong><br/>`;
    if (data.alert_id) content += `Alert: ${data.alert_id.substring(0, 8)}<br/>`;
    if (data.technique) content += `Technique: ${data.technique}<br/>`;
  }

  tooltip.html(content)
    .style('left', (event.pageX + 10) + 'px')
    .style('top', (event.pageY - 10) + 'px')
    .transition()
    .duration(200)
    .style('opacity', 1);
}

function hideTooltip() {
  if (tooltip) {
    tooltip.transition()
      .duration(200)
      .style('opacity', 0);
  }
}

export default CorrelationGraphViz;
