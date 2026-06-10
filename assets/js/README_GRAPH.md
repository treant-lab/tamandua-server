# Graph Visualization JavaScript Module

## Overview

`graph_viz.js` provides a D3.js-based force-directed graph visualization for attack correlation analysis. It integrates seamlessly with Phoenix LiveView through hooks.

## Installation

### Dependencies

The following D3 packages are required (already in package.json):

```json
{
  "d3": "^7.9.0",
  "d3-force": "^3.0.0",
  "d3-selection": "^3.0.0",
  "d3-zoom": "^3.0.0"
}
```

Install with:

```bash
cd apps/tamandua_server/assets
npm install
```

### Import

In `app.js`:

```javascript
import { CorrelationGraphViz } from './graph_viz.js'
```

## Usage

### Standalone (without LiveView)

```javascript
// Create container
const container = document.getElementById('graph-container');

// Initialize graph
const graph = new CorrelationGraphViz(container);
graph.initialize();

// Set data
graph.setData({
  nodes: [
    { id: 'n1', type: 'agent', hostname: 'web-server', ip: '10.0.1.5' },
    { id: 'n2', type: 'alert', title: 'Suspicious Process', severity: 'high' }
  ],
  links: [
    { source: 'n1', target: 'n2', type: 'network' }
  ]
});

// Setup event handlers
graph.onNodeClick = (node) => {
  console.log('Node clicked:', node);
};

graph.onLinkClick = (link) => {
  console.log('Link clicked:', link);
};
```

### With LiveView Hook

Already integrated in `app.js`:

```javascript
Hooks.CorrelationGraph = {
  mounted() {
    this.graph = new CorrelationGraphViz(this.el);
    this.graph.initialize();

    const graphData = JSON.parse(this.el.dataset.graph || '{"nodes":[],"links":[]}');
    this.graph.setData(graphData);

    this.graph.onNodeClick = (node) => {
      this.pushEvent("node_clicked", { node: node });
    };

    // ... more handlers
  }
}
```

## API Reference

### Constructor

```javascript
new CorrelationGraphViz(container)
```

**Parameters:**
- `container` (HTMLElement): DOM element to render graph into

**Returns:** `CorrelationGraphViz` instance

### Methods

#### `initialize()`

Sets up SVG, simulation, and zoom behavior. Must be called before `setData()`.

**Returns:** `this` (chainable)

```javascript
graph.initialize();
```

#### `setData(graphData)`

Loads graph data and starts simulation.

**Parameters:**
- `graphData` (Object):
  - `nodes` (Array): Node objects
  - `links` (Array): Link objects

**Returns:** `this` (chainable)

```javascript
graph.setData({
  nodes: [...],
  links: [...]
});
```

#### `resetView()`

Resets zoom and pan to default state.

```javascript
graph.resetView();
```

#### `zoomToFit()`

Auto-scales graph to fit viewport with 80% margin.

```javascript
graph.zoomToFit();
```

#### `selectNode(node)`

Programmatically selects a node and highlights connected links.

**Parameters:**
- `node` (Object): Node to select

```javascript
const node = graph.nodes.find(n => n.id === 'alert_123');
graph.selectNode(node);
```

#### `applyFilter(filter)`

Filters nodes and links based on criteria.

**Parameters:**
- `filter` (Object):
  - `type` (String): Node type filter
  - `severity` (Array): Severity levels
  - `technique` (Array): MITRE techniques
  - `campaign` (String): Campaign ID
  - `dateRange` (Object): `{start, end}` dates

```javascript
graph.applyFilter({
  severity: ['critical', 'high'],
  type: 'alert',
  dateRange: {
    start: new Date('2026-01-01'),
    end: new Date('2026-02-20')
  }
});
```

#### `clearFilter()`

Removes all filters and shows all nodes/links.

```javascript
graph.clearFilter();
```

#### `exportAsSVG()`

Exports current graph as SVG.

**Returns:** `String` - Blob URL for SVG file

```javascript
const url = graph.exportAsSVG();
const a = document.createElement('a');
a.href = url;
a.download = 'graph.svg';
a.click();
```

#### `exportAsPNG()`

Exports current graph as PNG image.

**Returns:** `Promise<String>` - Blob URL for PNG file

```javascript
const url = await graph.exportAsPNG();
const a = document.createElement('a');
a.href = url;
a.download = 'graph.png';
a.click();
```

#### `destroy()`

Stops simulation and removes SVG. Call before removing container.

```javascript
graph.destroy();
```

### Properties

#### `nodes` (Array)

Current node data (read-only)

#### `links` (Array)

Current link data (read-only)

#### `simulation` (d3.Simulation)

D3 force simulation instance (read-only)

#### `svg` (d3.Selection)

D3 selection of root SVG element (read-only)

### Event Handlers

#### `onNodeClick`

Called when user clicks a node.

**Signature:** `(node: Object) => void`

```javascript
graph.onNodeClick = (node) => {
  console.log('Clicked:', node.type, node.id);
  // Show details panel, navigate, etc.
};
```

#### `onLinkClick`

Called when user clicks a link.

**Signature:** `(link: Object) => void`

```javascript
graph.onLinkClick = (link) => {
  console.log('Link:', link.source.id, '->', link.target.id);
};
```

## Data Schemas

### Node Object

```javascript
{
  // Required
  id: String,              // Unique identifier
  type: String,            // "agent"|"alert"|"ioc"|"user"|"process"|"cluster"

  // Optional (type-specific)
  hostname: String,        // Agent hostname
  ip: String,              // Agent IP address
  os: String,              // Agent OS type
  title: String,           // Alert title
  severity: String,        // Alert severity ("critical"|"high"|"medium"|"low"|"info")
  techniques: [String],    // MITRE technique IDs
  tactics: [String],       // MITRE tactic names
  username: String,        // User account name
  value: String,           // IOC value (hash, IP, domain)
  ioc_type: String,        // IOC type ("file_hash"|"ip"|"domain")
  name: String,            // Process name
  pid: Number,             // Process ID
  path: String,            // Process path

  // Computed (added by graph)
  importance: Number,      // Degree centrality + severity weight
  x: Number,               // Current X position (set by simulation)
  y: Number,               // Current Y position (set by simulation)
  fx: Number,              // Fixed X (if pinned)
  fy: Number,              // Fixed Y (if pinned)
  selected: Boolean        // Selection state
}
```

### Link Object

```javascript
{
  // Required
  source: String|Object,   // Source node ID or node object
  target: String|Object,   // Target node ID or node object
  type: String,            // Link type (see below)

  // Optional
  weight: Number,          // Line thickness (default: 1.5)
  metadata: Object,        // Additional data

  // Computed (added by D3)
  index: Number            // Link index in array
}
```

### Link Types

- `lateral_movement` - Cross-agent attack propagation (red)
- `shared_credentials` - Same user/credentials (amber)
- `similar_techniques` - MITRE technique correlation (purple)
- `parent_child` - Process ancestry (green)
- `network` - Agent-alert connection (blue)
- `ioc` - Alert-IOC relationship (amber)
- `technique` - Technique-based correlation (purple)
- `temporal` - Time-based correlation (gray)

## Configuration

Edit the `config` object in `CorrelationGraphViz` constructor:

```javascript
this.config = {
  // Node radius by type
  nodeRadius: {
    agent: 12,
    alert: 10,
    ioc: 8,
    user: 10,
    process: 9
  },

  // Color scheme
  colors: {
    agent: '#3b82f6',
    alert: {
      critical: '#dc2626',
      high: '#ea580c',
      medium: '#f59e0b',
      low: '#eab308',
      info: '#6b7280'
    },
    ioc: '#8b5cf6',
    user: '#06b6d4',
    process: '#10b981'
  },

  // Link colors by type
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

  // Force simulation parameters
  forces: {
    charge: -300,          // Node repulsion (-ve = repel)
    linkDistance: 80,      // Ideal edge length
    collideRadius: 30      // Collision detection radius
  }
};
```

## Customization

### Custom Node Rendering

Override `getNodeLabel()` to customize node labels:

```javascript
getNodeLabel(node) {
  if (node.type === 'custom') {
    return `Custom: ${node.custom_field}`;
  }
  return super.getNodeLabel(node);
}
```

### Custom Colors

Override `getNodeColor()`:

```javascript
getNodeColor(node) {
  if (node.custom_severity) {
    return '#ff00ff';
  }
  return super.getNodeColor(node);
}
```

### Custom Tooltips

Modify `showTooltip()` in `graph_viz.js`:

```javascript
function showTooltip(event, data, type) {
  let content = `<strong>${data.type}</strong><br/>`;

  // Add custom fields
  if (data.custom_field) {
    content += `Custom: ${data.custom_field}<br/>`;
  }

  // ... rest of tooltip logic
}
```

## Performance Tips

### Large Graphs

For 1000+ nodes:

1. **Reduce simulation iterations:**
   ```javascript
   graph.simulation.alphaDecay(0.05); // Faster convergence
   ```

2. **Simplify rendering:**
   - Hide labels for small nodes
   - Use clustering in backend

3. **Limit visible nodes:**
   ```javascript
   graph.applyFilter({ ... });
   ```

### Smooth Animations

For 60 FPS:

1. Keep node count < 500
2. Avoid DOM updates in `tick()`
3. Use `transform` instead of `x`/`y` attributes

### Memory Usage

Clean up when unmounting:

```javascript
graph.destroy();
```

## Browser Support

- **Chrome/Edge**: ✅ Full support
- **Firefox**: ✅ Full support
- **Safari**: ✅ Full support (15+)
- **IE11**: ❌ Not supported (D3 v7 requires ES6)

## Debugging

### Enable Console Logging

```javascript
graph.debug = true;
```

### Inspect Simulation

```javascript
// Pause simulation
graph.simulation.stop();

// Check node positions
console.log(graph.nodes.map(n => ({ id: n.id, x: n.x, y: n.y })));

// Resume
graph.simulation.restart();
```

### Performance Profiling

```javascript
console.time('render');
graph.render();
console.timeEnd('render');
```

## Examples

### Example 1: Basic Usage

```javascript
const container = document.getElementById('graph');
const graph = new CorrelationGraphViz(container)
  .initialize()
  .setData({
    nodes: [
      { id: 'a1', type: 'agent', hostname: 'server1' },
      { id: 'alert1', type: 'alert', title: 'Malware', severity: 'high' }
    ],
    links: [
      { source: 'a1', target: 'alert1', type: 'network' }
    ]
  });
```

### Example 2: With Filters

```javascript
// Show only critical alerts from last 24 hours
const yesterday = new Date(Date.now() - 86400000);
graph.applyFilter({
  severity: ['critical'],
  dateRange: {
    start: yesterday,
    end: new Date()
  }
});
```

### Example 3: Export Workflow

```javascript
// Export both formats
async function exportGraph() {
  // SVG
  const svgUrl = graph.exportAsSVG();
  downloadFile(svgUrl, 'graph.svg');

  // PNG
  const pngUrl = await graph.exportAsPNG();
  downloadFile(pngUrl, 'graph.png');
}

function downloadFile(url, filename) {
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
```

## Testing

### Unit Tests (Future)

```javascript
import { CorrelationGraphViz } from './graph_viz.js';

describe('CorrelationGraphViz', () => {
  let container, graph;

  beforeEach(() => {
    container = document.createElement('div');
    graph = new CorrelationGraphViz(container);
  });

  afterEach(() => {
    graph.destroy();
  });

  test('initializes SVG', () => {
    graph.initialize();
    expect(container.querySelector('svg')).toBeTruthy();
  });

  test('loads data', () => {
    graph.initialize().setData({
      nodes: [{ id: 'n1', type: 'agent' }],
      links: []
    });
    expect(graph.nodes).toHaveLength(1);
  });
});
```

## Troubleshooting

### Issue: Graph not rendering

**Solution:** Ensure container has dimensions:

```css
#graph-container {
  width: 100%;
  height: 600px;
}
```

### Issue: Nodes overlap

**Solution:** Increase collision radius:

```javascript
graph.config.forces.collideRadius = 50;
graph.simulation.force('collide', d3.forceCollide().radius(50));
```

### Issue: Simulation runs forever

**Solution:** Set alpha decay:

```javascript
graph.simulation.alphaDecay(0.05); // Stops faster
```

## License

Part of Tamandua EDR - see main LICENSE file.
