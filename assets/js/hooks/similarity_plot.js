/**
 * Similarity Plot Hook
 *
 * Interactive Plotly scatter plot for alert similarity visualization.
 *
 * Features:
 * - Color-coded by cluster
 * - Click to select alert
 * - Hover to show alert details
 * - Zoom/pan interactions
 */

import Plotly from 'plotly.js-dist';

export default {
  mounted() {
    this.renderPlot();
  },

  updated() {
    this.renderPlot();
  },

  renderPlot() {
    const visualization = JSON.parse(this.el.dataset.visualization);
    const alerts = JSON.parse(this.el.dataset.alerts);
    const clusterLabels = JSON.parse(this.el.dataset.clusterLabels);

    if (!visualization || !visualization.coordinates) {
      console.error('No visualization data available');
      return;
    }

    const coordinates = visualization.coordinates;
    const alertIds = visualization.alert_ids;

    // Group alerts by cluster
    const clusterGroups = {};
    const noisePoints = {
      x: [],
      y: [],
      alert_ids: [],
      alerts: [],
      indices: []
    };

    coordinates.forEach((coord, i) => {
      const clusterId = clusterLabels[i];
      const alertId = alertIds[i];
      const alert = alerts.find(a => a.id === alertId);

      if (clusterId === -1) {
        // Noise/outlier
        noisePoints.x.push(coord[0]);
        noisePoints.y.push(coord[1]);
        noisePoints.alert_ids.push(alertId);
        noisePoints.alerts.push(alert);
        noisePoints.indices.push(i);
      } else {
        if (!clusterGroups[clusterId]) {
          clusterGroups[clusterId] = {
            x: [],
            y: [],
            alert_ids: [],
            alerts: [],
            indices: []
          };
        }
        clusterGroups[clusterId].x.push(coord[0]);
        clusterGroups[clusterId].y.push(coord[1]);
        clusterGroups[clusterId].alert_ids.push(alertId);
        clusterGroups[clusterId].alerts.push(alert);
        clusterGroups[clusterId].indices.push(i);
      }
    });

    // Color palette for clusters
    const colors = [
      '#3B82F6', // blue
      '#10B981', // green
      '#F59E0B', // amber
      '#EF4444', // red
      '#8B5CF6', // purple
      '#EC4899', // pink
      '#14B8A6', // teal
      '#F97316', // orange
      '#6366F1', // indigo
      '#06B6D4', // cyan
    ];

    // Create traces for each cluster
    const traces = [];

    Object.keys(clusterGroups).sort((a, b) => parseInt(a) - parseInt(b)).forEach((clusterId, idx) => {
      const group = clusterGroups[clusterId];
      const color = colors[idx % colors.length];

      const hoverText = group.alerts.map((alert, i) => {
        if (!alert) return 'Unknown alert';

        return `<b>${alert.title}</b><br>` +
               `Severity: ${alert.severity}<br>` +
               `Cluster: ${clusterId}<br>` +
               `Time: ${new Date(alert.inserted_at).toLocaleString()}<br>` +
               `Techniques: ${(alert.mitre_techniques || []).slice(0, 3).join(', ')}`;
      });

      traces.push({
        x: group.x,
        y: group.y,
        mode: 'markers',
        type: 'scatter',
        name: `Cluster ${clusterId} (${group.x.length})`,
        marker: {
          color: color,
          size: 10,
          opacity: 0.7,
          line: {
            color: color,
            width: 2
          }
        },
        text: hoverText,
        hoverinfo: 'text',
        customdata: group.alert_ids
      });
    });

    // Add noise/outliers trace
    if (noisePoints.x.length > 0) {
      const hoverText = noisePoints.alerts.map((alert) => {
        if (!alert) return 'Unknown alert';

        return `<b>${alert.title}</b><br>` +
               `Severity: ${alert.severity}<br>` +
               `Outlier (no cluster)<br>` +
               `Time: ${new Date(alert.inserted_at).toLocaleString()}<br>` +
               `Techniques: ${(alert.mitre_techniques || []).slice(0, 3).join(', ')}`;
      });

      traces.push({
        x: noisePoints.x,
        y: noisePoints.y,
        mode: 'markers',
        type: 'scatter',
        name: `Outliers (${noisePoints.x.length})`,
        marker: {
          color: '#9CA3AF',
          size: 8,
          opacity: 0.5,
          symbol: 'x'
        },
        text: hoverText,
        hoverinfo: 'text',
        customdata: noisePoints.alert_ids
      });
    }

    // Layout configuration
    const layout = {
      title: '',
      xaxis: {
        title: 'Dimension 1',
        showgrid: true,
        zeroline: false
      },
      yaxis: {
        title: 'Dimension 2',
        showgrid: true,
        zeroline: false
      },
      hovermode: 'closest',
      showlegend: true,
      legend: {
        orientation: 'v',
        x: 1.02,
        y: 1,
        xanchor: 'left'
      },
      margin: {
        l: 60,
        r: 180,
        t: 20,
        b: 60
      },
      height: 600,
      plot_bgcolor: '#F9FAFB',
      paper_bgcolor: '#FFFFFF'
    };

    // Configuration
    const config = {
      displayModeBar: true,
      displaylogo: false,
      modeBarButtonsToRemove: ['lasso2d', 'select2d'],
      responsive: true
    };

    // Render plot
    Plotly.newPlot(this.el, traces, layout, config);

    // Click handler
    this.el.on('plotly_click', (data) => {
      const point = data.points[0];
      const alertId = point.customdata;

      // Send event to LiveView
      this.pushEvent('select_alert', { alert_id: alertId });
    });
  },

  destroyed() {
    if (this.el && this.el.data) {
      Plotly.purge(this.el);
    }
  }
};
