const Dashboard = {
  pollInterval: null,
  epsChart: null,
  stChart: null,

  render(container) {
    Dashboard.cleanup();
    container.innerHTML = `
      <div class="page active">
        <div class="page-header">
          <h1 class="page-title">Dashboard</h1>
          <div class="btn-group">
            <button class="btn btn-success" id="btn-start" onclick="Dashboard.start()">Start</button>
            <button class="btn btn-danger" id="btn-stop" onclick="Dashboard.stop()">Stop</button>
            <button class="btn" id="btn-pause" onclick="Dashboard.pause()">Pause</button>
          </div>
        </div>
        <div class="grid-4">
          <div class="card">
            <div class="card-title">Status</div>
            <div class="stat-value accent" id="dash-state">Idle</div>
            <div class="stat-label" id="dash-uptime">--</div>
          </div>
          <div class="card">
            <div class="card-title">Events / Second</div>
            <div class="stat-value success" id="dash-eps">0.00</div>
            <div class="stat-label">Current EPS</div>
          </div>
          <div class="card">
            <div class="card-title">Total Events</div>
            <div class="stat-value" id="dash-total">0</div>
            <div class="stat-label">Since start</div>
          </div>
          <div class="card">
            <div class="card-title">Threat Events</div>
            <div class="stat-value danger" id="dash-threats">0</div>
            <div class="stat-label">Detected IOCs</div>
          </div>
        </div>
        <div class="grid-2">
          <div class="card">
            <div class="card-title">Events by Sourcetype</div>
            <div class="chart-container"><canvas id="chart-sourcetype"></canvas></div>
          </div>
          <div class="card">
            <div class="card-title">EPS Over Time</div>
            <div class="chart-container"><canvas id="chart-eps"></canvas></div>
          </div>
        </div>
      </div>
    `;
    Dashboard.initCharts();
    Dashboard.startPolling();
  },

  cleanup() {
    if (Dashboard.pollInterval) clearInterval(Dashboard.pollInterval);
    if (Dashboard.epsChart) { Dashboard.epsChart.destroy(); Dashboard.epsChart = null; }
    if (Dashboard.stChart) { Dashboard.stChart.destroy(); Dashboard.stChart = null; }
  },

  initCharts() {
    const stCtx = document.getElementById('chart-sourcetype');
    if (stCtx) {
      Dashboard.stChart = new Chart(stCtx, {
        type: 'bar',
        data: {
          labels: ['WinEventLog', 'Sysmon', 'linux_secure', 'DNS', 'HTTP', 'Firewall'],
          datasets: [{
            label: 'Events',
            data: [0, 0, 0, 0, 0, 0],
            backgroundColor: ['#58a6ff', '#bc8cff', '#3fb950', '#d29922', '#f78166', '#f85149'],
            borderWidth: 0,
            borderRadius: 4,
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { ticks: { color: '#8b949e', font: { size: 11 } }, grid: { color: '#21262d' } },
            y: { ticks: { color: '#8b949e' }, grid: { color: '#21262d' } }
          }
        }
      });
    }

    const epsCtx = document.getElementById('chart-eps');
    if (epsCtx) {
      Dashboard.epsHistory = [];
      Dashboard.epsChart = new Chart(epsCtx, {
        type: 'line',
        data: {
          labels: [],
          datasets: [{
            label: 'EPS',
            data: [],
            borderColor: '#3fb950',
            backgroundColor: 'rgba(63, 185, 80, 0.1)',
            fill: true,
            tension: 0.3,
            pointRadius: 0,
            borderWidth: 2,
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { ticks: { color: '#8b949e', maxTicksLimit: 10, font: { size: 10 } }, grid: { color: '#21262d' } },
            y: { beginAtZero: true, ticks: { color: '#8b949e' }, grid: { color: '#21262d' } }
          }
        }
      });
    }
  },

  startPolling() {
    const poll = async () => {
      try {
        const data = await App.api('GET', '/api/stats');
        Dashboard.updateStats(data);
      } catch (_) {}
    };
    poll();
    Dashboard.pollInterval = setInterval(poll, 2000);
  },

  updateStats(data) {
    const el = (id) => document.getElementById(id);
    const stateEl = el('dash-state');
    if (stateEl) stateEl.textContent = data.state.charAt(0).toUpperCase() + data.state.slice(1);
    const uptimeEl = el('dash-uptime');
    if (uptimeEl) {
      const m = Math.floor(data.uptime_seconds / 60);
      const s = Math.floor(data.uptime_seconds % 60);
      uptimeEl.textContent = `Uptime: ${m}m ${s}s`;
    }
    const epsEl = el('dash-eps');
    if (epsEl) epsEl.textContent = data.current_eps.toFixed(2);
    const totalEl = el('dash-total');
    if (totalEl) totalEl.textContent = data.total_events.toLocaleString();
    const threatEl = el('dash-threats');
    if (threatEl) threatEl.textContent = data.threat_events.toLocaleString();

    if (Dashboard.stChart) {
      const keys = ['wineventlog', 'sysmon', 'linux_secure', 'dns', 'http', 'firewall'];
      Dashboard.stChart.data.datasets[0].data = keys.map(k => data.events_by_sourcetype[k] || 0);
      Dashboard.stChart.update('none');
    }

    if (Dashboard.epsChart) {
      const now = new Date().toLocaleTimeString();
      Dashboard.epsChart.data.labels.push(now);
      Dashboard.epsChart.data.datasets[0].data.push(data.current_eps);
      if (Dashboard.epsChart.data.labels.length > 60) {
        Dashboard.epsChart.data.labels.shift();
        Dashboard.epsChart.data.datasets[0].data.shift();
      }
      Dashboard.epsChart.update('none');
    }

    App.updateStatusIndicator(data.state);
  },

  async start() { await App.api('POST', '/api/generator/start'); },
  async stop() { await App.api('POST', '/api/generator/stop'); },
  async pause() { await App.api('POST', '/api/generator/pause'); },
};
