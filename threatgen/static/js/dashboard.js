const Dashboard = {
  pollInterval: null,
  llmInterval: null,
  epsChart: null,
  stChart: null,

  render(container) {
    Dashboard.cleanup();
    container.innerHTML = `
      <div class="page active">
        <div class="page-header">
          <h1 class="page-title">Dashboard</h1>
          <div class="btn-group">
            <span class="llm-pill" id="llm-pill" title="LLM variation engine status">
              <span class="llm-dot"></span>
              <span class="llm-label">LLM: checking</span>
            </span>
            <span class="llm-pill active-pill llm-fallback" id="active-pill" title="Generator engine status">
              <span class="llm-dot"></span>
              <span class="llm-label">Inactive</span>
            </span>
            <button class="btn btn-success" id="btn-start" onclick="Dashboard.start()">Start</button>
            <button class="btn btn-danger" id="btn-stop" onclick="Dashboard.stop()">Stop</button>
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
    Dashboard.startLLMPolling();
  },

  cleanup() {
    if (Dashboard.pollInterval) clearInterval(Dashboard.pollInterval);
    if (Dashboard.llmInterval) clearInterval(Dashboard.llmInterval);
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
    Dashboard.updateActivePill(data.state);
  },

  updateActivePill(state) {
    const pill = document.getElementById('active-pill');
    const startBtn = document.getElementById('btn-start');
    const stopBtn = document.getElementById('btn-stop');
    const isActive = state === 'running';
    if (pill) {
      const label = pill.querySelector('.llm-label');
      pill.classList.remove('llm-active', 'llm-fallback');
      if (isActive) {
        pill.classList.add('llm-active');
        if (label) label.textContent = 'Active';
      } else {
        pill.classList.add('llm-fallback');
        if (label) label.textContent = 'Inactive';
      }
    }
    if (startBtn) startBtn.disabled = isActive;
    if (stopBtn) stopBtn.disabled = !isActive;
  },

  async start() { await App.api('POST', '/api/generator/start'); },
  async stop() { await App.api('POST', '/api/generator/stop'); },

  startLLMPolling() {
    const poll = async () => {
      try {
        const data = await App.api('GET', '/api/llm/status');
        Dashboard.updateLLMPill(data);
      } catch (_) {
        Dashboard.updateLLMPill(null);
      }
    };
    poll();
    Dashboard.llmInterval = setInterval(poll, 5000);
  },

  updateLLMPill(status) {
    const pill = document.getElementById('llm-pill');
    if (!pill) return;
    const label = pill.querySelector('.llm-label');

    pill.classList.remove('llm-active', 'llm-degraded', 'llm-fallback');
    if (!status) {
      pill.classList.add('llm-fallback');
      label.textContent = 'LLM: unknown';
      pill.title = 'Could not query /api/llm/status';
      return;
    }
    const pools = status.pool_sizes || {};
    const totalPool = Object.values(pools).reduce((a, b) => a + (b || 0), 0);
    const totalCapacity = (status.capacity || 0) * Object.keys(pools).length;

    if (!status.key_present) {
      pill.classList.add('llm-fallback');
      label.textContent = 'LLM: fallback (no API key)';
      pill.title = 'Set ANTHROPIC_API_KEY and restart to enable LLM variations.';
    } else if (!status.enabled || !status.worker_running) {
      pill.classList.add('llm-fallback');
      label.textContent = 'LLM: disabled';
      pill.title = status.last_error || 'Worker not running; using pattern fallback.';
    } else if (status.degraded) {
      pill.classList.add('llm-degraded');
      label.textContent = `LLM: degraded (${totalPool}/${totalCapacity})`;
      pill.title = status.last_error || 'Last refresh failed; using existing cache + fallback.';
    } else {
      pill.classList.add('llm-active');
      label.textContent = `LLM: active (${totalPool}/${totalCapacity})`;
      pill.title = `Model: ${status.model || 'n/a'}\nCampaign model: ${status.campaign_model || 'n/a'}`;
    }
  },
};
