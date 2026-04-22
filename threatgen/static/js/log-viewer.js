const LogViewer = {
  sockets: {},
  activeTab: 'wineventlog',
  maxLines: 500,
  autoScroll: true,
  sourcetypes: ['wineventlog', 'sysmon', 'linux_secure', 'dns', 'http', 'cisco:asa'],
  labels: {
    wineventlog: 'WinEventLog',
    sysmon: 'Sysmon',
    linux_secure: 'linux_secure',
    dns: 'DNS (stream)',
    http: 'HTTP (stream)',
    'cisco:asa': 'Cisco ASA',
  },
  threatPatterns: [
    /WSPrint/i, /BugSplatRc64/i, /msiexec.*\/V/i,
    /T1574|T1055|T1547|T1053|T1014|T1543|T1071/,
    /154\.205\.154\.\d+|207\.148\.12[01]\.\d+/,
    /212\.11\.64\.105|185\.196\.10\.\d+/,
    /bloopencil\.net|xtibh\.com|xcit76\.com/,
    /brute-force-server/i,
    /busybox/i,
    /pg_hba\.conf reject/,
  ],

  render(container) {
    LogViewer.cleanup();
    const tabs = LogViewer.sourcetypes.map(st =>
      `<button class="tab ${st === LogViewer.activeTab ? 'active' : ''}" data-st="${st}">${LogViewer.labels[st]}</button>`
    ).join('');

    container.innerHTML = `
      <div class="page active">
        <div class="page-header">
          <h1 class="page-title">Log Viewer</h1>
          <div class="btn-group">
            <button class="btn" id="btn-clear-logs" onclick="LogViewer.clearLogs()">Clear</button>
            <label class="toggle-wrap">
              <span style="font-size:13px;color:var(--text-secondary)">Auto-scroll</span>
              <label class="toggle">
                <input type="checkbox" id="log-autoscroll" checked onchange="LogViewer.autoScroll=this.checked">
                <span class="toggle-slider"></span>
              </label>
            </label>
          </div>
        </div>
        <div class="tabs" id="log-tabs">${tabs}</div>
        <div class="log-container" id="log-output"></div>
      </div>
    `;

    document.querySelectorAll('#log-tabs .tab').forEach(tab => {
      tab.addEventListener('click', () => {
        LogViewer.switchTab(tab.dataset.st);
      });
    });

    LogViewer.connectAll();
  },

  cleanup() {
    Object.values(LogViewer.sockets).forEach(ws => {
      try { ws.close(); } catch (_) {}
    });
    LogViewer.sockets = {};
  },

  switchTab(st) {
    LogViewer.activeTab = st;
    document.querySelectorAll('#log-tabs .tab').forEach(t => {
      t.classList.toggle('active', t.dataset.st === st);
    });
    LogViewer.redraw();
  },

  connectAll() {
    LogViewer._lines = {};
    LogViewer.sourcetypes.forEach(st => {
      LogViewer._lines[st] = [];
      LogViewer.connectWS(st);
    });
  },

  connectWS(st) {
    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(`${proto}://${location.host}/ws/logs/${encodeURIComponent(st)}`);
    LogViewer.sockets[st] = ws;

    ws.onmessage = (evt) => {
      const msg = evt.data;
      const pipe = msg.indexOf('|');
      const line = pipe >= 0 ? msg.substring(pipe + 1) : msg;
      const isThreat = LogViewer.threatPatterns.some(p => p.test(line));
      LogViewer._lines[st].push({ text: line, threat: isThreat });
      if (LogViewer._lines[st].length > LogViewer.maxLines) {
        LogViewer._lines[st].shift();
      }
      if (st === LogViewer.activeTab) {
        LogViewer.appendLine(line, isThreat);
      }
    };

    ws.onclose = () => {
      setTimeout(() => {
        if (App.currentPage === 'logs') LogViewer.connectWS(st);
      }, 3000);
    };
  },

  appendLine(text, isThreat) {
    const output = document.getElementById('log-output');
    if (!output) return;
    const div = document.createElement('div');
    div.className = 'log-line' + (isThreat ? ' threat' : '');
    div.textContent = text;
    output.appendChild(div);

    while (output.children.length > LogViewer.maxLines) {
      output.removeChild(output.firstChild);
    }

    if (LogViewer.autoScroll) {
      output.scrollTop = output.scrollHeight;
    }
  },

  redraw() {
    const output = document.getElementById('log-output');
    if (!output) return;
    output.innerHTML = '';
    const lines = LogViewer._lines[LogViewer.activeTab] || [];
    lines.forEach(l => LogViewer.appendLine(l.text, l.threat));
  },

  clearLogs() {
    LogViewer.sourcetypes.forEach(st => { LogViewer._lines[st] = []; });
    const output = document.getElementById('log-output');
    if (output) output.innerHTML = '';
  },
};
