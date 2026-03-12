const ConfigEditor = {
  config: null,

  async render(container) {
    try {
      ConfigEditor.config = await App.api('GET', '/api/config');
    } catch (_) {
      ConfigEditor.config = {};
    }
    const c = ConfigEditor.config;
    const d = c.diurnal || {};
    const st = c.sourcetypes || {};

    container.innerHTML = `
      <div class="page active">
        <div class="page-header">
          <h1 class="page-title">Configuration</h1>
          <div class="btn-group">
            <button class="btn btn-primary" onclick="ConfigEditor.save()">Save Changes</button>
          </div>
        </div>

        <div class="grid-2">
          <div class="card">
            <div class="card-title">General</div>
            <div class="form-group">
              <label class="form-label">Events Per Second (EPS)</label>
              <input type="number" class="form-input" id="cfg-eps" value="${c.eps || 5}" min="0.1" max="1000" step="0.5">
            </div>
            <div class="form-group">
              <label class="form-label">Threat Ratio (0.0 - 1.0)</label>
              <input type="number" class="form-input" id="cfg-threat-ratio" value="${c.threat_ratio || 0.08}" min="0" max="1" step="0.01">
            </div>
            <div class="form-group">
              <label class="form-label">Output Directory</label>
              <input type="text" class="form-input" id="cfg-output-dir" value="${c.output_dir || './logs'}">
            </div>
          </div>

          <div class="card">
            <div class="card-title">Diurnal Curve</div>
            <div class="form-group">
              <label class="toggle-wrap">
                <span class="form-label" style="margin:0">Enabled</span>
                <label class="toggle">
                  <input type="checkbox" id="cfg-diurnal-enabled" ${d.enabled !== false ? 'checked' : ''}>
                  <span class="toggle-slider"></span>
                </label>
              </label>
            </div>
            <div class="form-group">
              <label class="form-label">Peak Hours</label>
              <div style="display:flex;gap:8px;align-items:center">
                <input type="number" class="form-input" id="cfg-peak-start" value="${(d.peak_hours || [8, 18])[0]}" min="0" max="23" style="width:80px">
                <span style="color:var(--text-secondary)">to</span>
                <input type="number" class="form-input" id="cfg-peak-end" value="${(d.peak_hours || [8, 18])[1]}" min="0" max="23" style="width:80px">
              </div>
            </div>
            <div class="form-group">
              <label class="form-label">Peak Multiplier: <span id="peak-val">${d.peak_multiplier || 1.5}</span></label>
              <input type="range" id="cfg-peak-mult" min="0.5" max="5" step="0.1" value="${d.peak_multiplier || 1.5}"
                oninput="document.getElementById('peak-val').textContent=this.value">
            </div>
            <div class="form-group">
              <label class="form-label">Trough Multiplier: <span id="trough-val">${d.trough_multiplier || 0.3}</span></label>
              <input type="range" id="cfg-trough-mult" min="0.05" max="1" step="0.05" value="${d.trough_multiplier || 0.3}"
                oninput="document.getElementById('trough-val').textContent=this.value">
            </div>
          </div>
        </div>

        <div class="card">
          <div class="card-title">Sourcetype Weights</div>
          <table class="data-table">
            <thead>
              <tr><th>Sourcetype</th><th>Weight</th><th>Output File</th></tr>
            </thead>
            <tbody>
              ${Object.entries(st).map(([name, cfg]) => `
                <tr>
                  <td>${name}</td>
                  <td><input type="number" class="st-weight" data-st="${name}" value="${cfg.weight}" min="0" max="100"></td>
                  <td><input type="text" class="st-file" data-st="${name}" value="${cfg.file}" readonly style="color:var(--text-secondary)"></td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>
      </div>
    `;
  },

  async save() {
    const patch = {
      eps: parseFloat(document.getElementById('cfg-eps').value),
      threat_ratio: parseFloat(document.getElementById('cfg-threat-ratio').value),
      output_dir: document.getElementById('cfg-output-dir').value,
      diurnal: {
        enabled: document.getElementById('cfg-diurnal-enabled').checked,
        peak_hours: [
          parseInt(document.getElementById('cfg-peak-start').value),
          parseInt(document.getElementById('cfg-peak-end').value),
        ],
        peak_multiplier: parseFloat(document.getElementById('cfg-peak-mult').value),
        trough_multiplier: parseFloat(document.getElementById('cfg-trough-mult').value),
      },
    };

    const sourcetypes = {};
    document.querySelectorAll('.st-weight').forEach(input => {
      const st = input.dataset.st;
      const fileInput = document.querySelector(`.st-file[data-st="${st}"]`);
      sourcetypes[st] = {
        weight: parseInt(input.value),
        file: fileInput ? fileInput.value : st + '.log',
      };
    });
    patch.sourcetypes = sourcetypes;

    await App.api('PUT', '/api/config', patch);
  },
};
