const Campaigns = {
  data: [],

  async render(container) {
    try {
      Campaigns.data = await App.api('GET', '/api/campaigns');
    } catch (_) {
      Campaigns.data = [];
    }

    const cards = Campaigns.data.map(c => Campaigns.renderCard(c)).join('');

    container.innerHTML = `
      <div class="page active">
        <div class="page-header">
          <h1 class="page-title">Threat Campaigns</h1>
        </div>
        <div class="grid-3" id="campaign-grid">${cards}</div>
      </div>
    `;
  },

  renderCard(c) {
    const techniques = c.mitre_techniques.map(t => `<span class="mitre-tag">${t}</span>`).join('');
    const iocHtml = Object.entries(c.iocs).map(([key, vals]) => {
      if (!vals || !vals.length) return '';
      return `
        <div class="ioc-section">
          <div class="ioc-label">${key.replace(/_/g, ' ')}</div>
          <div class="ioc-value">${vals.join('<br>')}</div>
        </div>
      `;
    }).join('');

    return `
      <div class="campaign-card" id="campaign-${c.id}">
        <div class="campaign-header">
          <span class="campaign-name">${c.name}</span>
          <label class="toggle">
            <input type="checkbox" ${c.enabled ? 'checked' : ''} onchange="Campaigns.toggle('${c.id}', this.checked)">
            <span class="toggle-slider"></span>
          </label>
        </div>
        <div class="campaign-desc">${c.description}</div>
        <div class="mitre-tags">${techniques}</div>

        <div class="form-group">
          <label class="form-label">Interval: <span id="interval-val-${c.id}">${c.interval_minutes[0]}-${c.interval_minutes[1]}</span> min</label>
          <div style="display:flex;gap:8px;align-items:center">
            <input type="range" min="1" max="60" value="${c.interval_minutes[0]}" id="interval-min-${c.id}"
              oninput="document.getElementById('interval-val-${c.id}').textContent=this.value+'-'+document.getElementById('interval-max-${c.id}').value">
            <input type="range" min="5" max="120" value="${c.interval_minutes[1]}" id="interval-max-${c.id}"
              oninput="document.getElementById('interval-val-${c.id}').textContent=document.getElementById('interval-min-${c.id}').value+'-'+this.value">
          </div>
        </div>

        ${iocHtml}

        <div class="campaign-actions">
          <button class="btn btn-danger" onclick="Campaigns.trigger('${c.id}')">Trigger Now</button>
          <span class="trigger-result" id="trigger-result-${c.id}" style="font-size:12px;color:var(--text-secondary)"></span>
        </div>
      </div>
    `;
  },

  async toggle(id, enabled) {
    await App.api('PUT', `/api/campaigns/${id}`, { enabled });
  },

  async trigger(id) {
    const result = await App.api('POST', `/api/campaigns/${id}/trigger`);
    const el = document.getElementById(`trigger-result-${id}`);
    if (el) {
      el.textContent = `Generated ${result.events_generated} events`;
      el.style.color = 'var(--success)';
      setTimeout(() => { el.textContent = ''; }, 5000);
    }
  },
};
