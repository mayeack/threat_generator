/*
 * Unified Settings page: Generative AI (Claude) + Splunk HEC.
 *
 * Security notes (applied per workspace rules):
 *  - The Anthropic API key MAY be set via the UI (PUT /api/llm/key). It is
 *    written only to the OS secret store (macOS Keychain / Windows
 *    Credential Manager / Linux Secret Service) via the server-side
 *    `keyring` backend. It is NEVER persisted to `threatgen.db` or
 *    `default_config.yaml`, and NEVER returned from any API response.
 *    The `ANTHROPIC_API_KEY` environment variable always takes precedence
 *    over the keychain entry.
 *  - The Splunk HEC token MAY be set via the UI (PUT /api/hec/key). It
 *    is written only to the OS secret store via the server-side
 *    `keyring` backend. It is NEVER persisted to `threatgen.db` or
 *    `default_config.yaml`, and NEVER returned from any API response.
 *    The `SPLUNK_HEC_TOKEN` environment variable always takes
 *    precedence over the keychain entry.
 *  - All user-provided values are rendered via textContent / _attr() escaping
 *    to prevent DOM-based XSS (codeguard client-side web security).
 *  - Saves go through PUT /api/llm/config, PUT /api/llm/key,
 *    PUT /api/hec/config, and PUT /api/hec/key which each validate inputs
 *    server-side with Pydantic (codeguard input validation).
 */
const Settings = {
  hecDestinations: [],
  llmConfig: null,
  llmStatus: null,
  sourcetypeConfig: null,
  pollInterval: null,

  async render(container) {
    Settings.cleanup();

    await Settings._fetchAll();

    const llm = Settings.llmConfig || {};
    const llmStatus = Settings.llmStatus || {};
    const destinations = Settings.hecDestinations || [];
    const sts = Settings.sourcetypeConfig || {};

    const llmKeyBadge = Settings._llmKeyBadge(llm);

    const llmStateClass = Settings._llmStateClass(llm, llmStatus);
    const llmStateLabel = Settings._llmStateLabel(llm, llmStatus);

    container.innerHTML = `
      <div class="page active">
        <div class="page-header">
          <h1 class="page-title">Settings</h1>
        </div>

        <section id="settings-llm" class="settings-section" data-collapsed="false">
          <div class="settings-section-header">
            <div class="settings-section-heading">
              <button type="button" class="settings-collapse-btn" aria-expanded="true"
                aria-controls="settings-llm-body"
                onclick="Settings.toggleSection('settings-llm')"
                title="Collapse or expand section">
                <span class="settings-collapse-icon" aria-hidden="true"></span>
              </button>
              <div>
                <h2 class="settings-section-title">Generative AI</h2>
                <div class="settings-section-sub">
                  Drives per-sourcetype scenario variety and campaign narratives.
                  When disabled or when <code>ANTHROPIC_API_KEY</code> is not set,
                  all generators quietly fall back to deterministic patterns.
                </div>
              </div>
            </div>
            <div class="btn-group">
              <button class="btn" id="llm-btn-pause"
                onclick="Settings.toggleLLMPause()"
                title="Stop or resume the LLM variation worker. Not persisted; cleared on restart.">
                ${llmStatus.paused ? 'Resume GenAI Generation' : 'Pause GenAI Generation'}
              </button>
              <button class="btn" id="llm-btn-refresh" onclick="Settings.refreshLLMPool()">Regenerate Pool</button>
              <button class="btn btn-primary" onclick="Settings.saveLLM()">Save AI Settings</button>
            </div>
          </div>

          <div class="settings-section-body" id="settings-llm-body">
          <div class="grid-2">
            <div class="card">
              <div class="card-title">Worker Status</div>
              <div class="form-group">
                <span class="llm-pill ${llmStateClass}" id="llm-pill-settings">
                  <span class="llm-dot"></span>
                  <span class="llm-label">${llmStateLabel}</span>
                </span>
              </div>
              <table class="data-table">
                <tbody>
                  <tr><td style="width:220px">Environment key</td><td>${llmKeyBadge}</td></tr>
                  <tr><td>Worker running</td><td id="llm-running-cell">${llmStatus.worker_running ? 'yes' : 'no'}</td></tr>
                  <tr><td>Active model</td><td id="llm-active-model">${Settings._text(llmStatus.model || llm.model || '—')}</td></tr>
                  <tr><td>Campaign model</td><td id="llm-active-campaign">${Settings._text(llmStatus.campaign_model || llm.campaign_model || '—')}</td></tr>
                  <tr><td>Pool capacity</td><td id="llm-capacity">${Settings._text(llmStatus.capacity || 0)}</td></tr>
                  <tr><td>Last refresh</td><td id="llm-last-refresh">${Settings._fmtTs(llmStatus.last_refresh_ts)}</td></tr>
                  <tr><td>Last error</td><td id="llm-last-error">${Settings._text(llmStatus.last_error || '—')}</td></tr>
                </tbody>
              </table>
              <div class="form-group" style="margin-top:12px">
                <label class="form-label">Pool sizes</label>
                <div id="llm-pool-sizes" class="llm-pool-sizes">
                  ${Settings._renderPoolSizes(llmStatus)}
                </div>
              </div>
            </div>

            <div class="card">
              <div class="card-title">Anthropic API Key</div>
              <div class="form-group">
                <div id="llm-key-badge-slot">${llmKeyBadge}</div>
              </div>

              <div class="form-help">
                Precedence: the <code>ANTHROPIC_API_KEY</code> environment
                variable on the server always wins. Otherwise, a key stored
                in the OS keychain is used. The key is <strong>never</strong>
                written to <code>threatgen.db</code> or
                <code>default_config.yaml</code>, and is never returned by any
                API response.
              </div>

              <div id="llm-key-form" style="display:${llm.key_source === 'env' ? 'none' : 'block'}">
                <div class="form-group">
                  <label class="form-label" for="llm-api-key-input">
                    ${llm.key_source === 'keychain' ? 'Replace stored key' : 'Set API key'}
                  </label>
                  <div class="llm-key-row">
                    <input type="password"
                      class="form-input"
                      id="llm-api-key-input"
                      autocomplete="off"
                      spellcheck="false"
                      maxlength="500"
                      placeholder="sk-ant-...">
                    <button type="button" class="btn" id="llm-key-toggle"
                      onclick="Settings.toggleKeyVisibility()"
                      title="Show/hide">Show</button>
                  </div>
                  <div class="form-help">
                    Key is sent over the loopback interface only, stored in
                    the OS secret store, and cleared from the input field after
                    saving.
                  </div>
                </div>
                <div class="btn-group">
                  <button type="button" class="btn btn-primary"
                    onclick="Settings.saveLLMKey()">Save Key</button>
                  <button type="button" class="btn"
                    id="llm-key-clear-btn"
                    style="display:${llm.key_source === 'keychain' ? 'inline-flex' : 'none'}"
                    onclick="Settings.clearLLMKey()">Clear Stored Key</button>
                </div>
              </div>

              <div id="llm-key-env-note"
                class="form-help"
                style="display:${llm.key_source === 'env' ? 'block' : 'none'};margin-top:8px">
                The key is currently provided via <code>ANTHROPIC_API_KEY</code>.
                Unset that environment variable and restart ThreatGen if you
                want to manage the key from the UI.
              </div>

              <div id="llm-key-result" class="hec-test-result" style="margin-top:10px"></div>
            </div>
          </div>

          <div class="grid-2">
            <div class="card">
              <div class="card-title">Behavior</div>
              <div class="form-group">
                <label class="toggle-wrap">
                  <span class="form-label" style="margin:0">Enable generative AI</span>
                  <label class="toggle">
                    <input type="checkbox" id="llm-enabled" ${llm.enabled ? 'checked' : ''}>
                    <span class="toggle-slider"></span>
                  </label>
                </label>
                <div class="form-help">
                  When off, the worker stops and generators immediately use
                  pattern fallback. No API calls are made.
                </div>
              </div>
              <div class="form-group">
                <label class="form-label">Variation model</label>
                <input type="text" class="form-input" id="llm-model"
                  value="${Settings._attr(llm.model || 'claude-haiku-4-5')}"
                  maxlength="100"
                  placeholder="claude-haiku-4-5">
                <div class="form-help">Used to refill the per-sourcetype scenario cache.</div>
              </div>
              <div class="form-group">
                <label class="form-label">Campaign model</label>
                <input type="text" class="form-input" id="llm-campaign-model"
                  value="${Settings._attr(llm.campaign_model || 'claude-sonnet-4-5')}"
                  maxlength="100"
                  placeholder="claude-sonnet-4-5">
                <div class="form-help">Used once per campaign to draft a narrative plan.</div>
              </div>
            </div>

            <div class="card">
              <div class="card-title">Cache &amp; Refresh</div>
              <div class="form-group">
                <label class="form-label">Variation pool size (per sourcetype)</label>
                <input type="number" class="form-input" id="llm-pool-size"
                  min="1" max="1000"
                  value="${Settings._num(llm.variation_pool_size, 50)}">
              </div>
              <div class="form-group">
                <label class="form-label">Low-water mark (refill trigger)</label>
                <input type="number" class="form-input" id="llm-low-water"
                  min="1" max="1000"
                  value="${Settings._num(llm.low_water, 10)}">
              </div>
              <div class="form-group">
                <label class="form-label">Batch size per refill</label>
                <input type="number" class="form-input" id="llm-batch-size"
                  min="1" max="100"
                  value="${Settings._num(llm.batch_size, 10)}">
              </div>
              <div class="form-group">
                <label class="form-label">Refresh interval (minutes)</label>
                <input type="number" class="form-input" id="llm-refresh-interval"
                  min="1" max="1440"
                  value="${Settings._num(llm.refresh_interval_minutes, 60)}">
              </div>
            </div>

            <div class="card">
              <div class="card-title">Networking &amp; Limits</div>
              <div class="form-group">
                <label class="form-label">Request timeout (seconds)</label>
                <input type="number" class="form-input" id="llm-timeout"
                  min="1" max="300" step="0.5"
                  value="${Settings._num(llm.request_timeout_s, 30)}">
              </div>
              <div class="form-group">
                <label class="form-label">Max concurrent requests</label>
                <input type="number" class="form-input" id="llm-concurrency"
                  min="1" max="20"
                  value="${Settings._num(llm.max_concurrent_requests, 2)}">
              </div>
              <div class="form-group">
                <label class="form-label">Max retries per batch</label>
                <input type="number" class="form-input" id="llm-retries"
                  min="0" max="10"
                  value="${Settings._num(llm.max_retries, 2)}">
              </div>
            </div>

            <div class="card">
              <div class="card-title">Token Budgets</div>
              <div class="form-group">
                <label class="form-label">Max tokens (variation batch)</label>
                <input type="number" class="form-input" id="llm-tokens-variations"
                  min="256" max="32000" step="64"
                  value="${Settings._num(llm.max_tokens_variations, 4096)}">
              </div>
              <div class="form-group">
                <label class="form-label">Max tokens (campaign plan)</label>
                <input type="number" class="form-input" id="llm-tokens-campaign"
                  min="256" max="32000" step="64"
                  value="${Settings._num(llm.max_tokens_campaign, 4096)}">
              </div>
              <div class="form-help">
                Upper-bound per request. Lower values reduce cost; raise only
                if you see frequent truncation rejected by the JSON schema.
              </div>
            </div>
          </div>

          <div id="llm-save-result" class="hec-test-result"></div>
          </div>
        </section>

        <section id="settings-hec" class="settings-section" data-collapsed="false">
          <div class="settings-section-header">
            <div class="settings-section-heading">
              <button type="button" class="settings-collapse-btn" aria-expanded="true"
                aria-controls="settings-hec-body"
                onclick="Settings.toggleSection('settings-hec')"
                title="Collapse or expand section">
                <span class="settings-collapse-icon" aria-hidden="true"></span>
              </button>
              <div>
                <h2 class="settings-section-title">Splunk HEC Forwarding</h2>
                <div class="settings-section-sub">
                  Streams generated events to one or more Splunk HTTP Event
                  Collector endpoints. Every generated event is fanned out to
                  every enabled destination. Tokens are never written to
                  <code>threatgen.db</code> and never returned by any API.
                </div>
              </div>
            </div>
            <div class="btn-group">
              <button class="btn btn-primary"
                id="hec-btn-add"
                onclick="Settings.addHECDestination()"
                title="Add another Splunk HEC destination">+ Add Destination</button>
            </div>
          </div>

          <div class="settings-section-body" id="settings-hec-body">
            <div id="hec-destinations-list">
              ${Settings._hecTabbedHTML(destinations, sts)}
            </div>
          </div>
        </section>
      </div>
    `;

    Settings._bindHECCardListeners();

    await Settings._refreshRuntime();
    Settings.pollInterval = setInterval(Settings._refreshRuntime, 2500);
  },

  _bindHECCardListeners() {
    // Re-attach per-card listeners after any re-render. We listen on
    // the destinations list root so destinations added later still
    // pick up the warning toggle behavior.
    document.querySelectorAll('.hec-card').forEach(card => {
      const verify = card.querySelector('.hec-verify-tls');
      const warn = card.querySelector('.hec-tls-warn');
      if (verify && warn) {
        const update = () => {
          warn.style.display = verify.checked ? 'none' : 'block';
        };
        verify.removeEventListener('change', update);
        verify.addEventListener('change', update);
      }
    });
  },

  cleanup() {
    if (Settings.pollInterval) {
      clearInterval(Settings.pollInterval);
      Settings.pollInterval = null;
    }
  },

  toggleSection(id) {
    const section = document.getElementById(id);
    if (!section) return;
    const collapsed = section.dataset.collapsed === 'true';
    const next = collapsed ? 'false' : 'true';
    section.dataset.collapsed = next;
    const btn = section.querySelector('.settings-collapse-btn');
    if (btn) btn.setAttribute('aria-expanded', collapsed ? 'true' : 'false');
  },

  async toggleLLMPause() {
    const btn = document.getElementById('llm-btn-pause');
    const status = Settings.llmStatus || {};
    const paused = !!status.paused;
    const url = paused ? '/api/llm/resume' : '/api/llm/pause';
    if (btn) btn.disabled = true;
    try {
      const res = await fetch(url, { method: 'POST' });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        Settings._showLLMResult(false, `Failed: ${Settings._describeError(body, res.status)}`);
        return;
      }
      const info = await res.json();
      Settings._showLLMResult(
        true,
        info.paused ? 'GenAI generation paused.' : 'GenAI generation resumed.'
      );
      await Settings._refreshRuntime();
    } catch (_) {
      Settings._showLLMResult(false, 'Request failed (network error).');
    } finally {
      if (btn) btn.disabled = false;
    }
  },

  async _fetchAll() {
    try { Settings.llmConfig = await App.api('GET', '/api/llm/config'); }
    catch (_) { Settings.llmConfig = {}; }
    try { Settings.llmStatus = await App.api('GET', '/api/llm/status'); }
    catch (_) { Settings.llmStatus = {}; }
    try {
      const resp = await App.api('GET', '/api/hec/destinations');
      Settings.hecDestinations = (resp && Array.isArray(resp.destinations))
        ? resp.destinations
        : [];
    } catch (_) {
      Settings.hecDestinations = [];
    }
    try {
      const full = await App.api('GET', '/api/config');
      Settings.sourcetypeConfig = (full && full.sourcetypes) || {};
    } catch (_) {
      Settings.sourcetypeConfig = {};
    }
  },

  async _refreshRuntime() {
    try {
      const llmStatus = await App.api('GET', '/api/llm/status');
      Settings.llmStatus = llmStatus;
      Settings._paintLLMStatus(llmStatus);
    } catch (_) {}

    try {
      const resp = await App.api('GET', '/api/hec/stats');
      const list = (resp && Array.isArray(resp.destinations)) ? resp.destinations : [];
      list.forEach(s => Settings._paintHECStats(s));
    } catch (_) {}
  },

  _paintLLMStatus(status) {
    const pill = document.getElementById('llm-pill-settings');
    if (!pill) return;
    const llm = Settings.llmConfig || {};
    pill.classList.remove('llm-active', 'llm-degraded', 'llm-fallback');
    pill.classList.add(Settings._llmStateClass(llm, status));
    const label = pill.querySelector('.llm-label');
    if (label) label.textContent = Settings._llmStateLabel(llm, status);

    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    set('llm-running-cell', status.worker_running ? 'yes' : 'no');
    set('llm-active-model', status.model || llm.model || '—');
    set('llm-active-campaign', status.campaign_model || llm.campaign_model || '—');
    set('llm-capacity', status.capacity || 0);
    set('llm-last-refresh', Settings._fmtTs(status.last_refresh_ts));
    set('llm-last-error', status.last_error || '—');

    const poolEl = document.getElementById('llm-pool-sizes');
    if (poolEl) poolEl.innerHTML = Settings._renderPoolSizes(status);

    const refreshBtn = document.getElementById('llm-btn-refresh');
    if (refreshBtn) refreshBtn.disabled = !status.key_present || !!status.paused;

    const pauseBtn = document.getElementById('llm-btn-pause');
    if (pauseBtn) {
      pauseBtn.textContent = status.paused
        ? 'Resume GenAI Generation'
        : 'Pause GenAI Generation';
      pauseBtn.classList.toggle('btn-warning', !!status.paused);
    }
  },

  _paintHECStats(s) {
    if (!s || !s.id) return;
    const setIn = (root, sel, v) => {
      const el = root.querySelector(sel);
      if (el) el.textContent = v;
    };
    const card = document.querySelector(`.hec-card[data-dest-id="${CSS.escape(s.id)}"]`);
    if (!card) return;
    setIn(card, '.hec-sent', s.events_sent || 0);
    setIn(card, '.hec-failed', s.events_failed || 0);
    setIn(card, '.hec-dropped', s.events_dropped || 0);
    setIn(card, '.hec-queue', `${s.queue_depth || 0} / ${s.queue_capacity || 0}`);
    let state = 'disabled';
    if (s.enabled && s.running) state = 'running';
    else if (s.enabled && !s.running) state = 'configured (not running)';
    setIn(card, '.hec-state', state);
    setIn(card, '.hec-token', s.token_present ? 'yes' : 'no');
    setIn(card, '.hec-last-success', s.last_success_at || '—');
    setIn(card, '.hec-last-latency', s.last_latency_ms != null ? `${s.last_latency_ms} ms` : '—');
    setIn(card, '.hec-last-error', s.last_error || '—');
    setIn(card, '.hec-last-error-at', s.last_error_at || '—');
  },

  _llmStateClass(llm, status) {
    if (!status || !status.key_present) return 'llm-fallback';
    if (status.paused) return 'llm-fallback';
    if (!llm.enabled || !status.worker_running) return 'llm-fallback';
    if (status.degraded) return 'llm-degraded';
    return 'llm-active';
  },

  _llmStateLabel(llm, status) {
    if (!status || Object.keys(status).length === 0) return 'LLM: checking';
    if (!status.key_present) return 'LLM: fallback (no API key)';
    if (status.paused) return 'LLM: paused';
    if (!llm.enabled) return 'LLM: disabled';
    if (!status.worker_running) return 'LLM: fallback (worker not running)';
    const pools = status.pool_sizes || {};
    const totalPool = Object.values(pools).reduce((a, b) => a + (b || 0), 0);
    const totalCapacity = (status.capacity || 0) * Object.keys(pools).length;
    if (status.degraded) return `LLM: degraded (${totalPool}/${totalCapacity})`;
    return `LLM: active (${totalPool}/${totalCapacity})`;
  },

  _renderPoolSizes(status) {
    const pools = (status && status.pool_sizes) || {};
    const cap = (status && status.capacity) || 0;
    const names = Object.keys(pools).sort();
    if (names.length === 0) return '<div class="form-help">No pools yet.</div>';
    return names.map(n => `
      <div class="llm-pool-row">
        <span class="llm-pool-name">${Settings._attr(n)}</span>
        <span class="llm-pool-bar"><span class="llm-pool-fill" style="width:${cap ? Math.min(100, Math.round((pools[n] / cap) * 100)) : 0}%"></span></span>
        <span class="llm-pool-count">${pools[n]} / ${cap}</span>
      </div>`).join('');
  },

  async saveLLM() {
    const patch = {
      enabled: document.getElementById('llm-enabled').checked,
      model: document.getElementById('llm-model').value.trim(),
      campaign_model: document.getElementById('llm-campaign-model').value.trim(),
      variation_pool_size: parseInt(document.getElementById('llm-pool-size').value, 10),
      low_water: parseInt(document.getElementById('llm-low-water').value, 10),
      batch_size: parseInt(document.getElementById('llm-batch-size').value, 10),
      refresh_interval_minutes: parseInt(document.getElementById('llm-refresh-interval').value, 10),
      request_timeout_s: parseFloat(document.getElementById('llm-timeout').value),
      max_concurrent_requests: parseInt(document.getElementById('llm-concurrency').value, 10),
      max_retries: parseInt(document.getElementById('llm-retries').value, 10),
      max_tokens_variations: parseInt(document.getElementById('llm-tokens-variations').value, 10),
      max_tokens_campaign: parseInt(document.getElementById('llm-tokens-campaign').value, 10),
    };

    if (!patch.model) {
      Settings._showLLMResult(false, 'Variation model is required.');
      App.toast('Variation model is required.', 'err');
      return;
    }
    if (!patch.campaign_model) {
      Settings._showLLMResult(false, 'Campaign model is required.');
      App.toast('Campaign model is required.', 'err');
      return;
    }
    if (patch.low_water > patch.variation_pool_size) {
      Settings._showLLMResult(false, 'Low-water mark cannot exceed pool size.');
      App.toast('Low-water mark cannot exceed pool size.', 'err');
      return;
    }

    try {
      const res = await fetch('/api/llm/config', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(patch),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        const detail = Settings._describeError(body, res.status);
        Settings._showLLMResult(false, `Save failed: ${detail}`);
        App.toast(`AI settings save failed: ${detail}`, 'err');
        return;
      }
      Settings.llmConfig = await res.json();
      Settings._showLLMResult(true, 'AI settings saved. Worker reconfigured.');
      App.toast('AI settings saved', 'ok');
      await Settings._refreshRuntime();
    } catch (e) {
      Settings._showLLMResult(false, 'Save failed (network error)');
      App.toast('Save failed (network error)', 'err');
    }
  },

  _llmKeyBadge(llm) {
    const src = (llm && llm.key_source) || (llm && llm.key_env_set ? 'env' : 'none');
    if (src === 'env') {
      return `<span class="hec-badge hec-badge-ok">Key active (environment)</span>`;
    }
    if (src === 'keychain') {
      return `<span class="hec-badge hec-badge-ok">Key active (OS keychain)</span>`;
    }
    return `<span class="hec-badge hec-badge-warn">No API key configured</span>`;
  },

  toggleKeyVisibility() {
    const input = document.getElementById('llm-api-key-input');
    const btn = document.getElementById('llm-key-toggle');
    if (!input || !btn) return;
    if (input.type === 'password') {
      input.type = 'text';
      btn.textContent = 'Hide';
    } else {
      input.type = 'password';
      btn.textContent = 'Show';
    }
  },

  async saveLLMKey() {
    const input = document.getElementById('llm-api-key-input');
    if (!input) return;
    const raw = input.value || '';
    const key = raw.trim();
    if (!key) {
      Settings._renderResult('llm-key-result', false, 'API key is required.');
      App.toast('API key is required.', 'err');
      return;
    }
    if (!/^sk-ant-[A-Za-z0-9_\-]{20,500}$/.test(key)) {
      const msg = 'Key does not look like an Anthropic key (expected sk-ant-...).';
      Settings._renderResult('llm-key-result', false, msg);
      App.toast(msg, 'err');
      return;
    }

    try {
      const res = await fetch('/api/llm/key', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ api_key: key }),
      });
      // Best-effort wipe of the DOM value regardless of outcome.
      input.value = '';
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        const detail = Settings._describeError(body, res.status);
        Settings._renderResult('llm-key-result', false, `Save failed: ${detail}`);
        App.toast(`API key save failed: ${detail}`, 'err');
        return;
      }
      const info = await res.json();
      const msg = info.source === 'keychain'
        ? 'Key stored in OS keychain. Worker reconfigured.'
        : 'Key saved. Worker reconfigured.';
      Settings._renderResult('llm-key-result', true, msg);
      App.toast('Anthropic API key saved', 'ok');
      await Settings._reloadLLMKeyUi();
    } catch (_) {
      input.value = '';
      Settings._renderResult('llm-key-result', false, 'Save failed (network error).');
      App.toast('Save failed (network error)', 'err');
    }
  },

  async clearLLMKey() {
    if (!window.confirm('Remove the stored Anthropic API key from the OS keychain?')) {
      return;
    }
    try {
      const res = await fetch('/api/llm/key', { method: 'DELETE' });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        const detail = Settings._describeError(body, res.status);
        Settings._renderResult('llm-key-result', false, `Clear failed: ${detail}`);
        App.toast(`Clear failed: ${detail}`, 'err');
        return;
      }
      const info = await res.json();
      const msg = info.removed ? 'Stored key cleared.' : 'No key was stored.';
      Settings._renderResult('llm-key-result', true, msg);
      App.toast(msg, 'ok');
      await Settings._reloadLLMKeyUi();
    } catch (_) {
      Settings._renderResult('llm-key-result', false, 'Clear failed (network error).');
      App.toast('Clear failed (network error)', 'err');
    }
  },

  async _reloadLLMKeyUi() {
    try {
      Settings.llmConfig = await App.api('GET', '/api/llm/config');
    } catch (_) { /* keep stale config */ }
    const llm = Settings.llmConfig || {};

    const badgeSlot = document.getElementById('llm-key-badge-slot');
    if (badgeSlot) badgeSlot.innerHTML = Settings._llmKeyBadge(llm);

    const form = document.getElementById('llm-key-form');
    const envNote = document.getElementById('llm-key-env-note');
    const clearBtn = document.getElementById('llm-key-clear-btn');
    const label = document.querySelector('label[for="llm-api-key-input"]');

    if (form) form.style.display = llm.key_source === 'env' ? 'none' : 'block';
    if (envNote) envNote.style.display = llm.key_source === 'env' ? 'block' : 'none';
    if (clearBtn) clearBtn.style.display = llm.key_source === 'keychain' ? 'inline-flex' : 'none';
    if (label) {
      label.textContent = llm.key_source === 'keychain' ? 'Replace stored key' : 'Set API key';
    }

    await Settings._refreshRuntime();
  },

  _hecTokenBadge(dest) {
    const src = (dest && dest.token_source)
      || (dest && (dest.token_present || dest.token_env_set) ? 'env' : 'none');
    if (src === 'env') {
      return `<span class="hec-badge hec-badge-ok">Token active (environment)</span>`;
    }
    if (src === 'keychain') {
      return `<span class="hec-badge hec-badge-ok">Token active (OS keychain)</span>`;
    }
    return `<span class="hec-badge hec-badge-warn">No HEC token configured</span>`;
  },

  toggleHECTokenVisibility(destId) {
    const card = Settings._hecCard(destId);
    if (!card) return;
    const input = card.querySelector('.hec-token-input');
    const btn = card.querySelector('.hec-token-toggle');
    if (!input || !btn) return;
    if (input.type === 'password') {
      input.type = 'text';
      btn.textContent = 'Hide';
    } else {
      input.type = 'password';
      btn.textContent = 'Show';
    }
  },

  async saveHECKey(destId) {
    const card = Settings._hecCard(destId);
    if (!card) return;
    const input = card.querySelector('.hec-token-input');
    if (!input) return;
    const raw = input.value || '';
    const token = raw.trim();
    if (!token) {
      Settings._showHECKeyResult(destId, false, 'HEC token is required.');
      App.toast('HEC token is required.', 'err');
      return;
    }
    // Client-side shape check mirrors server validation (UUID).
    if (!/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(token)) {
      const msg = 'Token does not look like a Splunk HEC token (expected UUID: 8-4-4-4-12 hex).';
      Settings._showHECKeyResult(destId, false, msg);
      App.toast(msg, 'err');
      return;
    }

    try {
      const res = await fetch(
        `/api/hec/destinations/${encodeURIComponent(destId)}/key`,
        {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token }),
        },
      );
      // Best-effort wipe of the DOM value regardless of outcome.
      input.value = '';
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        const detail = Settings._describeError(body, res.status);
        Settings._showHECKeyResult(destId, false, `Save failed: ${detail}`);
        App.toast(`HEC token save failed: ${detail}`, 'err');
        return;
      }
      const info = await res.json();
      const msg = info.source === 'keychain'
        ? 'Token stored in OS keychain. Forwarder reconfigured.'
        : 'Token saved. Forwarder reconfigured.';
      Settings._showHECKeyResult(destId, true, msg);
      App.toast('HEC token saved', 'ok');
      await Settings._reloadHECKeyUi(destId);
    } catch (_) {
      input.value = '';
      Settings._showHECKeyResult(destId, false, 'Save failed (network error).');
      App.toast('Save failed (network error)', 'err');
    }
  },

  async clearHECKey(destId) {
    if (!window.confirm('Remove the stored Splunk HEC token for this destination from the OS keychain?')) {
      return;
    }
    try {
      const res = await fetch(
        `/api/hec/destinations/${encodeURIComponent(destId)}/key`,
        { method: 'DELETE' },
      );
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        const detail = Settings._describeError(body, res.status);
        Settings._showHECKeyResult(destId, false, `Clear failed: ${detail}`);
        App.toast(`Clear failed: ${detail}`, 'err');
        return;
      }
      const info = await res.json();
      const msg = info.removed ? 'Stored token cleared.' : 'No token was stored.';
      Settings._showHECKeyResult(destId, true, msg);
      App.toast(msg, 'ok');
      await Settings._reloadHECKeyUi(destId);
    } catch (_) {
      Settings._showHECKeyResult(destId, false, 'Clear failed (network error).');
      App.toast('Clear failed (network error)', 'err');
    }
  },

  async _reloadHECKeyUi(destId) {
    let fresh = null;
    try {
      fresh = await App.api('GET', `/api/hec/destinations/${encodeURIComponent(destId)}`);
    } catch (_) { /* keep stale config */ }
    if (fresh) {
      const idx = Settings.hecDestinations.findIndex(d => d.id === destId);
      if (idx >= 0) Settings.hecDestinations[idx] = fresh;
    }

    const dest = fresh
      || Settings.hecDestinations.find(d => d.id === destId)
      || {};
    const card = Settings._hecCard(destId);
    if (!card) return;

    const badgeSlot = card.querySelector('.hec-token-badge-slot');
    if (badgeSlot) badgeSlot.innerHTML = Settings._hecTokenBadge(dest);

    const form = card.querySelector('.hec-key-form');
    const envNote = card.querySelector('.hec-key-env-note');
    const clearBtn = card.querySelector('.hec-key-clear-btn');
    const label = card.querySelector('.hec-token-label');
    const envVarSpan = card.querySelector('.hec-env-var-name');

    if (form) form.style.display = dest.token_source === 'env' ? 'none' : 'block';
    if (envNote) envNote.style.display = dest.token_source === 'env' ? 'block' : 'none';
    if (clearBtn) clearBtn.style.display = dest.token_source === 'keychain' ? 'inline-flex' : 'none';
    if (label) {
      label.textContent = dest.token_source === 'keychain' ? 'Replace stored token' : 'Set HEC token';
    }
    if (envVarSpan && dest.token_env_var) {
      envVarSpan.textContent = dest.token_env_var;
    }

    await Settings._refreshRuntime();
  },

  async refreshLLMPool() {
    const btn = document.getElementById('llm-btn-refresh');
    if (btn) { btn.disabled = true; btn.textContent = 'Requesting...'; }
    try {
      const res = await fetch('/api/llm/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        Settings._showLLMResult(false, `Refresh failed: ${Settings._describeError(body, res.status)}`);
      } else {
        Settings._showLLMResult(true, 'Refresh queued.');
      }
    } catch (_) {
      Settings._showLLMResult(false, 'Refresh failed (network error)');
    } finally {
      setTimeout(() => {
        if (btn) { btn.textContent = 'Regenerate Pool'; btn.disabled = false; }
      }, 1500);
    }
  },

  _hecCard(destId) {
    return document.querySelector(
      `.hec-card[data-dest-id="${CSS.escape(destId)}"]`
    );
  },

  async addHECDestination() {
    const btn = document.getElementById('hec-btn-add');
    if (btn) btn.disabled = true;
    try {
      // A blank destination is fine; the server picks a fresh id and name.
      const res = await fetch('/api/hec/destinations', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: false }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        App.toast(`Add failed: ${Settings._describeError(body, res.status)}`, 'err');
        return;
      }
      // Focus the freshly created destination's tab after re-render.
      const created = await res.json().catch(() => null);
      if (created && created.id) Settings.activeHECDest = created.id;
      App.toast('Destination added', 'ok');
      // Full re-render so the new card mounts in the destinations list.
      await Settings._rerenderHECList();
    } catch (_) {
      App.toast('Add failed (network error)', 'err');
    } finally {
      if (btn) btn.disabled = false;
    }
  },

  async removeHECDestination(destId) {
    if (!destId) return;
    if (!window.confirm(`Remove destination "${destId}"? This also clears any stored token for it.`)) {
      return;
    }
    try {
      const res = await fetch(`/api/hec/destinations/${encodeURIComponent(destId)}`, {
        method: 'DELETE',
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        App.toast(`Remove failed: ${Settings._describeError(body, res.status)}`, 'err');
        return;
      }
      App.toast('Destination removed', 'ok');
      await Settings._rerenderHECList();
    } catch (_) {
      App.toast('Remove failed (network error)', 'err');
    }
  },

  async saveHEC(destId) {
    const card = Settings._hecCard(destId);
    if (!card) return;
    const urlEl = card.querySelector('.hec-url');
    const url = (urlEl.value || '').trim();
    if (url && !/^https:\/\//i.test(url)) {
      Settings._showHECResult(destId, false, 'URL must start with https://');
      App.toast('URL must start with https://', 'err');
      return;
    }

    const patch = {
      name: (card.querySelector('.hec-name').value || '').trim() || `Destination ${destId}`,
      enabled: card.querySelector('.hec-enabled').checked,
      url: url,
      verify_tls: card.querySelector('.hec-verify-tls').checked,
      default_index: (card.querySelector('.hec-index').value || '').trim() || 'main',
      default_source: (card.querySelector('.hec-source').value || '').trim() || 'threatgen',
      default_host: (card.querySelector('.hec-host').value || '').trim() || 'threatgen',
      sourcetype_map: Settings._collectMap(destId),
      batch_size: parseInt(card.querySelector('.hec-batch-size').value, 10) || 100,
      flush_interval_s: parseFloat(card.querySelector('.hec-flush').value) || 2.0,
      queue_max: parseInt(card.querySelector('.hec-queue-max').value, 10) || 10000,
      request_timeout_s: parseFloat(card.querySelector('.hec-timeout').value) || 10.0,
      max_retries: parseInt(card.querySelector('.hec-retries').value, 10) || 0,
    };

    try {
      const res = await fetch(`/api/hec/destinations/${encodeURIComponent(destId)}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(patch),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        const detail = Settings._describeError(body, res.status);
        Settings._showHECResult(destId, false, `Save failed: ${detail}`);
        App.toast(`HEC save failed: ${detail}`, 'err');
        return;
      }
      const updated = await res.json();
      // Patch our in-memory cache so the next re-render has fresh data.
      const idx = Settings.hecDestinations.findIndex(d => d.id === destId);
      if (idx >= 0) Settings.hecDestinations[idx] = updated;
      Settings._showHECResult(destId, true, 'Destination saved; forwarder reloaded.');
      App.toast('HEC destination saved', 'ok');
      await Settings._refreshRuntime();
    } catch (e) {
      Settings._showHECResult(destId, false, 'Save failed (network error)');
      App.toast('Save failed (network error)', 'err');
    }
  },

  async testHEC(destId) {
    const card = Settings._hecCard(destId);
    const btn = card ? card.querySelector('.hec-btn-test') : null;
    if (btn) btn.disabled = true;
    Settings._showHECResult(destId, null, 'Sending test event...');
    try {
      const res = await App.api('POST', `/api/hec/destinations/${encodeURIComponent(destId)}/test`);
      if (res && res.ok) {
        Settings._showHECResult(destId, true, `Success: HTTP ${res.status_code || ''} in ${res.latency_ms} ms`);
      } else {
        Settings._showHECResult(destId, false, `Failed: ${(res && res.error) || 'unknown error'}`);
      }
    } catch (_) {
      Settings._showHECResult(destId, false, 'Test failed (network error)');
    } finally {
      if (btn) btn.disabled = false;
      await Settings._refreshRuntime();
    }
  },

  _collectMap(destId) {
    const card = Settings._hecCard(destId);
    const map = {};
    if (!card) return map;
    card.querySelectorAll('.hec-st-map').forEach(el => {
      const k = el.dataset.st;
      const v = (el.value || '').trim();
      if (k && v) map[k] = v;
    });
    return map;
  },

  _showLLMResult(ok, message) { Settings._renderResult('llm-save-result', ok, message); },

  _showHECResult(destId, ok, message) {
    const card = Settings._hecCard(destId);
    if (!card) return;
    const el = card.querySelector('.hec-test-result-slot');
    if (!el) return;
    let cls = 'hec-test-info';
    if (ok === true) cls = 'hec-test-ok';
    else if (ok === false) cls = 'hec-test-err';
    el.className = 'hec-test-result ' + cls;
    el.textContent = message;
  },

  _showHECKeyResult(destId, ok, message) {
    const card = Settings._hecCard(destId);
    if (!card) return;
    const el = card.querySelector('.hec-key-result-slot');
    if (!el) return;
    let cls = 'hec-test-info';
    if (ok === true) cls = 'hec-test-ok';
    else if (ok === false) cls = 'hec-test-err';
    el.className = 'hec-test-result ' + cls;
    el.textContent = message;
  },

  async _rerenderHECList() {
    await Settings._fetchAll();
    const list = document.getElementById('hec-destinations-list');
    if (!list) return;
    const destinations = Settings.hecDestinations || [];
    const sts = Settings.sourcetypeConfig || {};
    list.innerHTML = Settings._hecTabbedHTML(destinations, sts);
    Settings._bindHECCardListeners();
    await Settings._refreshRuntime();
  },

  // ------------------------------------------------------------------
  // Chrome-style tabbed HEC destinations
  //
  // Renders a horizontal tab strip (one tab per destination plus a
  // trailing "+" tab) above a panel area. Only the active destination's
  // card is shown; the rest stay in the DOM (display:none) so runtime
  // stat painting and per-card DOM queries keep working for every
  // destination regardless of which tab is visible.
  // ------------------------------------------------------------------
  _hecTabbedHTML(destinations, sts) {
    destinations = destinations || [];
    if (destinations.length === 0) {
      return `<div class="form-help">No HEC destinations configured. Click "+ Add Destination" to forward events to a Splunk instance.</div>`;
    }
    Settings._normalizeActiveHEC(destinations);
    const active = Settings.activeHECDest;

    const tabs = destinations.map(d => {
      const id = d.id || '';
      const isActive = id === active;
      const isDefault = id === 'default';
      const close = isDefault
        ? ''
        : `<span class="hec-tab-close" title="Remove destination"
              onclick="event.stopPropagation();Settings.removeHECDestination('${Settings._attr(id)}')">&times;</span>`;
      return `
        <button type="button" class="hec-tab${isActive ? ' active' : ''}"
          role="tab" aria-selected="${isActive ? 'true' : 'false'}"
          data-tab-id="${Settings._attr(id)}"
          onclick="Settings.selectHECTab('${Settings._attr(id)}')"
          title="${Settings._attr(d.name || id)}">
          <span class="hec-tab-dot ${d.enabled ? 'on' : 'off'}"></span>
          <span class="hec-tab-label">${Settings._attr(d.name || id)}</span>
          ${close}
        </button>`;
    }).join('');

    const panels = destinations.map(d => {
      const id = d.id || '';
      const isActive = id === active;
      return `
        <div class="hec-panel" data-panel-id="${Settings._attr(id)}"
          style="display:${isActive ? 'block' : 'none'}">
          ${Settings._renderHECDestinationCard(d, sts)}
        </div>`;
    }).join('');

    return `
      <div class="hec-tabs" role="tablist">
        ${tabs}
        <button type="button" class="hec-tab-add"
          onclick="Settings.addHECDestination()"
          title="Add another Splunk HEC destination">+</button>
      </div>
      <div class="hec-panels">${panels}</div>
    `;
  },

  _normalizeActiveHEC(destinations) {
    const ids = (destinations || []).map(d => d.id);
    if (!Settings.activeHECDest || !ids.includes(Settings.activeHECDest)) {
      Settings.activeHECDest = ids.length ? ids[0] : null;
    }
  },

  selectHECTab(destId) {
    Settings.activeHECDest = destId;
    document.querySelectorAll('.hec-tab').forEach(t => {
      const on = t.dataset.tabId === destId;
      t.classList.toggle('active', on);
      t.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    document.querySelectorAll('.hec-panel').forEach(p => {
      p.style.display = p.dataset.panelId === destId ? 'block' : 'none';
    });
  },

  _renderResult(id, ok, message) {
    const el = document.getElementById(id);
    if (!el) return;
    let cls = 'hec-test-info';
    if (ok === true) cls = 'hec-test-ok';
    else if (ok === false) cls = 'hec-test-err';
    el.className = 'hec-test-result ' + cls;
    el.textContent = message;
  },

  _describeError(body, status) {
    if (!body) return `HTTP ${status}`;
    if (typeof body.detail === 'string') return body.detail;
    if (Array.isArray(body.detail) && body.detail.length) {
      const d = body.detail[0];
      const loc = Array.isArray(d.loc) ? d.loc.filter(x => x !== 'body').join('.') : '';
      return loc ? `${loc}: ${d.msg}` : d.msg;
    }
    return `HTTP ${status}`;
  },

  _fmtTs(ts) {
    if (!ts) return '—';
    try { return new Date(ts * 1000).toLocaleString(); } catch (_) { return '—'; }
  },

  _num(v, fallback) {
    if (v == null || Number.isNaN(v)) return fallback;
    return v;
  },

  _text(s) { return String(s == null ? '' : s); },

  _attr(s) {
    return String(s == null ? '' : s)
      .replace(/&/g, '&amp;')
      .replace(/"/g, '&quot;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  },

  // ------------------------------------------------------------------
  // HEC destination card renderer
  //
  // Renders one destination card. All user-controlled values pass
  // through ``_attr`` for HTML-attribute escaping (codeguard XSS).
  // The card has a stable ``data-dest-id`` attribute so per-card
  // handlers can scope DOM queries with ``CSS.escape``.
  // ------------------------------------------------------------------
  _renderHECDestinationCard(dest, sts) {
    const destId = dest.id || '';
    const isDefault = destId === 'default';
    const map = dest.sourcetype_map || {};
    const tokenBadge = Settings._hecTokenBadge(dest);
    const tokenSource = dest.token_source || 'none';
    const envVar = dest.token_env_var || 'SPLUNK_HEC_TOKEN';

    const removeBtn = isDefault
      ? ''
      : `<button class="btn" onclick="Settings.removeHECDestination('${Settings._attr(destId)}')"
            title="Remove this destination">Remove</button>`;

    return `
      <div class="card hec-card" data-dest-id="${Settings._attr(destId)}">
        <div class="hec-card-header">
          <div>
            <div class="hec-card-title">
              <span class="hec-card-name">${Settings._attr(dest.name || destId)}</span>
              <span class="hec-card-id">${Settings._attr(destId)}</span>
            </div>
            <div class="form-help" style="margin-top:4px">
              Every generated event is fanned out to every enabled destination.
            </div>
          </div>
          <div class="btn-group">
            <button class="btn hec-btn-test"
              onclick="Settings.testHEC('${Settings._attr(destId)}')"
              title="Send a synthetic event to verify connectivity">Test Connection</button>
            <button class="btn btn-primary"
              onclick="Settings.saveHEC('${Settings._attr(destId)}')">Save</button>
            ${removeBtn}
          </div>
        </div>

        <div class="hec-test-result hec-test-result-top hec-test-result-slot"></div>

        <div class="grid-2">
          <div class="hec-subcard">
            <div class="card-title">Connection</div>
            <div class="form-group">
              <label class="form-label">Display name</label>
              <input type="text" class="form-input hec-name"
                value="${Settings._attr(dest.name || '')}"
                maxlength="80"
                placeholder="e.g. Primary, Lab, DR">
            </div>
            <div class="form-group">
              <label class="toggle-wrap">
                <span class="form-label" style="margin:0">Enable forwarding</span>
                <label class="toggle">
                  <input type="checkbox" class="hec-enabled" ${dest.enabled ? 'checked' : ''}>
                  <span class="toggle-slider"></span>
                </label>
              </label>
            </div>
            <div class="form-group">
              <label class="form-label">HEC URL (Splunk Cloud)</label>
              <input type="text" class="form-input hec-url"
                value="${Settings._attr(dest.url || '')}"
                maxlength="512"
                placeholder="https://http-inputs-&lt;stack&gt;.splunkcloud.com:443">
              <div class="form-help">Must start with <code>https://</code>. The <code>/services/collector/event</code> path is appended automatically if omitted.</div>
            </div>
            <div class="form-group">
              <label class="toggle-wrap">
                <span class="form-label" style="margin:0">Verify TLS certificate</span>
                <label class="toggle">
                  <input type="checkbox" class="hec-verify-tls" ${dest.verify_tls !== false ? 'checked' : ''}>
                  <span class="toggle-slider"></span>
                </label>
              </label>
              <div class="form-help hec-tls-warn"
                style="display:${dest.verify_tls === false ? 'block' : 'none'};color:var(--danger)">
                Warning: disabling TLS verification is unsafe and should only be used in isolated development environments.
              </div>
            </div>
            <div class="form-group">
              <label class="form-label">Default Index</label>
              <input type="text" class="form-input hec-index"
                value="${Settings._attr(dest.default_index || 'main')}">
            </div>
            <div class="form-group">
              <label class="form-label">Default Source</label>
              <input type="text" class="form-input hec-source"
                value="${Settings._attr(dest.default_source || 'threatgen')}">
            </div>
            <div class="form-group">
              <label class="form-label">Default Host</label>
              <input type="text" class="form-input hec-host"
                value="${Settings._attr(dest.default_host || 'threatgen')}">
            </div>
          </div>

          <div class="hec-subcard">
            <div class="card-title">HEC Token</div>
            <div class="form-group">
              <div class="hec-token-badge-slot">${tokenBadge}</div>
            </div>

            <div class="form-help">
              Precedence: the <code class="hec-env-var-name">${Settings._attr(envVar)}</code>
              environment variable on the server always wins. Otherwise, a token stored
              in the OS keychain for this destination is used. The token is
              <strong>never</strong> written to <code>threatgen.db</code> or
              <code>default_config.yaml</code>, and is never returned by any API response.
            </div>

            <div class="hec-key-form" style="display:${tokenSource === 'env' ? 'none' : 'block'}">
              <div class="form-group">
                <label class="form-label hec-token-label">
                  ${tokenSource === 'keychain' ? 'Replace stored token' : 'Set HEC token'}
                </label>
                <div class="llm-key-row">
                  <input type="password"
                    class="form-input hec-token-input"
                    autocomplete="off"
                    spellcheck="false"
                    maxlength="36"
                    placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx">
                  <button type="button" class="btn hec-token-toggle"
                    onclick="Settings.toggleHECTokenVisibility('${Settings._attr(destId)}')"
                    title="Show/hide">Show</button>
                </div>
                <div class="form-help">
                  Token is sent over the loopback interface only, stored in
                  the OS secret store under this destination's id, and cleared
                  from the input field after saving.
                </div>
              </div>
              <div class="btn-group">
                <button type="button" class="btn btn-primary"
                  onclick="Settings.saveHECKey('${Settings._attr(destId)}')">Save Token</button>
                <button type="button" class="btn hec-key-clear-btn"
                  style="display:${tokenSource === 'keychain' ? 'inline-flex' : 'none'}"
                  onclick="Settings.clearHECKey('${Settings._attr(destId)}')">Clear Stored Token</button>
              </div>
            </div>

            <div class="form-help hec-key-env-note"
              style="display:${tokenSource === 'env' ? 'block' : 'none'};margin-top:8px">
              The token is currently provided via
              <code class="hec-env-var-name">${Settings._attr(envVar)}</code>.
              Unset that environment variable and restart ThreatGen if you
              want to manage the token from the UI.
            </div>

            <div class="hec-test-result hec-key-result-slot" style="margin-top:10px"></div>

            <div class="card-title" style="margin-top:16px">Performance</div>
            <div class="form-group">
              <label class="form-label">Batch Size</label>
              <input type="number" class="form-input hec-batch-size" min="1" max="10000"
                value="${Settings._num(dest.batch_size, 100)}">
            </div>
            <div class="form-group">
              <label class="form-label">Flush Interval (seconds)</label>
              <input type="number" class="form-input hec-flush" min="0.1" max="300" step="0.1"
                value="${Settings._num(dest.flush_interval_s, 2.0)}">
            </div>
            <div class="form-group">
              <label class="form-label">Queue Capacity</label>
              <input type="number" class="form-input hec-queue-max" min="1" max="1000000"
                value="${Settings._num(dest.queue_max, 10000)}">
            </div>
            <div class="form-group">
              <label class="form-label">Request Timeout (seconds)</label>
              <input type="number" class="form-input hec-timeout" min="1" max="300" step="0.5"
                value="${Settings._num(dest.request_timeout_s, 10.0)}">
            </div>
            <div class="form-group">
              <label class="form-label">Max Retries</label>
              <input type="number" class="form-input hec-retries" min="0" max="10"
                value="${Settings._num(dest.max_retries, 3)}">
            </div>
          </div>
        </div>

        <div class="hec-subcard">
          <div class="card-title">Sourcetype Mapping</div>
          <div class="form-help" style="margin-bottom:10px">
            Optional: override the Splunk <code>sourcetype</code> sent for each
            generator. Leave a row blank to send the generator's native name.
          </div>
          <table class="data-table">
            <thead>
              <tr><th>Generator</th><th>Splunk sourcetype override</th></tr>
            </thead>
            <tbody>
              ${Object.keys(sts || {}).sort().map(name => `
                <tr>
                  <td>${Settings._attr(name)}</td>
                  <td>
                    <input type="text" class="hec-st-map" data-st="${Settings._attr(name)}"
                      value="${Settings._attr(map[name] || '')}"
                      placeholder="(use &quot;${Settings._attr(name)}&quot;)">
                  </td>
                </tr>
              `).join('')}
            </tbody>
          </table>
        </div>

        <div class="grid-4">
          <div class="hec-subcard">
            <div class="card-title">Events Sent</div>
            <div class="stat-value success hec-sent">0</div>
            <div class="stat-label">Total forwarded</div>
          </div>
          <div class="hec-subcard">
            <div class="card-title">Events Failed</div>
            <div class="stat-value danger hec-failed">0</div>
            <div class="stat-label">After all retries</div>
          </div>
          <div class="hec-subcard">
            <div class="card-title">Events Dropped</div>
            <div class="stat-value hec-dropped">0</div>
            <div class="stat-label">Queue overflow</div>
          </div>
          <div class="hec-subcard">
            <div class="card-title">Queue</div>
            <div class="stat-value hec-queue">0 / 0</div>
            <div class="stat-label">Depth / capacity</div>
          </div>
        </div>

        <div class="hec-subcard">
          <div class="card-title">Forwarder Health</div>
          <table class="data-table">
            <tbody>
              <tr><td style="width:220px">State</td><td class="hec-state">unknown</td></tr>
              <tr><td>Token detected for this destination</td><td class="hec-token">—</td></tr>
              <tr><td>Last success</td><td class="hec-last-success">—</td></tr>
              <tr><td>Last success latency</td><td class="hec-last-latency">—</td></tr>
              <tr><td>Last error</td><td class="hec-last-error">—</td></tr>
              <tr><td>Last error time</td><td class="hec-last-error-at">—</td></tr>
            </tbody>
          </table>
        </div>
      </div>
    `;
  },
};
