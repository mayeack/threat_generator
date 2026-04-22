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
  hecConfig: null,
  llmConfig: null,
  llmStatus: null,
  sourcetypeConfig: null,
  pollInterval: null,

  async render(container) {
    Settings.cleanup();

    await Settings._fetchAll();

    const llm = Settings.llmConfig || {};
    const llmStatus = Settings.llmStatus || {};
    const hec = Settings.hecConfig || {};
    const sts = Settings.sourcetypeConfig || {};
    const map = hec.sourcetype_map || {};

    const llmKeyBadge = Settings._llmKeyBadge(llm);
    const hecTokenBadge = Settings._hecTokenBadge(hec);

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
                  Streams generated events directly to a Splunk HTTP Event
                  Collector endpoint. TLS is required; the token lives only in
                  the <code>SPLUNK_HEC_TOKEN</code> environment variable.
                </div>
              </div>
            </div>
            <div class="btn-group">
              <button class="btn" id="hec-btn-test" onclick="Settings.testHEC()">Test Connection</button>
              <button class="btn btn-primary" onclick="Settings.saveHEC()">Save HEC Settings</button>
            </div>
          </div>

          <div class="settings-section-body" id="settings-hec-body">
          <div id="hec-test-result" class="hec-test-result hec-test-result-top"></div>
          <div class="grid-2">
            <div class="card">
              <div class="card-title">Connection</div>
              <div class="form-group">
                <label class="toggle-wrap">
                  <span class="form-label" style="margin:0">Enable forwarding</span>
                  <label class="toggle">
                    <input type="checkbox" id="hec-enabled" ${hec.enabled ? 'checked' : ''}>
                    <span class="toggle-slider"></span>
                  </label>
                </label>
              </div>
              <div class="form-group">
                <label class="form-label">HEC URL (Splunk Cloud)</label>
                <input type="text" class="form-input" id="hec-url"
                  value="${Settings._attr(hec.url || '')}"
                  maxlength="512"
                  placeholder="https://http-inputs-&lt;stack&gt;.splunkcloud.com:443">
                <div class="form-help">Must start with <code>https://</code>. The <code>/services/collector/event</code> path is appended automatically if omitted.</div>
              </div>
              <div class="form-group">
                <label class="toggle-wrap">
                  <span class="form-label" style="margin:0">Verify TLS certificate</span>
                  <label class="toggle">
                    <input type="checkbox" id="hec-verify-tls" ${hec.verify_tls !== false ? 'checked' : ''}>
                    <span class="toggle-slider"></span>
                  </label>
                </label>
                <div class="form-help" id="hec-tls-warn" style="display:${hec.verify_tls === false ? 'block' : 'none'};color:var(--danger)">
                  Warning: disabling TLS verification is unsafe and should only be used in isolated development environments.
                </div>
              </div>
              <div class="form-group">
                <label class="form-label">Default Index</label>
                <input type="text" class="form-input" id="hec-index" value="${Settings._attr(hec.default_index || 'main')}">
              </div>
              <div class="form-group">
                <label class="form-label">Default Source</label>
                <input type="text" class="form-input" id="hec-source" value="${Settings._attr(hec.default_source || 'threatgen')}">
              </div>
              <div class="form-group">
                <label class="form-label">Default Host</label>
                <input type="text" class="form-input" id="hec-host" value="${Settings._attr(hec.default_host || 'threatgen')}">
              </div>
            </div>

            <div class="card">
              <div class="card-title">HEC Token</div>
              <div class="form-group">
                <div id="hec-token-badge-slot">${hecTokenBadge}</div>
              </div>

              <div class="form-help">
                Precedence: the <code>SPLUNK_HEC_TOKEN</code> environment
                variable on the server always wins. Otherwise, a token stored
                in the OS keychain is used. The token is <strong>never</strong>
                written to <code>threatgen.db</code> or
                <code>default_config.yaml</code>, and is never returned by any
                API response.
              </div>

              <div id="hec-key-form" style="display:${hec.token_source === 'env' ? 'none' : 'block'}">
                <div class="form-group">
                  <label class="form-label" for="hec-token-input">
                    ${hec.token_source === 'keychain' ? 'Replace stored token' : 'Set HEC token'}
                  </label>
                  <div class="llm-key-row">
                    <input type="password"
                      class="form-input"
                      id="hec-token-input"
                      autocomplete="off"
                      spellcheck="false"
                      maxlength="36"
                      placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx">
                    <button type="button" class="btn" id="hec-token-toggle"
                      onclick="Settings.toggleHECTokenVisibility()"
                      title="Show/hide">Show</button>
                  </div>
                  <div class="form-help">
                    Token is sent over the loopback interface only, stored in
                    the OS secret store, and cleared from the input field after
                    saving.
                  </div>
                </div>
                <div class="btn-group">
                  <button type="button" class="btn btn-primary"
                    onclick="Settings.saveHECKey()">Save Token</button>
                  <button type="button" class="btn"
                    id="hec-key-clear-btn"
                    style="display:${hec.token_source === 'keychain' ? 'inline-flex' : 'none'}"
                    onclick="Settings.clearHECKey()">Clear Stored Token</button>
                </div>
              </div>

              <div id="hec-key-env-note"
                class="form-help"
                style="display:${hec.token_source === 'env' ? 'block' : 'none'};margin-top:8px">
                The token is currently provided via <code>SPLUNK_HEC_TOKEN</code>.
                Unset that environment variable and restart ThreatGen if you
                want to manage the token from the UI.
              </div>

              <div id="hec-key-result" class="hec-test-result" style="margin-top:10px"></div>

              <div class="card-title" style="margin-top:16px">Performance</div>
              <div class="form-group">
                <label class="form-label">Batch Size</label>
                <input type="number" class="form-input" id="hec-batch-size" min="1" max="10000" value="${Settings._num(hec.batch_size, 100)}">
              </div>
              <div class="form-group">
                <label class="form-label">Flush Interval (seconds)</label>
                <input type="number" class="form-input" id="hec-flush" min="0.1" max="300" step="0.1" value="${Settings._num(hec.flush_interval_s, 2.0)}">
              </div>
              <div class="form-group">
                <label class="form-label">Queue Capacity</label>
                <input type="number" class="form-input" id="hec-queue-max" min="1" max="1000000" value="${Settings._num(hec.queue_max, 10000)}">
              </div>
              <div class="form-group">
                <label class="form-label">Request Timeout (seconds)</label>
                <input type="number" class="form-input" id="hec-timeout" min="1" max="300" step="0.5" value="${Settings._num(hec.request_timeout_s, 10.0)}">
              </div>
              <div class="form-group">
                <label class="form-label">Max Retries</label>
                <input type="number" class="form-input" id="hec-retries" min="0" max="10" value="${Settings._num(hec.max_retries, 3)}">
              </div>
            </div>
          </div>

          <div class="card">
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
                ${Object.keys(sts).sort().map(name => `
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
            <div class="card">
              <div class="card-title">Events Sent</div>
              <div class="stat-value success" id="hec-sent">0</div>
              <div class="stat-label">Total forwarded</div>
            </div>
            <div class="card">
              <div class="card-title">Events Failed</div>
              <div class="stat-value danger" id="hec-failed">0</div>
              <div class="stat-label">After all retries</div>
            </div>
            <div class="card">
              <div class="card-title">Events Dropped</div>
              <div class="stat-value" id="hec-dropped">0</div>
              <div class="stat-label">Queue overflow</div>
            </div>
            <div class="card">
              <div class="card-title">Queue</div>
              <div class="stat-value" id="hec-queue">0 / 0</div>
              <div class="stat-label">Depth / capacity</div>
            </div>
          </div>

          <div class="card">
            <div class="card-title">Forwarder Health</div>
            <table class="data-table">
              <tbody>
                <tr><td style="width:220px">State</td><td id="hec-state">unknown</td></tr>
                <tr><td>Token detected in environment</td><td id="hec-token">—</td></tr>
                <tr><td>Last success</td><td id="hec-last-success">—</td></tr>
                <tr><td>Last success latency</td><td id="hec-last-latency">—</td></tr>
                <tr><td>Last error</td><td id="hec-last-error">—</td></tr>
                <tr><td>Last error time</td><td id="hec-last-error-at">—</td></tr>
              </tbody>
            </table>
          </div>

          </div>
        </section>
      </div>
    `;

    const verifyToggle = document.getElementById('hec-verify-tls');
    if (verifyToggle) {
      verifyToggle.addEventListener('change', () => {
        const warn = document.getElementById('hec-tls-warn');
        if (warn) warn.style.display = verifyToggle.checked ? 'none' : 'block';
      });
    }

    await Settings._refreshRuntime();
    Settings.pollInterval = setInterval(Settings._refreshRuntime, 2500);
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
    try { Settings.hecConfig = await App.api('GET', '/api/hec/config'); }
    catch (_) { Settings.hecConfig = {}; }
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
      const s = await App.api('GET', '/api/hec/stats');
      if (s) Settings._paintHECStats(s);
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
    const set = (id, v) => { const el = document.getElementById(id); if (el) el.textContent = v; };
    set('hec-sent', s.events_sent || 0);
    set('hec-failed', s.events_failed || 0);
    set('hec-dropped', s.events_dropped || 0);
    set('hec-queue', `${s.queue_depth || 0} / ${s.queue_capacity || 0}`);
    let state = 'disabled';
    if (s.enabled && s.running) state = 'running';
    else if (s.enabled && !s.running) state = 'configured (not running)';
    set('hec-state', state);
    set('hec-token', s.token_present ? 'yes' : 'no');
    set('hec-last-success', s.last_success_at || '—');
    set('hec-last-latency', s.last_latency_ms != null ? `${s.last_latency_ms} ms` : '—');
    set('hec-last-error', s.last_error || '—');
    set('hec-last-error-at', s.last_error_at || '—');
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

  _hecTokenBadge(hec) {
    const src = (hec && hec.token_source)
      || (hec && (hec.token_present || hec.token_env_set) ? 'env' : 'none');
    if (src === 'env') {
      return `<span class="hec-badge hec-badge-ok">Token active (environment)</span>`;
    }
    if (src === 'keychain') {
      return `<span class="hec-badge hec-badge-ok">Token active (OS keychain)</span>`;
    }
    return `<span class="hec-badge hec-badge-warn">No HEC token configured</span>`;
  },

  toggleHECTokenVisibility() {
    const input = document.getElementById('hec-token-input');
    const btn = document.getElementById('hec-token-toggle');
    if (!input || !btn) return;
    if (input.type === 'password') {
      input.type = 'text';
      btn.textContent = 'Hide';
    } else {
      input.type = 'password';
      btn.textContent = 'Show';
    }
  },

  async saveHECKey() {
    const input = document.getElementById('hec-token-input');
    if (!input) return;
    const raw = input.value || '';
    const token = raw.trim();
    if (!token) {
      Settings._renderResult('hec-key-result', false, 'HEC token is required.');
      App.toast('HEC token is required.', 'err');
      return;
    }
    // Client-side shape check mirrors server validation (UUID).
    if (!/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(token)) {
      const msg = 'Token does not look like a Splunk HEC token (expected UUID: 8-4-4-4-12 hex).';
      Settings._renderResult('hec-key-result', false, msg);
      App.toast(msg, 'err');
      return;
    }

    try {
      const res = await fetch('/api/hec/key', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token }),
      });
      // Best-effort wipe of the DOM value regardless of outcome.
      input.value = '';
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        const detail = Settings._describeError(body, res.status);
        Settings._renderResult('hec-key-result', false, `Save failed: ${detail}`);
        App.toast(`HEC token save failed: ${detail}`, 'err');
        return;
      }
      const info = await res.json();
      const msg = info.source === 'keychain'
        ? 'Token stored in OS keychain. Forwarder reconfigured.'
        : 'Token saved. Forwarder reconfigured.';
      Settings._renderResult('hec-key-result', true, msg);
      App.toast('HEC token saved', 'ok');
      await Settings._reloadHECKeyUi();
    } catch (_) {
      input.value = '';
      Settings._renderResult('hec-key-result', false, 'Save failed (network error).');
      App.toast('Save failed (network error)', 'err');
    }
  },

  async clearHECKey() {
    if (!window.confirm('Remove the stored Splunk HEC token from the OS keychain?')) {
      return;
    }
    try {
      const res = await fetch('/api/hec/key', { method: 'DELETE' });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        const detail = Settings._describeError(body, res.status);
        Settings._renderResult('hec-key-result', false, `Clear failed: ${detail}`);
        App.toast(`Clear failed: ${detail}`, 'err');
        return;
      }
      const info = await res.json();
      const msg = info.removed ? 'Stored token cleared.' : 'No token was stored.';
      Settings._renderResult('hec-key-result', true, msg);
      App.toast(msg, 'ok');
      await Settings._reloadHECKeyUi();
    } catch (_) {
      Settings._renderResult('hec-key-result', false, 'Clear failed (network error).');
      App.toast('Clear failed (network error)', 'err');
    }
  },

  async _reloadHECKeyUi() {
    try {
      Settings.hecConfig = await App.api('GET', '/api/hec/config');
    } catch (_) { /* keep stale config */ }
    const hec = Settings.hecConfig || {};

    const badgeSlot = document.getElementById('hec-token-badge-slot');
    if (badgeSlot) badgeSlot.innerHTML = Settings._hecTokenBadge(hec);

    const form = document.getElementById('hec-key-form');
    const envNote = document.getElementById('hec-key-env-note');
    const clearBtn = document.getElementById('hec-key-clear-btn');
    const label = document.querySelector('label[for="hec-token-input"]');

    if (form) form.style.display = hec.token_source === 'env' ? 'none' : 'block';
    if (envNote) envNote.style.display = hec.token_source === 'env' ? 'block' : 'none';
    if (clearBtn) clearBtn.style.display = hec.token_source === 'keychain' ? 'inline-flex' : 'none';
    if (label) {
      label.textContent = hec.token_source === 'keychain' ? 'Replace stored token' : 'Set HEC token';
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

  async saveHEC() {
    const urlEl = document.getElementById('hec-url');
    const url = (urlEl.value || '').trim();
    if (url && !/^https:\/\//i.test(url)) {
      Settings._showHECResult(false, 'URL must start with https://');
      App.toast('URL must start with https://', 'err');
      return;
    }

    const patch = {
      enabled: document.getElementById('hec-enabled').checked,
      url: url,
      verify_tls: document.getElementById('hec-verify-tls').checked,
      default_index: document.getElementById('hec-index').value.trim() || 'main',
      default_source: document.getElementById('hec-source').value.trim() || 'threatgen',
      default_host: document.getElementById('hec-host').value.trim() || 'threatgen',
      sourcetype_map: Settings._collectMap(),
      batch_size: parseInt(document.getElementById('hec-batch-size').value, 10) || 100,
      flush_interval_s: parseFloat(document.getElementById('hec-flush').value) || 2.0,
      queue_max: parseInt(document.getElementById('hec-queue-max').value, 10) || 10000,
      request_timeout_s: parseFloat(document.getElementById('hec-timeout').value) || 10.0,
      max_retries: parseInt(document.getElementById('hec-retries').value, 10) || 0,
    };

    try {
      const res = await fetch('/api/hec/config', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(patch),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        const detail = Settings._describeError(body, res.status);
        Settings._showHECResult(false, `Save failed: ${detail}`);
        App.toast(`HEC save failed: ${detail}`, 'err');
        return;
      }
      Settings.hecConfig = await res.json();
      Settings._showHECResult(true, 'HEC configuration saved and forwarder reloaded.');
      App.toast('HEC settings saved', 'ok');
      await Settings._refreshRuntime();
    } catch (e) {
      Settings._showHECResult(false, 'Save failed (network error)');
      App.toast('Save failed (network error)', 'err');
    }
  },

  async testHEC() {
    const btn = document.getElementById('hec-btn-test');
    if (btn) btn.disabled = true;
    Settings._showHECResult(null, 'Sending test event...');
    try {
      const res = await App.api('POST', '/api/hec/test');
      if (res && res.ok) {
        Settings._showHECResult(true, `Success: HTTP ${res.status_code || ''} in ${res.latency_ms} ms`);
      } else {
        Settings._showHECResult(false, `Failed: ${(res && res.error) || 'unknown error'}`);
      }
    } catch (_) {
      Settings._showHECResult(false, 'Test failed (network error)');
    } finally {
      if (btn) btn.disabled = false;
      await Settings._refreshRuntime();
    }
  },

  _collectMap() {
    const map = {};
    document.querySelectorAll('.hec-st-map').forEach(el => {
      const k = el.dataset.st;
      const v = (el.value || '').trim();
      if (k && v) map[k] = v;
    });
    return map;
  },

  _showLLMResult(ok, message) { Settings._renderResult('llm-save-result', ok, message); },
  _showHECResult(ok, message) { Settings._renderResult('hec-test-result', ok, message); },

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
};
