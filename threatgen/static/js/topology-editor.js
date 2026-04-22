const TopologyEditor = {
  topo: null,

  async render(container) {
    try {
      TopologyEditor.topo = await App.api('GET', '/api/topology');
    } catch (_) {
      TopologyEditor.topo = {};
    }
    const t = TopologyEditor.topo;

    container.innerHTML = `
      <div class="page active">
        <div class="page-header">
          <h1 class="page-title">Topology</h1>
          <div class="btn-group">
            <button class="btn btn-secondary" onclick="TopologyEditor.exportToSplunk()">Export to Splunk</button>
            <button class="btn btn-primary" onclick="TopologyEditor.save()">Save Changes</button>
          </div>
        </div>

        <div class="grid-2">
          <div class="card">
            <div class="card-title">Domain Settings</div>
            <div class="form-group">
              <label class="form-label">Domain Name</label>
              <input type="text" class="form-input" id="topo-domain" value="${t.domain_name || ''}">
            </div>
            <div class="form-group">
              <label class="form-label">DNS FQDN</label>
              <input type="text" class="form-input" id="topo-fqdn" value="${t.dns_fqdn || ''}">
            </div>
            <div class="form-group">
              <label class="form-label">DNS Server IP</label>
              <input type="text" class="form-input" id="topo-dns-ip" value="${t.dns_server_ip || ''}">
            </div>
            <div class="form-group">
              <label class="form-label">NAT Pool</label>
              <input type="text" class="form-input" id="topo-nat" value="${t.nat_pool || ''}">
            </div>
          </div>
          <div class="card">
            <div class="card-title">Network Summary</div>
            <div style="font-size:13px;color:var(--text-secondary);line-height:2">
              <div>Windows Hosts: <strong style="color:var(--text-primary)">${(t.windows_hosts || []).length}</strong></div>
              <div>Linux Hosts: <strong style="color:var(--text-primary)">${(t.linux_hosts || []).length}</strong></div>
              <div>Domain Controllers: <strong style="color:var(--text-primary)">${(t.domain_controllers || []).length}</strong></div>
              <div>File Servers: <strong style="color:var(--text-primary)">${(t.file_servers || []).length}</strong></div>
              <div>DMZ Servers: <strong style="color:var(--text-primary)">${(t.dmz_servers || []).length}</strong></div>
              <div>Firewalls: <strong style="color:var(--text-primary)">${(t.firewalls || []).length}</strong></div>
              <div>Users: <strong style="color:var(--text-primary)">${(t.users || []).length}</strong></div>
            </div>
          </div>
        </div>

        ${TopologyEditor.renderHostTable('Windows Hosts', 'windows_hosts', t.windows_hosts || [], ['hostname', 'ip'])}
        ${TopologyEditor.renderHostTable('Linux Hosts', 'linux_hosts', t.linux_hosts || [], ['hostname', 'ip'])}
        ${TopologyEditor.renderHostTable('Domain Controllers', 'domain_controllers', t.domain_controllers || [], ['hostname', 'ip', 'os_version'])}
        ${TopologyEditor.renderHostTable('File Servers', 'file_servers', t.file_servers || [], ['hostname', 'ip', 'os_version'])}
        ${TopologyEditor.renderDMZTable(t.dmz_servers || [])}
        ${TopologyEditor.renderFirewallTable(t.firewalls || [])}
        ${TopologyEditor.renderUserTable(t.users || [])}
      </div>
    `;
  },

  renderHostTable(title, key, hosts, fields) {
    const headers = fields.map(f => `<th>${f}</th>`).join('');
    const rows = hosts.map((h, i) =>
      `<tr>${fields.map(f => `<td><input data-key="${key}" data-idx="${i}" data-field="${f}" value="${h[f] || ''}"></td>`).join('')}
       <td><button class="btn btn-danger" style="padding:4px 8px;font-size:11px" onclick="TopologyEditor.removeRow('${key}',${i})">X</button></td></tr>`
    ).join('');
    return `
      <div class="card">
        <div class="card-title" style="display:flex;justify-content:space-between;align-items:center">
          ${title}
          <button class="btn" style="padding:4px 10px;font-size:11px" onclick="TopologyEditor.addRow('${key}',${JSON.stringify(fields).replace(/"/g, '&quot;')})">+ Add</button>
        </div>
        <table class="data-table"><thead><tr>${headers}<th style="width:40px"></th></tr></thead><tbody>${rows}</tbody></table>
      </div>`;
  },

  renderDMZTable(servers) {
    const rows = servers.map((s, i) => `
      <tr>
        <td><input data-key="dmz_servers" data-idx="${i}" data-field="hostname" value="${s.hostname}"></td>
        <td><input data-key="dmz_servers" data-idx="${i}" data-field="ip" value="${s.ip}"></td>
        <td><input data-key="dmz_servers" data-idx="${i}" data-field="role" value="${s.role}"></td>
        <td><input data-key="dmz_servers" data-idx="${i}" data-field="ports" value="${(s.ports || []).join(',')}"></td>
        <td><button class="btn btn-danger" style="padding:4px 8px;font-size:11px" onclick="TopologyEditor.removeRow('dmz_servers',${i})">X</button></td>
      </tr>
    `).join('');
    return `
      <div class="card">
        <div class="card-title" style="display:flex;justify-content:space-between;align-items:center">
          DMZ Servers
          <button class="btn" style="padding:4px 10px;font-size:11px" onclick="TopologyEditor.addDMZ()">+ Add</button>
        </div>
        <table class="data-table"><thead><tr><th>Hostname</th><th>IP</th><th>Role</th><th>Ports</th><th style="width:40px"></th></tr></thead><tbody>${rows}</tbody></table>
      </div>`;
  },

  renderFirewallTable(firewalls) {
    const rows = firewalls.map((f, i) => `
      <tr>
        <td><input data-key="firewalls" data-idx="${i}" data-field="hostname" value="${f.hostname}"></td>
        <td><input data-key="firewalls" data-idx="${i}" data-field="inside_ip" value="${f.inside_ip}"></td>
        <td><input data-key="firewalls" data-idx="${i}" data-field="outside_ip" value="${f.outside_ip}"></td>
        <td><input data-key="firewalls" data-idx="${i}" data-field="dmz_ip" value="${f.dmz_ip}"></td>
        <td><button class="btn btn-danger" style="padding:4px 8px;font-size:11px" onclick="TopologyEditor.removeRow('firewalls',${i})">X</button></td>
      </tr>
    `).join('');
    return `
      <div class="card">
        <div class="card-title" style="display:flex;justify-content:space-between;align-items:center">
          Firewalls
          <button class="btn" style="padding:4px 10px;font-size:11px" onclick="TopologyEditor.addFirewall()">+ Add</button>
        </div>
        <table class="data-table"><thead><tr><th>Hostname</th><th>Inside IP</th><th>Outside IP</th><th>DMZ IP</th><th style="width:40px"></th></tr></thead><tbody>${rows}</tbody></table>
      </div>`;
  },

  renderUserTable(users) {
    const rows = users.map((u, i) => `
      <tr>
        <td><input data-key="users" data-idx="${i}" data-field="username" value="${u.username}"></td>
        <td>
          <label class="toggle">
            <input type="checkbox" data-key="users" data-idx="${i}" data-field="is_admin" ${u.is_admin ? 'checked' : ''}>
            <span class="toggle-slider"></span>
          </label>
        </td>
        <td><button class="btn btn-danger" style="padding:4px 8px;font-size:11px" onclick="TopologyEditor.removeRow('users',${i})">X</button></td>
      </tr>
    `).join('');
    return `
      <div class="card">
        <div class="card-title" style="display:flex;justify-content:space-between;align-items:center">
          Users
          <button class="btn" style="padding:4px 10px;font-size:11px" onclick="TopologyEditor.addUser()">+ Add</button>
        </div>
        <table class="data-table"><thead><tr><th>Username</th><th>Admin</th><th style="width:40px"></th></tr></thead><tbody>${rows}</tbody></table>
      </div>`;
  },

  collectTopology() {
    const t = JSON.parse(JSON.stringify(TopologyEditor.topo));
    t.domain_name = document.getElementById('topo-domain').value;
    t.dns_fqdn = document.getElementById('topo-fqdn').value;
    t.dns_server_ip = document.getElementById('topo-dns-ip').value;
    t.nat_pool = document.getElementById('topo-nat').value;

    document.querySelectorAll('input[data-key]').forEach(input => {
      const key = input.dataset.key;
      const idx = parseInt(input.dataset.idx);
      const field = input.dataset.field;
      if (!t[key] || !t[key][idx]) return;

      if (input.type === 'checkbox') {
        t[key][idx][field] = input.checked;
      } else if (field === 'ports') {
        t[key][idx][field] = input.value.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p));
      } else {
        t[key][idx][field] = input.value;
      }
    });

    return t;
  },

  async save() {
    const topo = TopologyEditor.collectTopology();
    const btn = document.querySelector('button[onclick="TopologyEditor.save()"]');
    if (btn) btn.disabled = true;
    try {
      const res = await fetch('/api/topology', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ topology: topo }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        const msg = (body && body.detail) ? body.detail : `HTTP ${res.status}`;
        App.toast(`Save failed: ${msg}`, 'err');
        return;
      }
      TopologyEditor.topo = topo;
      App.toast('Topology saved', 'ok');
    } catch (_) {
      App.toast('Save failed (network error)', 'err');
    } finally {
      if (btn) btn.disabled = false;
    }
  },

  removeRow(key, idx) {
    if (TopologyEditor.topo[key]) {
      TopologyEditor.topo[key].splice(idx, 1);
      TopologyEditor.render(document.getElementById('main-content'));
    }
  },

  addRow(key, fields) {
    if (!TopologyEditor.topo[key]) TopologyEditor.topo[key] = [];
    const obj = {};
    fields.forEach(f => { obj[f] = ''; });
    TopologyEditor.topo[key].push(obj);
    TopologyEditor.render(document.getElementById('main-content'));
  },

  addDMZ() {
    if (!TopologyEditor.topo.dmz_servers) TopologyEditor.topo.dmz_servers = [];
    TopologyEditor.topo.dmz_servers.push({ hostname: '', ip: '', role: '', ports: [] });
    TopologyEditor.render(document.getElementById('main-content'));
  },

  addFirewall() {
    if (!TopologyEditor.topo.firewalls) TopologyEditor.topo.firewalls = [];
    TopologyEditor.topo.firewalls.push({ hostname: '', inside_ip: '', outside_ip: '', dmz_ip: '' });
    TopologyEditor.render(document.getElementById('main-content'));
  },

  addUser() {
    if (!TopologyEditor.topo.users) TopologyEditor.topo.users = [];
    TopologyEditor.topo.users.push({ username: '', is_admin: false });
    TopologyEditor.render(document.getElementById('main-content'));
  },

  exportToSplunk() {
    const topo = TopologyEditor.collectTopology();
    const assetSpl = TopologyEditor.buildAssetSPL(topo);
    const identitySpl = TopologyEditor.buildIdentitySPL(topo);
    TopologyEditor.showSplunkModal(assetSpl, identitySpl);
  },

  // Strip characters that would break our SPL field/record separators.
  // Keeps alnum, dot, dash, underscore, colon, slash, space, and @ for emails.
  _splSafe(value) {
    const v = value == null ? '' : String(value);
    return v.replace(/[|;"\r\n\t]/g, '').trim();
  },

  _assetRecordsFromTopology(t) {
    const records = [];
    const dnsSuffix = t.dns_fqdn ? String(t.dns_fqdn).toLowerCase() : '';
    const fqdn = (host) => {
      const h = String(host || '').toLowerCase();
      if (!h) return '';
      if (!dnsSuffix || h.indexOf('.') !== -1) return h;
      return h + '.' + dnsSuffix;
    };

    const push = (ip, host, category, priority, bunit, extra) => {
      if (!ip && !host) return;
      records.push({
        ip: TopologyEditor._splSafe(ip),
        nt_host: TopologyEditor._splSafe(host),
        dns: TopologyEditor._splSafe(fqdn(host)),
        category: TopologyEditor._splSafe(category),
        priority: TopologyEditor._splSafe(priority),
        bunit: TopologyEditor._splSafe(bunit || ''),
        description: TopologyEditor._splSafe(extra || ''),
      });
    };

    (t.windows_hosts || []).forEach(h => push(h.ip, h.hostname, 'workstation|windows', 'low', 'corp', ''));
    (t.linux_hosts || []).forEach(h => push(h.ip, h.hostname, 'server|linux', 'medium', 'corp', ''));
    (t.domain_controllers || []).forEach(h => push(h.ip, h.hostname, 'server|domain_controller', 'critical', 'corp', h.os_version || ''));
    (t.file_servers || []).forEach(h => push(h.ip, h.hostname, 'server|file_server', 'high', 'corp', h.os_version || ''));
    (t.dmz_servers || []).forEach(h => {
      const role = h.role ? `dmz|${h.role}` : 'dmz';
      const ports = Array.isArray(h.ports) ? h.ports.join('/') : '';
      push(h.ip, h.hostname, role, 'high', 'dmz', ports ? `ports=${ports}` : '');
    });
    (t.firewalls || []).forEach(h => {
      // Firewalls have multiple IPs; emit one asset record per interface IP.
      if (h.inside_ip) push(h.inside_ip, h.hostname, 'network|firewall|inside', 'critical', 'network', 'interface=inside');
      if (h.outside_ip) push(h.outside_ip, h.hostname, 'network|firewall|outside', 'critical', 'network', 'interface=outside');
      if (h.dmz_ip) push(h.dmz_ip, h.hostname, 'network|firewall|dmz', 'critical', 'network', 'interface=dmz');
    });

    // Add the DNS server itself as an asset if present.
    if (t.dns_server_ip) {
      push(t.dns_server_ip, 'dns-' + (t.domain_name || 'corp').toLowerCase(), 'server|dns', 'high', 'corp', 'role=dns');
    }

    return records;
  },

  _identityRecordsFromTopology(t) {
    const domain = t.domain_name ? String(t.domain_name).toUpperCase() : '';
    return (t.users || [])
      .filter(u => u && u.username)
      .map(u => {
        const uname = TopologyEditor._splSafe(u.username);
        const isAdmin = !!u.is_admin;
        return {
          identity: uname,
          nick: uname,
          prefix: domain ? TopologyEditor._splSafe(domain + '\\' + uname) : uname,
          category: isAdmin ? 'privileged|employee' : 'employee',
          priority: isAdmin ? 'high' : 'low',
          watchlist: isAdmin ? 'true' : 'false',
          bunit: 'corp',
        };
      });
  },

  buildAssetSPL(t) {
    const records = TopologyEditor._assetRecordsFromTopology(t);
    if (records.length === 0) {
      return '``` No assets defined in topology. ```\n| makeresults | head 0';
    }

    // Build a single-string records payload separated by ';' with '|' field separators.
    // Fields: ip|nt_host|dns|category|priority|bunit|description
    const payload = records
      .map(r => [r.ip, r.nt_host, r.dns, r.category, r.priority, r.bunit, r.description].join('|'))
      .join(';');

    // Splunk ES asset_lookup_by_str.csv columns:
    // key,ip,mac,nt_host,dns,owner,priority,lat,long,city,country,bunit,category,pci_domain,
    //   is_expected,should_timesync,should_update,requires_av
    return [
      '``` ThreatGen -> Splunk ES Asset Lookup (asset_lookup_by_str.csv) ```',
      '``` Paste into a Splunk search, run, then verify with: | inputlookup asset_lookup_by_str.csv ```',
      '| makeresults',
      '| eval records="' + payload + '"',
      '| eval records=split(records,";")',
      '| mvexpand records',
      '| eval fields=split(records,"|")',
      '| eval ip=mvindex(fields,0)',
      '| eval nt_host=mvindex(fields,1)',
      '| eval dns=mvindex(fields,2)',
      '| eval category=mvindex(fields,3)',
      '| eval prio_src=mvindex(fields,4)',
      '| eval bunit=mvindex(fields,5)',
      '| eval description=mvindex(fields,6)',
      '| eval key=coalesce(nt_host,ip)',
      '| eval priority=case(prio_src="critical","critical",prio_src="high","high",prio_src="medium","medium",1=1,"low")',
      '| eval mac="", owner="", lat="", long="", city="", country="", pci_domain=""',
      '| eval is_expected="true", should_timesync="true", should_update="true", requires_av="true"',
      '| table key,ip,mac,nt_host,dns,owner,priority,lat,long,city,country,bunit,category,pci_domain,is_expected,should_timesync,should_update,requires_av,description',
      '| outputlookup asset_lookup_by_str.csv',
    ].join('\n');
  },

  buildIdentitySPL(t) {
    const records = TopologyEditor._identityRecordsFromTopology(t);
    if (records.length === 0) {
      return '``` No users defined in topology. ```\n| makeresults | head 0';
    }

    // Fields: identity|nick|prefix|category|priority|watchlist|bunit
    const payload = records
      .map(r => [r.identity, r.nick, r.prefix, r.category, r.priority, r.watchlist, r.bunit].join('|'))
      .join(';');

    // Splunk ES identity_lookup_expanded.csv columns:
    // identity,prefix,nick,first,last,suffix,email,phone,phone2,managedBy,priority,bunit,
    //   category,watchlist,startDate,endDate
    return [
      '``` ThreatGen -> Splunk ES Identity Lookup (identity_lookup_expanded.csv) ```',
      '``` Paste into a Splunk search, run, then verify with: | inputlookup identity_lookup_expanded.csv ```',
      '| makeresults',
      '| eval records="' + payload + '"',
      '| eval records=split(records,";")',
      '| mvexpand records',
      '| eval fields=split(records,"|")',
      '| eval identity=mvindex(fields,0)',
      '| eval nick=mvindex(fields,1)',
      '| eval prefix=mvindex(fields,2)',
      '| eval category=mvindex(fields,3)',
      '| eval priority=mvindex(fields,4)',
      '| eval watchlist=mvindex(fields,5)',
      '| eval bunit=mvindex(fields,6)',
      '| eval first="", last="", suffix="", email="", phone="", phone2="", managedBy="", startDate="", endDate=""',
      '| table identity,prefix,nick,first,last,suffix,email,phone,phone2,managedBy,priority,bunit,category,watchlist,startDate,endDate',
      '| outputlookup identity_lookup_expanded.csv',
    ].join('\n');
  },

  showSplunkModal(assetSpl, identitySpl) {
    // Build a dedicated modal so multiple SPL blocks can be shown with copy buttons.
    // DOM is built with createElement / textContent to prevent XSS from topology values.
    let overlay = document.getElementById('splunk-export-overlay');
    if (overlay) overlay.remove();

    overlay = document.createElement('div');
    overlay.className = 'modal-overlay';
    overlay.id = 'splunk-export-overlay';
    overlay.addEventListener('click', (e) => { if (e.target === overlay) TopologyEditor._closeSplunkModal(); });

    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.setAttribute('role', 'dialog');
    modal.setAttribute('aria-modal', 'true');

    // Header
    const header = document.createElement('div');
    header.className = 'modal-header';
    const title = document.createElement('h2');
    title.className = 'modal-title';
    title.textContent = 'Export Topology to Splunk';
    const closeBtn = document.createElement('button');
    closeBtn.className = 'modal-close';
    closeBtn.setAttribute('aria-label', 'Close');
    closeBtn.textContent = '\u00D7';
    closeBtn.addEventListener('click', TopologyEditor._closeSplunkModal);
    header.appendChild(title);
    header.appendChild(closeBtn);

    // Summary
    const summary = document.createElement('p');
    summary.className = 'hunt-summary';
    summary.textContent =
      'Run the SPL below in Splunk to populate the Enterprise Security Asset and Identity ' +
      'framework lookups used by AIRI / exposure analytics. Verify with | inputlookup ' +
      'asset_lookup_by_str.csv or | inputlookup identity_lookup_expanded.csv after running.';

    // Body
    const body = document.createElement('div');
    body.className = 'modal-body';

    body.appendChild(TopologyEditor._splBlock('Assets \u2014 asset_lookup_by_str.csv', assetSpl));
    body.appendChild(TopologyEditor._splBlock('Identities \u2014 identity_lookup_expanded.csv', identitySpl));

    modal.appendChild(header);
    modal.appendChild(summary);
    modal.appendChild(body);
    overlay.appendChild(modal);
    document.body.appendChild(overlay);

    // Open on next frame so the CSS transition (if any) can engage.
    requestAnimationFrame(() => {
      overlay.classList.add('open');
      document.body.classList.add('modal-open');
    });

    TopologyEditor._splKeyHandler = (e) => {
      if (e.key === 'Escape') TopologyEditor._closeSplunkModal();
    };
    document.addEventListener('keydown', TopologyEditor._splKeyHandler);
  },

  _splBlock(heading, spl) {
    const wrap = document.createElement('div');
    wrap.style.marginBottom = '18px';

    const h = document.createElement('div');
    h.className = 'hunt-step-title';
    h.textContent = heading;
    wrap.appendChild(h);

    const splWrap = document.createElement('div');
    splWrap.className = 'hunt-spl';

    const copyBtn = document.createElement('button');
    copyBtn.className = 'hunt-spl-copy';
    copyBtn.type = 'button';
    copyBtn.textContent = 'Copy SPL';
    copyBtn.addEventListener('click', () => TopologyEditor._copyText(spl, copyBtn));

    const pre = document.createElement('pre');
    pre.className = 'hunt-spl-code';
    const code = document.createElement('code');
    code.textContent = spl;
    pre.appendChild(code);

    splWrap.appendChild(copyBtn);
    splWrap.appendChild(pre);
    wrap.appendChild(splWrap);
    return wrap;
  },

  _copyText(text, btn) {
    const done = () => {
      const prev = btn.textContent;
      btn.textContent = 'Copied';
      btn.classList.add('copied');
      setTimeout(() => {
        btn.textContent = prev;
        btn.classList.remove('copied');
      }, 1500);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done).catch(() => TopologyEditor._fallbackCopy(text, done));
    } else {
      TopologyEditor._fallbackCopy(text, done);
    }
  },

  _fallbackCopy(text, done) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'absolute';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); done(); } catch (_) { /* noop */ }
    document.body.removeChild(ta);
  },

  _closeSplunkModal() {
    const overlay = document.getElementById('splunk-export-overlay');
    if (overlay) {
      overlay.classList.remove('open');
      document.body.classList.remove('modal-open');
      overlay.remove();
    }
    if (TopologyEditor._splKeyHandler) {
      document.removeEventListener('keydown', TopologyEditor._splKeyHandler);
      TopologyEditor._splKeyHandler = null;
    }
  },
};
