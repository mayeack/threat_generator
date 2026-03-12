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
    await App.api('PUT', '/api/topology', { topology: topo });
    TopologyEditor.topo = topo;
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
};
