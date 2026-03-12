const App = {
  currentPage: 'dashboard',
  statusInterval: null,

  init() {
    document.querySelectorAll('.nav-link').forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        const page = link.dataset.page;
        App.navigate(page);
      });
    });
    App.navigate('dashboard');
    App.startStatusPolling();
  },

  navigate(page) {
    App.currentPage = page;
    document.querySelectorAll('.nav-link').forEach(l => l.classList.remove('active'));
    const active = document.querySelector(`.nav-link[data-page="${page}"]`);
    if (active) active.classList.add('active');

    const content = document.getElementById('main-content');

    switch (page) {
      case 'dashboard': Dashboard.render(content); break;
      case 'logs': LogViewer.render(content); break;
      case 'config': ConfigEditor.render(content); break;
      case 'topology': TopologyEditor.render(content); break;
      case 'campaigns': Campaigns.render(content); break;
    }
  },

  startStatusPolling() {
    const poll = async () => {
      try {
        const res = await fetch('/api/generator/status');
        const data = await res.json();
        App.updateStatusIndicator(data.state);
      } catch (_) {}
    };
    poll();
    App.statusInterval = setInterval(poll, 3000);
  },

  updateStatusIndicator(state) {
    const el = document.getElementById('engine-status-indicator');
    if (!el) return;
    const dot = el.querySelector('.status-dot');
    const text = el.querySelector('.status-text');
    dot.className = 'status-dot ' + state;
    text.textContent = state.charAt(0).toUpperCase() + state.slice(1);
  },

  async api(method, path, body) {
    const opts = { method, headers: { 'Content-Type': 'application/json' } };
    if (body) opts.body = JSON.stringify(body);
    const res = await fetch(path, opts);
    return res.json();
  }
};

document.addEventListener('DOMContentLoaded', () => App.init());
