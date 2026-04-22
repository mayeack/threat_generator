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
    const prev = App.currentPage;
    if (prev !== page) {
      try {
        const prevModule = App._pageModule(prev);
        if (prevModule && typeof prevModule.cleanup === 'function') prevModule.cleanup();
      } catch (_) {}
    }
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
      case 'settings': Settings.render(content); break;
    }
  },

  _pageModule(page) {
    switch (page) {
      case 'dashboard': return typeof Dashboard !== 'undefined' ? Dashboard : null;
      case 'logs': return typeof LogViewer !== 'undefined' ? LogViewer : null;
      case 'config': return typeof ConfigEditor !== 'undefined' ? ConfigEditor : null;
      case 'topology': return typeof TopologyEditor !== 'undefined' ? TopologyEditor : null;
      case 'campaigns': return typeof Campaigns !== 'undefined' ? Campaigns : null;
      case 'settings': return typeof Settings !== 'undefined' ? Settings : null;
      default: return null;
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
  },

  /**
   * Show a transient toast notification in the top-right corner.
   * Multiple toasts stack vertically and auto-dismiss.
   *
   * Security: `message` is rendered via textContent (never innerHTML) so
   * server-returned error strings cannot inject markup into the page.
   *
   * @param {string} message - human-readable message to display
   * @param {'ok'|'err'|'info'} [type='ok'] - visual variant
   * @param {number} [durationMs=3200] - how long before auto-dismiss
   */
  toast(message, type = 'ok', durationMs = 3200) {
    let container = document.getElementById('toast-container');
    if (!container) {
      container = document.createElement('div');
      container.id = 'toast-container';
      container.setAttribute('role', 'status');
      container.setAttribute('aria-live', 'polite');
      document.body.appendChild(container);
    }

    const el = document.createElement('div');
    el.className = `toast toast-${type === 'err' ? 'err' : type === 'info' ? 'info' : 'ok'}`;

    const icon = document.createElement('span');
    icon.className = 'toast-icon';
    icon.setAttribute('aria-hidden', 'true');
    icon.textContent = type === 'err' ? '!' : type === 'info' ? 'i' : '\u2713';

    const text = document.createElement('span');
    text.className = 'toast-text';
    text.textContent = String(message == null ? '' : message);

    el.appendChild(icon);
    el.appendChild(text);
    container.appendChild(el);

    // Force a reflow so the enter animation applies reliably on
    // back-to-back toasts.
    void el.offsetWidth;
    el.classList.add('toast-enter');

    const dismiss = () => {
      if (!el.isConnected) return;
      el.classList.remove('toast-enter');
      el.classList.add('toast-exit');
      setTimeout(() => { if (el.isConnected) el.remove(); }, 220);
    };

    const timer = setTimeout(dismiss, Math.max(1200, durationMs));
    el.addEventListener('click', () => { clearTimeout(timer); dismiss(); });
  }
};

document.addEventListener('DOMContentLoaded', () => App.init());
