// Reusable modal that renders HuntGuides[campaignId] with a three-way
// difficulty selector (easy / medium / hard).
//
// Content is user-controlled (no HTML from the server) - we render it into
// text nodes / safe attributes only (no innerHTML of untrusted strings),
// which avoids DOM-based XSS. Campaign ids and names are server-provided
// but we also set them via textContent.

(function () {
  'use strict';

  const DIFFICULTIES = [
    { id: 'easy', label: 'Easy', hint: 'Step-by-step with SPL' },
    { id: 'medium', label: 'Medium', hint: 'Step-by-step without SPL' },
    { id: 'hard', label: 'Hard', hint: 'High-level hypothesis' },
  ];

  let overlayEl = null;
  let modalEl = null;
  let titleEl = null;
  let summaryEl = null;
  let tabsEl = null;
  let bodyEl = null;
  let currentGuide = null;
  let currentDifficulty = 'easy';

  function el(tag, attrs, children) {
    const node = document.createElement(tag);
    if (attrs) {
      Object.keys(attrs).forEach(function (k) {
        if (k === 'class') node.className = attrs[k];
        else if (k === 'text') node.textContent = attrs[k];
        else if (k === 'onclick') node.addEventListener('click', attrs[k]);
        else node.setAttribute(k, attrs[k]);
      });
    }
    if (children) {
      children.forEach(function (c) {
        if (c == null) return;
        node.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
      });
    }
    return node;
  }

  function ensureOverlay() {
    if (overlayEl) return;

    overlayEl = el('div', { class: 'modal-overlay', id: 'hunt-modal-overlay' });
    overlayEl.addEventListener('click', function (e) {
      if (e.target === overlayEl) close();
    });

    modalEl = el('div', { class: 'modal modal-hunt', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'hunt-modal-title' });

    const closeBtn = el('button', { class: 'modal-close', 'aria-label': 'Close', text: '\u00d7', onclick: close });

    titleEl = el('h2', { class: 'modal-title', id: 'hunt-modal-title' });
    summaryEl = el('p', { class: 'hunt-summary' });

    const header = el('div', { class: 'modal-header' }, [titleEl, closeBtn]);

    tabsEl = el('div', { class: 'difficulty-tabs', role: 'tablist' });
    DIFFICULTIES.forEach(function (d) {
      const tab = el('button', {
        class: 'difficulty-tab',
        'data-difficulty': d.id,
        role: 'tab',
        title: d.hint,
        onclick: function () { setDifficulty(d.id); },
      }, [
        el('span', { class: 'difficulty-tab-label', text: d.label }),
        el('span', { class: 'difficulty-tab-hint', text: d.hint }),
      ]);
      tabsEl.appendChild(tab);
    });

    bodyEl = el('div', { class: 'modal-body hunt-body' });

    modalEl.appendChild(header);
    modalEl.appendChild(summaryEl);
    modalEl.appendChild(tabsEl);
    modalEl.appendChild(bodyEl);

    overlayEl.appendChild(modalEl);
    document.body.appendChild(overlayEl);

    document.addEventListener('keydown', function (e) {
      if (overlayEl.classList.contains('open') && e.key === 'Escape') close();
    });
  }

  function setDifficulty(d) {
    currentDifficulty = d;
    Array.prototype.forEach.call(tabsEl.querySelectorAll('.difficulty-tab'), function (t) {
      if (t.getAttribute('data-difficulty') === d) t.classList.add('active');
      else t.classList.remove('active');
    });
    renderBody();
  }

  function renderBody() {
    bodyEl.textContent = '';
    if (!currentGuide) {
      bodyEl.appendChild(el('div', { class: 'hunt-empty', text: 'No guidance available for this campaign yet.' }));
      return;
    }

    const tier = currentGuide[currentDifficulty];
    if (!tier || !tier.length) {
      bodyEl.appendChild(el('div', { class: 'hunt-empty', text: 'No guidance authored for this difficulty yet.' }));
      return;
    }

    if (currentDifficulty === 'hard') {
      const list = el('ul', { class: 'hunt-hypotheses' });
      tier.forEach(function (line) {
        list.appendChild(el('li', { class: 'hunt-hypothesis', text: String(line) }));
      });
      bodyEl.appendChild(list);
      return;
    }

    const list = el('ol', { class: 'hunt-steps' });
    tier.forEach(function (step, idx) {
      const stepEl = el('li', { class: 'hunt-step' });
      stepEl.appendChild(el('div', { class: 'hunt-step-title', text: (idx + 1) + '. ' + String(step.title || '') }));
      if (step.detail) {
        stepEl.appendChild(el('div', { class: 'hunt-step-detail', text: String(step.detail) }));
      }
      if (currentDifficulty === 'easy' && step.spl) {
        stepEl.appendChild(renderSpl(String(step.spl)));
      }
      list.appendChild(stepEl);
    });
    bodyEl.appendChild(list);
  }

  function renderSpl(spl) {
    const wrapper = el('div', { class: 'hunt-spl' });
    const pre = el('pre', { class: 'hunt-spl-code' }, [el('code', { text: spl })]);
    const copyBtn = el('button', {
      class: 'hunt-spl-copy',
      type: 'button',
      text: 'Copy SPL',
      onclick: function () { copyText(spl, copyBtn); },
    });
    wrapper.appendChild(copyBtn);
    wrapper.appendChild(pre);
    return wrapper;
  }

  function copyText(text, btn) {
    const done = function () {
      const prev = btn.textContent;
      btn.textContent = 'Copied';
      btn.classList.add('copied');
      setTimeout(function () {
        btn.textContent = prev;
        btn.classList.remove('copied');
      }, 1500);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(text).then(done).catch(function () { fallbackCopy(text, done); });
    } else {
      fallbackCopy(text, done);
    }
  }

  function fallbackCopy(text, done) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'absolute';
    ta.style.left = '-9999px';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); done(); } catch (_) {}
    document.body.removeChild(ta);
  }

  function open(campaignId, campaignName) {
    ensureOverlay();
    const guides = window.HuntGuides || {};
    currentGuide = guides[campaignId] || null;

    titleEl.textContent = (campaignName || campaignId) + ' \u2014 How to Detect';
    summaryEl.textContent = currentGuide && currentGuide.summary ? currentGuide.summary : '';
    summaryEl.style.display = summaryEl.textContent ? 'block' : 'none';

    setDifficulty('easy');
    overlayEl.classList.add('open');
    document.body.classList.add('modal-open');
  }

  function close() {
    if (!overlayEl) return;
    overlayEl.classList.remove('open');
    document.body.classList.remove('modal-open');
    currentGuide = null;
  }

  window.HuntModal = { open: open, close: close };
})();
