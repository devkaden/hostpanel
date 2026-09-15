/* Shared client helpers: CSRF-aware fetch, toasts, modals, confirmations. */
(function () {
  'use strict';

  const meta = document.querySelector('meta[name="csrf-token"]');
  const CSRF = meta ? meta.getAttribute('content') : '';

  async function api(url, options) {
    const opts = Object.assign({ method: 'POST' }, options || {});
    opts.headers = Object.assign(
      { 'X-CSRF-Token': CSRF, Accept: 'application/json' },
      opts.headers || {}
    );
    if (opts.body && !(opts.body instanceof FormData) && typeof opts.body !== 'string') {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(opts.body);
    }
    const res = await fetch(url, opts);
    let data = null;
    const text = await res.text();
    try {
      data = text ? JSON.parse(text) : {};
    } catch (_) {
      data = { error: text.slice(0, 300) || 'Unexpected response' };
    }
    if (!res.ok) {
      const err = new Error(data.error || `Request failed (${res.status})`);
      err.data = data;
      err.status = res.status;
      throw err;
    }
    return data;
  }

  function toast(message, kind) {
    const host = document.getElementById('toast-host');
    if (!host) return;
    const el = document.createElement('div');
    el.className = 'toast' + (kind ? ' toast-' + kind : '');
    el.textContent = message;
    host.appendChild(el);
    setTimeout(() => {
      el.style.transition = 'opacity .25s';
      el.style.opacity = '0';
      setTimeout(() => el.remove(), 260);
    }, kind === 'error' ? 7000 : 3800);
  }

  function openModal(id) {
    const el = document.getElementById(id);
    if (el) el.classList.add('open');
  }

  function closeModal(id) {
    const el = document.getElementById(id);
    if (el) el.classList.remove('open');
  }

  // Close modals on backdrop click and Escape.
  document.addEventListener('click', (e) => {
    if (e.target.classList && e.target.classList.contains('modal-backdrop')) {
      e.target.classList.remove('open');
    }
    const closer = e.target.closest && e.target.closest('[data-close-modal]');
    if (closer) closeModal(closer.getAttribute('data-close-modal'));
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      document.querySelectorAll('.modal-backdrop.open').forEach((m) => m.classList.remove('open'));
    }
  });

  function bytes(n) {
    if (n === null || n === undefined) return '-';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let v = Number(n);
    let i = 0;
    while (v >= 1024 && i < units.length - 1) {
      v /= 1024;
      i += 1;
    }
    return (v >= 10 || i === 0 ? Math.round(v) : v.toFixed(1)) + ' ' + units[i];
  }

  function copy(text, label) {
    const done = () => toast((label || 'Copied') + ' to clipboard', 'ok');
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done, () => fallbackCopy(text, done));
    } else {
      fallbackCopy(text, done);
    }
  }

  function fallbackCopy(text, done) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try {
      document.execCommand('copy');
      done();
    } catch (_) {
      toast('Could not copy automatically - select the text manually', 'error');
    }
    ta.remove();
  }

  // Any element with data-copy copies its value on click.
  document.addEventListener('click', (e) => {
    const el = e.target.closest && e.target.closest('[data-copy]');
    if (el) {
      e.preventDefault();
      copy(el.getAttribute('data-copy'), el.getAttribute('data-copy-label'));
    }
  });

  function escapeHtml(str) {
    return String(str).replace(/[&<>"']/g, (c) => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));
  }

  function relTime(iso) {
    if (!iso) return '-';
    const then = new Date(iso).getTime();
    if (Number.isNaN(then)) return iso;
    const diff = Math.round((Date.now() - then) / 1000);
    if (diff < 60) return diff + 's ago';
    if (diff < 3600) return Math.round(diff / 60) + 'm ago';
    if (diff < 86400) return Math.round(diff / 3600) + 'h ago';
    return Math.round(diff / 86400) + 'd ago';
  }

  /* ------------------------------------------------ interface mode ---- */
  function setMode(mode) {
    var value = mode === 'advanced' ? 'advanced' : 'simple';
    document.documentElement.setAttribute('data-mode', value);
    document.body.className = 'mode-' + value;
    try { localStorage.setItem('hp-mode', value); } catch (e) { /* private mode */ }
    document.querySelectorAll('[data-mode-set]').forEach(function (b) {
      b.setAttribute('aria-pressed', String(b.getAttribute('data-mode-set') === value));
    });
  }

  function currentMode() {
    return document.documentElement.getAttribute('data-mode') === 'advanced' ? 'advanced' : 'simple';
  }

  /* ------------------------------------------------------- theming ----- */
  function setTheme(theme) {
    var resolved = theme;
    if (theme === 'system') {
      resolved = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches
        ? 'light' : 'dark';
    }
    document.documentElement.setAttribute('data-theme', resolved);
    try { localStorage.setItem('hp-theme', theme); } catch (e) { /* private mode */ }
  }

  function currentTheme() {
    return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
  }

  document.addEventListener('DOMContentLoaded', function () {
    setMode(currentMode());

    var toggle = document.getElementById('theme-toggle');
    if (toggle) {
      toggle.addEventListener('click', function () {
        setTheme(currentTheme() === 'light' ? 'dark' : 'light');
      });
    }

    document.querySelectorAll('[data-mode-set]').forEach(function (b) {
      b.addEventListener('click', function () { setMode(b.getAttribute('data-mode-set')); });
    });

    // Help bubbles are reachable by keyboard, not just hover.
    document.querySelectorAll('.help').forEach(function (h) {
      if (!h.hasAttribute('tabindex')) h.setAttribute('tabindex', '0');
      if (!h.hasAttribute('role')) h.setAttribute('role', 'note');
      if (!h.textContent.trim()) h.textContent = '?';
    });
  });

  window.HP = {
    api, toast, openModal, closeModal, bytes, copy, escapeHtml, relTime, CSRF,
    setMode, currentMode, setTheme, currentTheme,
  };
})();
