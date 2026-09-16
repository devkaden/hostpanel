/* Shared client helpers: CSRF-aware fetch, toasts, modals, confirmations. */
(function () {
  'use strict';

  const meta = document.querySelector('meta[name="csrf-token"]');
  const CSRF = meta ? meta.getAttribute('content') : '';

  async function api(url, options) {
    // credentials is set explicitly rather than left to the default.
    //
    // fetch() originally defaulted to omitting cookies, and the default only
    // changed to same-origin later; a browser that omits them sends no session
    // cookie, which the panel sees as a brand new session whose CSRF token
    // cannot match - a 403 on every write, while XHR-based uploads on the same
    // page keep working, because XHR always sent cookies. That asymmetry is
    // very confusing to debug from the outside, and one word prevents it.
    const opts = Object.assign({ method: 'POST', credentials: 'same-origin' }, options || {});
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
      // Named in the console, because "Failed to load resource" alone says
      // neither which call failed nor why.
      try { console.error('[api]', opts.method, url, res.status, data.error || ''); } catch (_) {}
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

  /* --------------------------------------------------- dialogs -------- */
  /**
   * In-app replacements for window.confirm / alert / prompt. The built-in ones
   * are styled by the browser, block the whole tab, and cannot show a list or
   * a copy button. These return a promise and look like the rest of the panel.
   */
  function dialog(opts) {
    return new Promise(function (resolve) {
      var o = opts || {};
      var backdrop = document.createElement('div');
      backdrop.className = 'dlg-backdrop';

      var box = document.createElement('div');
      box.className = 'dlg' + (o.wide ? ' dlg-wide' : '');
      box.setAttribute('role', 'dialog');
      box.setAttribute('aria-modal', 'true');

      var icons = { danger: '!', warn: '!', ok: '\u2713', info: 'i', question: '?' };
      var tone = o.tone || (o.danger ? 'danger' : 'question');

      var body = document.createElement('div');
      body.className = 'dlg-body';

      var icon = document.createElement('div');
      icon.className = 'dlg-icon ' + (tone === 'question' ? '' : tone);
      icon.textContent = icons[tone] || '?';
      body.appendChild(icon);

      var content = document.createElement('div');
      content.className = 'dlg-content';

      var title = document.createElement('h3');
      title.className = 'dlg-title';
      title.textContent = o.title || 'Are you sure?';
      content.appendChild(title);

      if (o.message) {
        var msg = document.createElement('p');
        msg.className = 'dlg-message';
        msg.textContent = o.message;
        content.appendChild(msg);
      }

      if (o.list && o.list.length) {
        var list = document.createElement('div');
        list.className = 'dlg-list';
        o.list.forEach(function (line) {
          var row = document.createElement('div');
          row.textContent = line;
          list.appendChild(row);
        });
        content.appendChild(list);
      }

      var input = null;
      if (o.input) {
        var field = document.createElement('div');
        field.className = 'dlg-field';
        if (o.inputLabel) {
          var lab = document.createElement('label');
          lab.textContent = o.inputLabel;
          field.appendChild(lab);
        }
        input = document.createElement('input');
        input.type = 'text';
        input.value = o.value || '';
        if (o.placeholder) input.placeholder = o.placeholder;
        if (o.readonly) { input.readOnly = true; input.style.fontFamily = 'var(--mono)'; }
        field.appendChild(input);
        content.appendChild(field);
      }

      body.appendChild(content);
      box.appendChild(body);

      var foot = document.createElement('div');
      foot.className = 'dlg-foot';

      var finish = function (value) {
        backdrop.classList.remove('in');
        setTimeout(function () {
          backdrop.remove();
          document.removeEventListener('keydown', onKey, true);
          resolve(value);
        }, 120);
      };

      if (o.cancelText !== null) {
        var cancel = document.createElement('button');
        cancel.className = 'btn';
        cancel.textContent = o.cancelText || 'Cancel';
        cancel.addEventListener('click', function () { finish(o.input ? null : false); });
        foot.appendChild(cancel);
      }

      if (o.extraText) {
        var extra = document.createElement('button');
        extra.className = 'btn';
        extra.textContent = o.extraText;
        extra.addEventListener('click', function () { finish('extra'); });
        foot.appendChild(extra);
      }

      var ok = document.createElement('button');
      ok.className = 'btn ' + (o.danger ? 'btn-danger' : 'btn-primary');
      ok.textContent = o.confirmText || 'OK';
      ok.addEventListener('click', function () {
        if (o.copyValue && /^copy$/i.test(o.confirmText || '')) {
          copy(o.copyValue, o.copyLabel || 'Command');
        }
        finish(o.input ? (input ? input.value : '') : true);
      });
      foot.appendChild(ok);

      // A dialog with something to copy gets exactly one Copy button. It used
      // to get two - this one, plus the confirm button when the caller had
      // also named it "Copy" - which looked like a bug because it was one.
      if (o.copyValue && !/^copy$/i.test(o.confirmText || '')) {
        var copyBtn = document.createElement('button');
        copyBtn.className = 'btn';
        copyBtn.textContent = 'Copy';
        copyBtn.addEventListener('click', function () { copy(o.copyValue, o.copyLabel || 'Value'); });
        foot.insertBefore(copyBtn, foot.firstChild);
      }

      box.appendChild(foot);
      backdrop.appendChild(box);

      // Clicking the backdrop cancels, but only the backdrop itself.
      backdrop.addEventListener('mousedown', function (e) {
        if (e.target === backdrop) finish(o.input ? null : false);
      });

      function onKey(e) {
        if (e.key === 'Escape') { e.preventDefault(); finish(o.input ? null : false); }
        if (e.key === 'Enter' && (!input || document.activeElement === input)) {
          e.preventDefault();
          ok.click();
        }
      }
      document.addEventListener('keydown', onKey, true);

      document.body.appendChild(backdrop);
      requestAnimationFrame(function () { backdrop.classList.add('in'); });
      setTimeout(function () { (input || ok).focus(); if (input && !o.readonly) input.select(); }, 60);
    });
  }

  function confirmDialog(opts) {
    var o = typeof opts === 'string' ? { message: opts } : (opts || {});
    return dialog(Object.assign({ confirmText: 'Confirm' }, o, { input: false }));
  }

  function alertDialog(opts) {
    var o = typeof opts === 'string' ? { message: opts } : (opts || {});
    return dialog(Object.assign({ tone: 'info', confirmText: 'Close', cancelText: null }, o, { input: false }));
  }

  function promptDialog(opts) {
    var o = typeof opts === 'string' ? { message: opts } : (opts || {});
    return dialog(Object.assign({ tone: 'question', confirmText: 'OK' }, o, { input: true }));
  }

  /* ------------------------------------------------ interface mode ---- */
  // Preferences are stored against the signed-in account, so they follow the
  // person across refreshes, devices and logins. localStorage is only a
  // pre-paint cache so a page never flashes the wrong theme.
  function savePref(body) {
    api('/account/prefs', { body: body }).catch(function () {
      /* a failed save still applies for this page */
    });
  }

  function setMode(mode, persist) {
    var value = mode === 'advanced' ? 'advanced' : 'simple';
    document.documentElement.setAttribute('data-mode', value);
    document.body.className = 'mode-' + value;
    try { localStorage.setItem('hp-mode', value); } catch (e) { /* private mode */ }
    document.querySelectorAll('[data-mode-set]').forEach(function (b) {
      b.setAttribute('aria-pressed', String(b.getAttribute('data-mode-set') === value));
    });
    document.querySelectorAll('[data-mode-label]').forEach(function (el) {
      el.textContent = value === 'advanced' ? 'Advanced' : 'Simple';
    });
    if (persist) savePref({ ui_mode: value });
  }

  function currentMode() {
    return document.documentElement.getAttribute('data-mode') === 'advanced' ? 'advanced' : 'simple';
  }

  /* ------------------------------------------------------- theming ----- */
  function setTheme(theme, persist) {
    var resolved = theme;
    if (theme === 'system') {
      resolved = window.matchMedia && window.matchMedia('(prefers-color-scheme: light)').matches
        ? 'light' : 'dark';
    }
    document.documentElement.setAttribute('data-theme', resolved);
    try { localStorage.setItem('hp-theme', theme); } catch (e) { /* private mode */ }
    if (persist) savePref({ theme: theme });
  }

  function currentTheme() {
    return document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
  }

  /* ------------------------------------------- CSP violation reporting -- */
  /**
   * Reports anything the Content-Security-Policy blocks.
   *
   * A CSP refusal is close to invisible: the browser blocks the resource and
   * says nothing useful, so it surfaces as a blank iframe, an upload that never
   * sends, or an image that will not load - and none of those point at the
   * header responsible. This has already cost two long debugging sessions, so
   * the panel now says so itself, naming the directive and the URL.
   */
  function reportCspViolations() {
    document.addEventListener('securitypolicyviolation', function (e) {
      var detail = e.violatedDirective + ' blocked ' + (e.blockedURI || '(inline)');
      try { console.error('[csp]', detail, e); } catch (_) { /* no console */ }

      var host = document.getElementById('csp-note');
      if (host) {
        host.style.display = '';
        host.textContent =
          'The browser blocked this: ' + detail + '. That is the panel\'s ' +
          'Content-Security-Policy, not your site. Set DISABLE_CSP=true in ' +
          '/opt/hostpanel/app/.env and restart to confirm.';
      }
    });
  }

  /* ----------------------------------------------------- dropdowns ----- */
  /**
   * Any .menu with a .menu-trigger. Closes on outside click and on Escape,
   * because a menu that only closes by pressing the same button again is the
   * kind of small wrongness that makes a UI feel unfinished.
   */
  function initMenus() {
    var menus = Array.prototype.slice.call(document.querySelectorAll('.menu'));
    if (!menus.length) return;

    function closeAll(except) {
      menus.forEach(function (m) {
        if (m === except) return;
        m.setAttribute('data-open', 'false');
        var t = m.querySelector('.menu-trigger');
        if (t) t.setAttribute('aria-expanded', 'false');
      });
    }

    menus.forEach(function (menu) {
      var trigger = menu.querySelector('.menu-trigger');
      if (!trigger) return;
      menu.setAttribute('data-open', 'false');
      trigger.addEventListener('click', function (e) {
        e.stopPropagation();
        var open = menu.getAttribute('data-open') === 'true';
        closeAll(menu);
        menu.setAttribute('data-open', String(!open));
        trigger.setAttribute('aria-expanded', String(!open));
      });
      // Clicks inside the panel should not close it before the control runs.
      var panel = menu.querySelector('.menu-panel');
      if (panel) panel.addEventListener('click', function (e) { e.stopPropagation(); });
    });

    document.addEventListener('click', function () { closeAll(null); });
    document.addEventListener('keydown', function (e) {
      if (e.key === 'Escape') closeAll(null);
    });
  }

  /* -------------------------------------------------- site actions ----- */
  /**
   * Start / Stop / Restart / Apply changes, wherever they appear.
   *
   * These used to be wired up inside the Overview page, which is why the other
   * site tabs had no controls at all: switching to Logs to watch a restart
   * meant navigating back to press the button. Living here, the same bar works
   * on every tab.
   */
  function initSiteActions() {
    var bar = document.querySelector('[data-site-actions]');
    if (!bar) return;
    var siteId = bar.getAttribute('data-site-actions');

    bar.querySelectorAll('[data-action]').forEach(function (btn) {
      btn.addEventListener('click', async function () {
        var action = btn.getAttribute('data-action');
        var label = btn.textContent.trim();
        btn.disabled = true;
        try {
          var res = await api('/sites/' + siteId + '/action/' + action, { method: 'POST' });
          if (res.background) {
            toast(label + ' started', 'ok');
            // The build log lives on the Overview page; go and watch it.
            window.location.href = '/sites/' + siteId + '?provisioning=1';
            return;
          }
          toast(label + ' done', 'ok');
          window.location.reload();
        } catch (err) {
          await alertDialog({ title: label + ' failed', message: err.message, tone: 'danger' });
          btn.disabled = false;
        }
      });
    });
  }

  document.addEventListener('DOMContentLoaded', function () {
    setMode(currentMode());

    var toggle = document.getElementById('theme-toggle');
    if (toggle) {
      toggle.addEventListener('click', function () {
        setTheme(currentTheme() === 'light' ? 'dark' : 'light', true);
      });
    }

    document.querySelectorAll('[data-mode-set]').forEach(function (b) {
      b.addEventListener('click', function () { setMode(b.getAttribute('data-mode-set'), true); });
    });
    document.querySelectorAll('[data-mode-toggle]').forEach(function (b) {
      b.addEventListener('click', function (e) {
        e.stopPropagation();
        setMode(currentMode() === 'advanced' ? 'simple' : 'advanced', true);
      });
    });

    initMenus();
    initSiteActions();
    reportCspViolations();

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
    dialog, confirm: confirmDialog, alert: alertDialog, prompt: promptDialog,
  };
})();
