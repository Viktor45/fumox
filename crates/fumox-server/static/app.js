// Admin panel behaviour.
//
// Loaded with `defer` from /admin/static/app.js, so the document is
// parsed when this runs. The content-security policy allows scripts from
// this origin only: there is no inline script and no inline event
// handler in the templates, every handler is delegated from here.
//
// The toast handler decodes its message with `decodeURIComponent`: the
// server percent-encodes every message it sends (the `HX-Trigger` header
// and the pending toast alike), because a header is Latin-1 on the wire
// and raw UTF-8 would arrive as mojibake.

(function () {
  'use strict';

  // Toast: handlers send HX-Trigger: {"toast": {"message": ..., "level": ...}}.
  document.body.addEventListener('toast', function (e) {
    var wrap = document.getElementById('toast-wrap');
    if (!wrap) return;
    var detail = e.detail || {};
    var div = document.createElement('div');
    var isError = detail.level === 'error';
    div.className = 'toast' + (isError ? ' error' : '');
    // role=status/alert makes the toast announced by screen readers;
    // errors stay longer and are dismissable by click.
    div.setAttribute('role', isError ? 'alert' : 'status');
    var message = detail.message || '';
    try { message = decodeURIComponent(message); } catch (_) {}
    div.textContent = message || String(e.detail);
    div.addEventListener('click', function () { div.remove(); });
    wrap.appendChild(div);
    setTimeout(function () { div.remove(); }, isError ? 10000 : 4000);
  });

  // Toast of a plain-browser action: the server parks the message in the
  // session and hands it over here, once. It does not travel through the
  // URL, so a copied link cannot replay it and a crafted link cannot
  // fake one.
  (function () {
    if (!window.fetch) return;
    fetch('/admin/flash', { credentials: 'same-origin' })
      .then(function (response) {
        if (!response.ok) return null;
        return response.json();
      })
      .then(function (data) {
        if (!data || !data.message) return;
        document.body.dispatchEvent(new CustomEvent('toast', {
          detail: { message: data.message, level: data.level || 'ok' }
        }));
      })
      .catch(function () { /* a missing toast is not worth an error */ });
  })();

  // SSE: push updates from the server. Each event is
  // re-broadcast on <body> as a namespaced DOM event so HTMX fragments
  // can react with hx-trigger="fumox:*". Polling fragments remain the
  // no-JS fallback, SSE is a pure enhancement.
  (function () {
    if (!window.EventSource) return;
    var statusEl = document.getElementById('sse-status');
    function setStatus(state) {
      if (!statusEl) return;
      statusEl.setAttribute('data-state', state);
      statusEl.textContent = state === 'live'
        ? statusEl.getAttribute('data-live')
        : statusEl.getAttribute('data-stale');
      statusEl.hidden = false;
    }
    var es = new EventSource('/admin/events');
    es.addEventListener('open', function () { setStatus('live'); });
    es.addEventListener('error', function () {
      // EventSource reconnects on its own; show the gap meanwhile.
      setStatus(es.readyState === EventSource.OPEN ? 'live' : 'stale');
    });
    ['fetch.started', 'fetch.done', 'fetch.failed']
      .forEach(function (name) {
        es.addEventListener(name, function (e) {
          var data = {};
          try { data = JSON.parse(e.data); } catch (_) {}
          document.body.dispatchEvent(new CustomEvent('fumox:' + name, { detail: data }));
        });
      });
    // When any fetch finishes, refresh the in-flight status fragment and
    // the source fetch-log if either is present on the page.
    function refreshAfterFetch() {
      if (!window.htmx) return;
      ['refresh-status', 'log-live'].forEach(function (id) {
        var el = document.getElementById(id);
        if (el) window.htmx.trigger(el, 'fumox:refresh');
      });
    }
    document.body.addEventListener('fumox:fetch.done', refreshAfterFetch);
    document.body.addEventListener('fumox:fetch.failed', refreshAfterFetch);
  })();

  // Toggle swaps replace the button the user just activated (the form
  // travels out-of-band with the badge), so keyboard focus falls to
  // <body> after every click. Put it back on the re-created button, but
  // only when focus was not moved elsewhere in the meantime.
  (function () {
    function restoreToggleFocus(event) {
      var target = event.detail && event.detail.target;
      if (!target || target.id !== 'enabled-badge') return;
      if (document.activeElement !== document.body) return;
      requestAnimationFrame(function () {
        var form = document.getElementById('toggle-form');
        var btn = form && form.querySelector('button[type="submit"]');
        if (btn) btn.focus();
      });
    }
    document.body.addEventListener('htmx:afterSwap', restoreToggleFocus);
    document.body.addEventListener('htmx:oobAfterSwap', restoreToggleFocus);
  })();

  // Local time: the server emits every
  // timestamp as <time class="ts" datetime="RFC3339 UTC">UTC text</time>.
  // The browser rewrites the text into the user's timezone, formatted in
  // the panel language (<html lang>), without JS the UTC text stays.
  // Re-run after every HTMX swap: fragments carry <time> elements too.
  // Idempotent: the text is always rebuilt from the datetime attribute.
  (function () {
    function localize(root) {
      if (!root.querySelectorAll) return;
      var lang = document.documentElement.lang || undefined;
      var full, dayOnly;
      try {
        full = new Intl.DateTimeFormat(lang, {
          year: 'numeric', month: '2-digit', day: '2-digit',
          hour: '2-digit', minute: '2-digit', second: '2-digit'
        });
        // `time.ts.day` marks a calendar-day bucket (the ingest chart's
        // columns): the time of day is always 00:00 and only crowds out
        // the date in a 64px column, so those keep the date alone.
        dayOnly = new Intl.DateTimeFormat(lang, {
          year: 'numeric', month: '2-digit', day: '2-digit'
        });
      } catch (_) { return; }
      var zone = '';
      try {
        zone = ' (' + (Intl.DateTimeFormat().resolvedOptions().timeZone || 'UTC') + ')';
      } catch (_) {}
      root.querySelectorAll('time.ts').forEach(function (el) {
        var attr = el.getAttribute('datetime');
        if (!attr) return;
        var stamp = new Date(attr);
        if (isNaN(stamp)) return;
        var isDay = el.classList.contains('day');
        var fmt = isDay ? dayOnly : full;
        var local = fmt.format(stamp);
        el.textContent = local;
        // Language-neutral tooltip: the original UTC instant and the zone used.
        el.title = attr + ' → ' + local + zone;
      });
    }
    localize(document);
    document.body.addEventListener('htmx:afterSettle', function () {
      localize(document);
    });
  })();

  // Pipeline widget: show/hide the inner fields of a tri-state section
  // (geo / sort / limit) based on which radio is checked. The inner
  // fields are always in the DOM so the browser can hold typed values
  // across toggles; the `hidden` attribute is the only visibility knob.
  // Runs on initial load (initial state) and on every HTMX settle (the
  // widget re-renders on preset / mode / preview refresh).
  //
  // The token names below are the contract between the rendered widget
  // and this script: the template emits `data-ped-section="<name>"`,
  // the radio group `ped_<name>` and the inner block
  // `data-ped-inner="<name>"` for every section. A test suite keeps the
  // two sides in sync (template_contracts.rs); change them together.
  var PED_SECTION_ATTR = 'data-ped-section';
  var PED_INNER_ATTR = 'data-ped-inner';
  var PED_INPUT_PREFIX = 'ped_';
  (function () {
    function syncSection(section) {
      var name = section.getAttribute(PED_SECTION_ATTR);
      if (!name) return;
      var checked = section.querySelector('input[name="' + PED_INPUT_PREFIX + name + '"]:checked');
      var inner = section.querySelector('[' + PED_INNER_ATTR + '="' + name + '"]');
      if (!inner) return;
      // Hide when the section is `skip`; show otherwise. `defaults`
      // and `set` keep the inner fields visible so the user can edit.
      // A hidden block is disabled along with the hiding: its fields
      // are dropped on save (the section is skipped), so submitting
      // them would promise what the server silently ignores. Disabled
      // controls are left out of the submission by both the plain form
      // and htmx, and they keep their typed values for the toggle-back.
      var inputs = inner.querySelectorAll('input, select, textarea');
      if (checked && checked.value === 'skip') {
        inner.setAttribute('hidden', '');
        for (var i = 0; i < inputs.length; i++) inputs[i].disabled = true;
      } else {
        inner.removeAttribute('hidden');
        for (var j = 0; j < inputs.length; j++) inputs[j].disabled = false;
      }
    }
    function syncAll(root) {
      var sections = (root || document).querySelectorAll('[' + PED_SECTION_ATTR + ']');
      for (var i = 0; i < sections.length; i++) syncSection(sections[i]);
    }
    syncAll(document);
    // User clicks on a tri-state radio.
    document.body.addEventListener('change', function (event) {
      var target = event.target;
      if (!(target instanceof HTMLInputElement)) return;
      var name = target.name;
      if (!name || name.indexOf(PED_INPUT_PREFIX) !== 0) return;
      var section = target.closest('[' + PED_SECTION_ATTR + ']');
      if (section) syncSection(section);
    });
    // The widget is re-rendered by HTMX on preset / mode / preview
    // refresh, re-run after every settle so the initial state matches
    // the rendered radios.
    document.body.addEventListener('htmx:afterSettle', function () {
      syncAll(document);
    });
  })();

  // Settings tabs: the panes swap on the radio's :checked, but
  // `aria-selected` is server-rendered and would keep naming the tab the
  // page loaded with. Mirror the radio onto the labels.
  (function () {
    function syncTabs() {
      document.querySelectorAll('input.tab-input').forEach(function (input) {
        var label = document.querySelector('label[for="' + input.id + '"]');
        if (label) label.setAttribute('aria-selected', input.checked ? 'true' : 'false');
      });
    }
    document.body.addEventListener('change', function (event) {
      if (event.target instanceof HTMLInputElement && event.target.classList.contains('tab-input')) syncTabs();
    });
    syncTabs();
  })();

  // Rule counters: the lists are capped in height, so the number is the
  // only way to see how many rules a section holds, and htmx changes the
  // rows without a page render. Blank lines do not count, the rename
  // editor always keeps one and it emits no rule.
  (function () {
    function filledRows(container) {
      if (!container) return 0;
      return Array.prototype.filter.call(
        container.querySelectorAll('.ped-row'),
        function (row) {
          return Array.prototype.some.call(
            row.querySelectorAll('input[type="text"]'),
            function (input) { return input.value.trim() !== ''; }
          );
        }
      ).length;
    }
    function syncRuleCounts() {
      document.querySelectorAll('[data-ped-count]').forEach(function (badge) {
        var which = badge.getAttribute('data-ped-count');
        var count = filledRows(
          document.querySelector(which === 'rename' ? '#ped-rows' : '#ped-drop-rows')
        );
        badge.textContent = String(count);
        if (count === 0) badge.setAttribute('hidden', '');
        else badge.removeAttribute('hidden');
      });
    }
    document.body.addEventListener('htmx:afterSettle', syncRuleCounts);
    syncRuleCounts();
  })();

  // Pipeline rule rows: the container is re-rendered wholesale after a
  // target change or a row removal, and only the target select carries
  // a stable id for htmx to hand the focus back to. Track where the
  // focus sat (row number and the control's position inside the row)
  // and put it back after the settle; when the row the user was on was
  // removed, land on the neighbouring remove button. A hidden live
  // region next to the rows says that the list changed: the rows
  // themselves stay silent, a re-rendered table would read itself out.
  (function () {
    var ROW_CONTAINER_SEL = '#ped-rows, #ped-drop-rows';
    var snapshot = null;

    function indexIn(parent, el) {
      return Array.prototype.indexOf.call(parent.children, el);
    }

    // Where the focus sits, kept current on every focus move inside the
    // rows: the restore must not depend on which control fired the
    // request.
    document.body.addEventListener('focusin', function (event) {
      var active = event.target;
      if (!active || !active.closest) return;
      var row = active.closest('.ped-row');
      if (!row) return;
      var container = row.closest(ROW_CONTAINER_SEL);
      if (!container) return;
      snapshot = {
        container: container.id,
        row: indexIn(container, row),
        control: indexIn(row, active),
        removed: false
      };
    });

    // The remove button drops its own row: remember the row so the
    // focus can land on the neighbour's button after the swap. The
    // click runs before the request; the button's hx-post carries the
    // rows endpoint's `remove=` form — a contract with _rows.html.
    document.body.addEventListener('click', function (event) {
      var target = event.target;
      if (!(target instanceof HTMLButtonElement)) return;
      var row = target.closest('.ped-row');
      if (!row) return;
      var container = row.closest(ROW_CONTAINER_SEL);
      if (!container) return;
      var path = target.getAttribute('hx-post') || '';
      if (path.indexOf('remove=') === -1) return;
      snapshot = {
        container: container.id,
        row: indexIn(container, row),
        removed: true
      };
    });

    document.body.addEventListener('htmx:afterSettle', function (event) {
      var target = event.detail && event.detail.target;
      if (!target || !snapshot) return;
      if (target.id !== 'ped-rows' && target.id !== 'ped-drop-rows') return;
      var remembered = snapshot;
      snapshot = null;

      var live = document.querySelector('[data-ped-live="' + remembered.container + '"]');
      if (live) live.textContent = live.getAttribute('data-list-changed') || '';

      // The keyboard user's focus fell to <body> with the row it sat
      // in; put it back, but only when focus was not moved elsewhere in
      // the meantime.
      if (document.activeElement !== document.body) return;
      var rows = target.querySelectorAll('.ped-row');
      if (!rows.length) return;
      var row = remembered.removed
        ? rows[Math.min(remembered.row, rows.length - 1)]
        : rows[remembered.row];
      if (!row) return;
      var control = remembered.removed
        ? row.querySelector('button')
        : row.children[remembered.control];
      if (control && typeof control.focus === 'function') control.focus();
    });
  })();

  // Dialogs: a trigger carries `data-dialog-open="<dialog id>"`, a
  // cancel button carries `data-dialog-close`. The no-JS fallback in
  // base.html renders the dialog as a plain panel and hides the trigger,
  // so the form inside stays reachable without scripting.
  //
  // The focus goes to the heading of the dialog, not to the first
  // control: in the destructive dialogs the first control is the button
  // that applies them, and a keyboard user must not be able to press it
  // by accident. The focus returns to the trigger when the dialog
  // closes.
  document.body.addEventListener('click', function (event) {
    var target = event.target;
    if (!target || !target.closest) return;
    var opener = target.closest('[data-dialog-open]');
    if (opener) {
      var dialog = document.getElementById(opener.getAttribute('data-dialog-open'));
      if (dialog && typeof dialog.showModal === 'function') {
        dialog.showModal();
        var heading = dialog.querySelector('h1[tabindex], h2[tabindex], h3[tabindex]');
        if (heading) heading.focus();
        dialog.addEventListener('close', function () { opener.focus(); }, { once: true });
      }
      return;
    }
    var closer = target.closest('[data-dialog-close]');
    if (closer) {
      var owner = closer.closest('dialog');
      if (owner) owner.close();
    }
  });

  // A request the server refused: the plain-text body of the response
  // (a localized "not found" or "internal error") is printed into the
  // slot the page keeps next to the control that failed. The
  // content-security policy forbids inline handlers, so the listener is
  // delegated from here.
  (function () {
    function slotFor(elt) {
      var holder = elt && elt.closest ? elt.closest('[data-error-target]') : null;
      if (!holder) return null;
      return document.getElementById(holder.getAttribute('data-error-target'));
    }
    document.body.addEventListener('htmx:beforeRequest', function (event) {
      var slot = slotFor(event.detail && event.detail.elt);
      if (slot) slot.textContent = '';
    });
    document.body.addEventListener('htmx:responseError', function (event) {
      var detail = event.detail || {};
      var slot = slotFor(detail.elt);
      if (!slot) return;
      var xhr = detail.xhr;
      var message = xhr && xhr.responseText ? xhr.responseText.trim() : '';
      slot.textContent = message || slot.getAttribute('data-error-fallback') || '';
    });
    // A request that never got an answer (the network dropped, the
    // server is gone): htmx fires sendError and no responseError, so
    // without this the slot would keep claiming the action succeeded.
    // There is no body to print, the slot's fallback text stands in.
    document.body.addEventListener('htmx:sendError', function (event) {
      var slot = slotFor(event.detail && event.detail.elt);
      if (!slot) return;
      slot.textContent = slot.getAttribute('data-error-fallback') || '';
    });
  })();

  // A table that refreshes itself: the container is re-rendered on every
  // poll, and a live region on the table itself would read the whole
  // table out every time. The table stays silent, the status line next to
  // it counts the rows that appeared since the previous poll.
  (function () {
    function stamps(container) {
      var list = [];
      container.querySelectorAll('time.ts').forEach(function (el) {
        var value = Date.parse(el.getAttribute('datetime') || '');
        if (!isNaN(value)) list.push(value);
      });
      return list;
    }
    function update(container) {
      var slot = document.getElementById(container.getAttribute('data-live-status'));
      if (!slot) return;
      var list = stamps(container);
      if (!list.length) return;
      var newest = list.reduce(function (a, b) { return a > b ? a : b; });
      var seen = container.getAttribute('data-newest');
      if (seen === null) {
        // The first render is the baseline, nothing is new yet.
        container.setAttribute('data-newest', String(newest));
        return;
      }
      var previous = Number(seen);
      container.setAttribute('data-newest', String(newest));
      if (!(newest > previous)) return;
      var added = list.filter(function (value) { return value > previous; }).length;
      var template = slot.getAttribute('data-new-records') || '{n}';
      slot.textContent = template.replace('{n}', String(added));
    }
    function updateAll() {
      document.querySelectorAll('[data-live-status]').forEach(update);
    }
    document.body.addEventListener('htmx:afterSwap', updateAll);
    updateAll();
  })();

  // The theme and language switchers return to the current page: their
  // hidden `next` inputs carry the current path, filled here once per
  // document load (the script is deferred, so this runs before any
  // interaction). Without JavaScript the inputs stay empty and the
  // server falls back to the dashboard.
  document.querySelectorAll('input[data-next-input]').forEach(function (input) {
    input.value = location.pathname + location.search;
  });

  // A select that submits its own form (the dashboard's row count).
  document.body.addEventListener('change', function (event) {
    var target = event.target;
    if (!(target instanceof HTMLSelectElement)) return;
    if (!target.hasAttribute('data-submit-form')) return;
    if (target.form) target.form.submit();
  });

  // A form that asks before it acts: the confirmation text is the
  // `data-confirm` attribute of the form.
  document.body.addEventListener('submit', function (event) {
    var form = event.target;
    if (!form || !form.getAttribute) return;
    var message = form.getAttribute('data-confirm');
    if (!message) return;
    if (!window.confirm(message)) event.preventDefault();
  });

  // A form the server refused: the first invalid control takes the
  // focus, so the operator lands on the field that has to be fixed
  // instead of on the top of a long form. The control can sit in a pane
  // that the CSS-only tabs keep hidden, and a hidden control cannot take
  // the focus, so its pane is opened first.
  (function () {
    function openPaneOf(element) {
      var pane = element.closest('.tab-pane');
      if (!pane || !pane.id) return;
      var radios = document.querySelectorAll('input.tab-input');
      for (var i = 0; i < radios.length; i++) {
        var label = document.querySelector('label[for="' + radios[i].id + '"]');
        if (!label) continue;
        if (label.getAttribute('aria-controls') !== pane.id) continue;
        if (radios[i].checked) return;
        radios[i].checked = true;
        // The strip's `aria-selected` is mirrored from the radio.
        radios[i].dispatchEvent(new Event('change', { bubbles: true }));
        return;
      }
    }
    var invalid = document.querySelector('[aria-invalid="true"]');
    if (!invalid) return;
    openPaneOf(invalid);
    // Reading a layout property flushes the style, so the pane is
    // already visible when the focus is moved into it.
    void invalid.offsetHeight;
    invalid.focus();
  })();

  // The import screen: load a chosen JSON file into the payload
  // textarea. The textarea also accepts a manual paste, so the flow
  // works without scripting.
  (function () {
    var input = document.getElementById('io-file');
    if (!input || !window.FileReader) return;
    input.addEventListener('change', function () {
      var file = input.files && input.files[0];
      if (!file) return;
      var reader = new FileReader();
      reader.onload = function () {
        var area = document.querySelector('textarea[name="payload"]');
        if (area) area.value = reader.result;
      };
      reader.readAsText(file);
    });
  })();
})();
