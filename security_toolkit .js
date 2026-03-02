/**
 * Browser Security Analysis Toolkit v4.0
 * Modular runtime reconnaissance framework for educational and authorized security research.
 * NON-DESTRUCTIVE: observe and log only — no exploitation, no data modification.
 *
 * Usage:
 *   Paste into browser DevTools Console and press Enter.
 *   window.Toolkit.exportReport() → full JSON export of analysis results.
 */
(function () {
  'use strict';

  // ─── Color Palette ──────────────────────────────────────────────────────────
  const C = {
    ok:      'color:#00e676;font-weight:bold',
    warn:    'color:#ffea00;font-weight:bold',
    risk:    'color:#ff1744;font-weight:bold',
    info:    'color:#40c4ff;font-weight:bold',
    muted:   'color:#90a4ae',
    heading: 'color:#e040fb;font-weight:bold;font-size:13px',
    label:   'color:#b0bec5;font-weight:bold',
    score:   'color:#fff;background:#37474f;font-weight:bold;font-size:13px;padding:3px 8px;border-radius:3px',
    banner:  'color:#000;background:linear-gradient(90deg,#e040fb,#00b0ff);font-weight:bold;font-size:14px;padding:4px 10px;border-radius:4px',
  };

  const log   = (style, ...args) => console.log(`%c${args[0]}`, style, ...args.slice(1));
  const table = (data) => data && Object.keys(data).length && console.table(data);

  // ─── Constants ───────────────────────────────────────────────────────────────
  const API_PATTERNS      = [/\/api\//i, /\/auth\//i, /\/login/i, /\/logout/i, /\/submit/i, /\/token/i, /\/oauth/i, /\/graphql/i, /\/rest\//i, /\/v\d+\//i];
  const AUTH_PATTERNS     = [/\/auth\//i, /\/login/i, /\/logout/i, /\/token/i, /\/oauth/i, /\/session/i, /\/refresh/i, /\/2fa/i, /\/sso/i];
  const ANALYTICS_DOMAINS = ['google-analytics.com','googletagmanager.com','analytics.','segment.io','mixpanel.com','amplitude.com','hotjar.com','intercom.io','fullstory.com','heap.io','sentry.io','datadog','newrelic','bugsnag'];
  const CDN_DOMAINS       = ['cloudflare.com','cdn.jsdelivr.net','unpkg.com','cdnjs.cloudflare.com','cdn.skypack.dev','stackpath.bootstrapcdn.com','maxcdn.bootstrapcdn.com','ajax.googleapis.com','cdn.datatables.net'];
  const SENSITIVE_KEYS    = ['token','auth','session','jwt','access','refresh','secret','password','passwd','apikey','api_key','bearer','credential','sid','ssid'];
  const SENSITIVE_FIELDS  = ['password','pass','passwd','secret','token','auth','key','pin','ssn','credit','card','cvv'];
  const KNOWN_LIBS        = {
    React:   () => !!(window.React   || document.querySelector('[data-reactroot],[data-reactid]')),
    Angular: () => !!(window.angular || document.querySelector('[ng-app],[ng-controller],[_nghost],[ng-version]')),
    Vue:     () => !!(window.Vue     || document.querySelector('[data-v-]')),
    jQuery:  () => !!window.jQuery,
    Next:    () => !!(window.__NEXT_DATA__ || window.next),
    Nuxt:    () => !!window.__NUXT__,
    Ember:   () => !!window.Ember,
    Svelte:  () => !!document.querySelector('[class*="svelte-"]'),
    Lodash:  () => !!window._,
    Axios:   () => !!window.axios,
    Moment:  () => !!window.moment,
  };

  // ─── Internal State Registry ────────────────────────────────────────────────
  const _state = {
    version:              '4.0',
    startTime:            performance.now(),
    requests:             [],
    endpointMap:          new Map(),        // url → { count, statuses, durations }
    tokens:               {},
    tokenEntropy:         {},
    securitySignals:      { high: [], medium: [], low: [] },
    thirdPartyDomains:    new Set(),
    apiEndpoints:         new Set(),
    sinkInvocations:      [],
    scriptTagsAdded:      [],
    domScore:             0,
    riskScore:            0,
    cookies:              [],
    formAnalysis:         [],
    domStats:             {},
    websocketConnections: [],
    postMessages:         [],
    jwtFindings:          [],
    serviceWorkers:       [],
    permissions:          [],
    piiFindings:          {},
    reportReady:          false,
  };

  // ─── Utility: Shannon Entropy ────────────────────────────────────────────────
  function shannonEntropy(str) {
    if (!str || str.length === 0) return 0;
    const freq = {};
    for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
    const len = str.length;
    return -Object.values(freq).reduce((sum, f) => {
      const p = f / len;
      return sum + p * Math.log2(p);
    }, 0);
  }

  // ─── Utility: Throttle ──────────────────────────────────────────────────────
  function throttle(fn, delay) {
    let last = 0;
    return function (...args) {
      const now = Date.now();
      if (now - last >= delay) { last = now; fn.apply(this, args); }
    };
  }

  // ─── Module: Core ───────────────────────────────────────────────────────────
  const Core = {
    init() {
      console.log('%c 🔐 Browser Security Analysis Toolkit v4.0 ', C.banner);
      log(C.info, `ℹ  Target : ${location.href}`);
      log(C.info, `ℹ  Date   : ${new Date().toISOString()}`);
      log(C.info, `ℹ  Agent  : ${navigator.userAgent.substring(0, 80)}`);
      log(C.muted, '─────────────────────────────────────────────────────────────────');
    },
    run() {},
  };

  // ─── Module: NetworkMonitor ─────────────────────────────────────────────────
  const NetworkMonitor = {
    init() {
      const pageOrigin = location.origin;

      // Hook fetch — record timing, size, auth detection
      const _fetch = window.fetch;
      window.fetch = function (...args) {
        const req    = args[0];
        const url    = req instanceof Request ? req.url : String(req);
        const opts   = args[1] || {};
        const method = (opts.method || (req instanceof Request ? req.method : 'GET')).toUpperCase();
        const t0     = performance.now();
        return _fetch.apply(this, args).then(res => {
          const duration = +(performance.now() - t0).toFixed(1);
          const size     = parseInt(res.headers.get('content-length') || '0', 10);
          const ct       = res.headers.get('content-type') || '';
          NetworkMonitor._record(method, url, res.status, ct, size, duration, pageOrigin);
          return res;
        }).catch(err => { throw err; });
      };

      // Hook XHR — record timing, size, auth detection
      const _open = XMLHttpRequest.prototype.open;
      const _send = XMLHttpRequest.prototype.send;
      XMLHttpRequest.prototype.open = function (method, url) {
        this._rm = method ? method.toUpperCase() : 'GET';
        this._ru = String(url);
        this._t0 = 0;
        return _open.apply(this, arguments);
      };
      XMLHttpRequest.prototype.send = function () {
        this._t0 = performance.now();
        this.addEventListener('load', () => {
          try {
            const duration = +(performance.now() - this._t0).toFixed(1);
            const ct       = this.getResponseHeader('content-type') || '';
            const size     = (this.responseText || '').length;
            NetworkMonitor._record(this._rm, this._ru, this.status, ct, size, duration, pageOrigin);
          } catch (_) {}
        });
        return _send.apply(this, arguments);
      };
    },

    _record(method, url, status, contentType, size, duration, pageOrigin) {
      let origin;
      try { origin = new URL(url).origin; } catch { origin = 'relative'; }
      const isCross     = origin !== 'relative' && origin !== pageOrigin;
      const isAPI       = API_PATTERNS.some(p => p.test(url));
      const isAuth      = AUTH_PATTERNS.some(p => p.test(url));
      const isAnalytics = ANALYTICS_DOMAINS.some(d => url.includes(d));
      const isJSON      = /json/i.test(contentType);

      if (isAPI || isCross) _state.apiEndpoints.add(url);
      if (isCross)          _state.thirdPartyDomains.add(origin);

      // Build live endpoint map and detect repeated calls
      if (!_state.endpointMap.has(url)) {
        _state.endpointMap.set(url, { count: 0, statuses: [], durations: [] });
      }
      const ep = _state.endpointMap.get(url);
      ep.count++;
      ep.statuses.push(status);
      ep.durations.push(duration);

      // Flag suspicious status code clusters
      if ([401, 403, 500, 502, 503].includes(status)) {
        _state.securitySignals.medium.push(`HTTP ${status} on ${method} ${url.substring(0, 80)}`);
      }

      const entry = { method, url, status, isCross, isAPI, isAuth, isAnalytics, isJSON, origin, size, contentType, duration };
      _state.requests.push(entry);
      NetworkMonitor._log(entry);
    },

    _log(e) {
      const statusStyle = e.status >= 500 ? C.risk : e.status >= 400 ? C.warn : C.ok;
      const tags = [
        e.isCross     ? '🌐 CROSS'     : '',
        e.isAPI       ? '🔌 API'       : '',
        e.isAuth      ? '🔒 AUTH'      : '',
        e.isAnalytics ? '📊 ANALYTICS' : '',
        e.isJSON      ? '📦 JSON'      : '',
        e.size > 0    ? `${(e.size / 1024).toFixed(1)}KB` : '',
        `${e.duration}ms`,
      ].filter(Boolean).join(' ');
      console.log(
        `%c${e.method} %c${e.status} %c${e.url.substring(0, 100)}%c ${tags}`,
        C.label, statusStyle, C.muted, C.info
      );
    },

    run() {
      console.groupCollapsed('%c🌐 Network Monitor', C.heading);
      log(C.ok, '✓ fetch() and XMLHttpRequest hooked — monitoring live requests');
      if (_state.requests.length) {
        const summary = {};
        _state.requests.forEach(r => { summary[r.url.substring(0, 80)] = `${r.method} ${r.status} ${r.duration}ms`; });
        table(summary);
      } else {
        log(C.info, 'ℹ No requests captured at scan time — hooks active for future requests');
      }
      console.groupEnd();
    },
  };

  // ─── Module: TokenAnalyzer ──────────────────────────────────────────────────
  const TokenAnalyzer = {
    init() {
      // Watch for live token rotation via MutationObserver
      const observer = new MutationObserver(throttle(mutations => {
        mutations.forEach(m => {
          if (m.type === 'attributes' && m.target instanceof HTMLInputElement && m.target.type === 'hidden') {
            const name   = m.target.name || m.target.id;
            const newVal = m.target.value;
            if (_state.tokens[name] !== undefined && _state.tokens[name] !== newVal) {
              log(C.warn, `🔄 Token rotated: [${name}] "${_state.tokens[name].substring(0, 20)}…" → "${newVal.substring(0, 20)}…"`);
              _state.tokens[name]      = newVal;
              _state.tokenEntropy[name] = shannonEntropy(newVal);
              _state.securitySignals.low.push(`Token rotation: ${name}`);
            }
          }
        });
      }, 200));
      observer.observe(document.body, { attributes: true, subtree: true, attributeFilter: ['value'] });
    },

    run() {
      console.groupCollapsed('%c🔑 Token Analyzer', C.heading);
      const hiddenInputs = document.querySelectorAll('input[type="hidden"]');
      const snapshot = {};
      hiddenInputs.forEach(inp => {
        const n       = inp.name || inp.id || '(unnamed)';
        snapshot[n]   = inp.value;
        const entropy = shannonEntropy(inp.value);
        _state.tokenEntropy[n] = entropy;
        if (/csrf|token|xsrf|viewstate|state|nonce|key|auth|_token/i.test(n)) {
          const classification = entropy > 3.5 ? '🔄 dynamic' : '⚠ static (low entropy)';
          log(C.warn, `⚠ Security token [${n}] — entropy: ${entropy.toFixed(2)} — ${classification}`);
          if (entropy <= 3.5) {
            _state.securitySignals.medium.push(`Static token field: ${n} (entropy ${entropy.toFixed(2)})`);
          }
        }
      });
      _state.tokens = snapshot;
      if (Object.keys(snapshot).length) {
        log(C.info, `ℹ ${Object.keys(snapshot).length} hidden input(s)`);
        table(Object.fromEntries(
          Object.entries(snapshot).map(([k, v]) => [k, `${v.substring(0, 50)} (entropy: ${(_state.tokenEntropy[k] || 0).toFixed(2)})`])
        ));
      } else {
        log(C.ok, '✓ No hidden inputs detected');
      }
      log(C.info, 'ℹ MutationObserver active — monitoring token rotation');
      console.groupEnd();
    },
  };

  // ─── Module: EventMapper ────────────────────────────────────────────────────
  const EventMapper = {
    init() {},

    run() {
      console.groupCollapsed('%c🗺 Event Mapper', C.heading);
      const forms    = document.querySelectorAll('form');
      const formRows = [];
      log(C.info, `ℹ Found ${forms.length} form(s)`);

      forms.forEach((form, i) => {
        const method  = (form.getAttribute('method') || '').toUpperCase();
        const action  = form.action || '(none)';
        const hasCSRF = !!form.querySelector('input[name*="csrf" i], input[name*="token" i], input[name*="xsrf" i]');
        const inlineH = ['onsubmit', 'onreset'].filter(h => form.getAttribute(h));
        const fields  = [...form.querySelectorAll('input,select,textarea')];
        const names   = fields.map(f => f.name).filter(Boolean);

        // Detect duplicated field names within a form
        const seen = {};
        names.forEach(n => { seen[n] = (seen[n] || 0) + 1; });
        const dupes = Object.entries(seen).filter(([, c]) => c > 1).map(([n]) => n);
        if (dupes.length) {
          log(C.warn, `⚠ Form #${i}: duplicated field names: ${dupes.join(', ')}`);
          _state.securitySignals.low.push(`Form #${i}: duplicated fields: ${dupes.join(', ')}`);
        }

        // GET form with sensitive-like fields
        if (method === 'GET') {
          const sensFields = fields.filter(f => SENSITIVE_FIELDS.some(s => (f.name || '').toLowerCase().includes(s)));
          if (sensFields.length) {
            log(C.risk, `🚨 Form #${i}: GET form with sensitive field(s): ${sensFields.map(f => f.name).join(', ')}`);
            _state.securitySignals.high.push(`GET form with sensitive fields: ${sensFields.map(f => f.name).join(', ')}`);
          }
        }

        // Missing method attribute
        if (!method) {
          log(C.warn, `⚠ Form #${i}: missing method attribute`);
          _state.securitySignals.low.push(`Form #${i}: missing method`);
        }

        // Numeric-only hidden fields (possible object ID exposure)
        const numericHidden = fields.filter(f => f.type === 'hidden' && /^\d+$/.test(f.value));
        if (numericHidden.length) {
          log(C.info, `ℹ Form #${i}: numeric-only hidden field(s): ${numericHidden.map(f => `${f.name}=${f.value}`).join(', ')}`);
        }

        // Object ID in action URL
        if (/\/\d+[/?]?/.test(action) || /[?&]id=\d+/i.test(action)) {
          log(C.warn, `⚠ Form #${i}: action URL may contain object ID: ${action}`);
          _state.securitySignals.low.push(`Form #${i}: object ID in action URL`);
        }

        formRows.push({
          '#':              i,
          method:           method || '⚠ MISSING',
          action:           action.substring(0, 60),
          'CSRF?':          hasCSRF ? '✓' : '✗',
          fields:           names.length,
          'inline-handler': inlineH.join(', ') || 'none',
        });
      });

      if (formRows.length) table(formRows);
      _state.formAnalysis = formRows;

      // Enumerate inline event handlers across the page
      const inlineAttrs  = ['onclick','onsubmit','onchange','oninput','onkeyup','onkeydown','onfocus','onblur','onload','onerror'];
      let   inlineCount  = 0;
      inlineAttrs.forEach(attr => {
        const els = document.querySelectorAll(`[${attr}]`);
        if (els.length) { inlineCount += els.length; log(C.warn, `⚠ ${els.length} element(s) with inline [${attr}]`); }
      });
      if (!inlineCount) log(C.ok, '✓ No inline JS event handlers detected');

      const buttons = document.querySelectorAll('button, input[type="submit"], input[type="button"]');
      log(C.info, `ℹ ${buttons.length} button/submit element(s)`);
      console.groupEnd();
    },
  };

  // ─── Module: StorageAnalyzer ─────────────────────────────────────────────────
  const StorageAnalyzer = {
    init() {},

    run() {
      console.groupCollapsed('%c🗄 Storage Analyzer', C.heading);

      const dumpStorage = (storage, label) => {
        const out = {};
        try {
          for (let i = 0; i < storage.length; i++) {
            const k = storage.key(i);
            out[k]  = storage.getItem(k);
          }
        } catch (e) { log(C.muted, `(${label} inaccessible: ${e.message})`); return; }
        if (!Object.keys(out).length) { log(C.ok, `✓ ${label}: empty`); return; }
        log(C.info, `ℹ ${label}: ${Object.keys(out).length} key(s)`);
        Object.entries(out).forEach(([k, v]) => {
          const isSens = SENSITIVE_KEYS.some(s => k.toLowerCase().includes(s) || (v && v.toLowerCase().includes(s)));
          if (isSens) {
            log(C.risk, `🚨 SENSITIVE [${label}] "${k}"`);
            _state.securitySignals.high.push(`Sensitive key in ${label}: ${k}`);
          }
        });
        table(Object.fromEntries(Object.entries(out).map(([k, v]) => [k, String(v).substring(0, 80)])));
      };
      dumpStorage(localStorage,   'localStorage');
      dumpStorage(sessionStorage, 'sessionStorage');

      // Cookie analysis: entropy estimation and sensitivity detection
      if (document.cookie) {
        const rawCookies = document.cookie.split(';').map(c => c.trim());
        _state.cookies = rawCookies.map(c => {
          const eqIdx = c.indexOf('=');
          const name  = eqIdx >= 0 ? c.substring(0, eqIdx).trim() : c.trim();
          const value = eqIdx >= 0 ? c.substring(eqIdx + 1) : '';
          return { name, value, entropy: shannonEntropy(value) };
        });
        log(C.info, `ℹ ${_state.cookies.length} cookie(s) accessible`);
        const rows = {};
        _state.cookies.forEach(({ name, value, entropy }) => {
          const isSens = SENSITIVE_KEYS.some(s => name.toLowerCase().includes(s));
          rows[name]   = `${value.substring(0, 50)} | entropy: ${entropy.toFixed(2)}${isSens ? ' ⚠ SENSITIVE' : ''}`;
          if (isSens)      _state.securitySignals.medium.push(`Sensitive cookie name: ${name}`);
          if (entropy > 4.5) _state.securitySignals.low.push(`High-entropy cookie: ${name} (${entropy.toFixed(2)})`);
        });
        table(rows);
      } else {
        log(C.ok, '✓ No accessible cookies');
      }
      console.groupEnd();
    },
  };

  // ─── Module: ScriptAnalyzer ──────────────────────────────────────────────────
  const ScriptAnalyzer = {
    init() {},

    run() {
      console.groupCollapsed('%c📜 Script Analyzer', C.heading);
      const pageOrigin      = location.origin;
      const externalScripts = [...document.querySelectorAll('script[src]')];
      const inlineScripts   = [...document.querySelectorAll('script:not([src])')];
      const domainMap       = {};

      externalScripts.forEach(s => {
        try {
          const o = new URL(s.src, location.href).origin;
          if (!domainMap[o]) domainMap[o] = [];
          domainMap[o].push(s.src.substring(0, 80));
          if (o !== pageOrigin) {
            _state.thirdPartyDomains.add(o);
            // Classify third-party script origin
            const isCDN       = CDN_DOMAINS.some(d => o.includes(d));
            const isAnalytics = ANALYTICS_DOMAINS.some(d => o.includes(d));
            if (!isCDN && !isAnalytics) {
              _state.securitySignals.medium.push(`Unknown third-party script: ${o}`);
            }
          }
        } catch (_) {}
      });

      log(C.info, `ℹ ${externalScripts.length} external script(s) across ${Object.keys(domainMap).length} domain(s)`);
      if (Object.keys(domainMap).length) {
        table(Object.fromEntries(Object.entries(domainMap).map(([d, s]) => {
          const tag = CDN_DOMAINS.some(c => d.includes(c)) ? '[CDN]'
                    : ANALYTICS_DOMAINS.some(a => d.includes(a)) ? '[ANALYTICS]'
                    : d === location.origin ? '[FIRST-PARTY]'
                    : '[THIRD-PARTY ⚠]';
          return [d, `${s.length} script(s) ${tag}`];
        })));
      }

      // Detect known JS libraries
      const detected = Object.entries(KNOWN_LIBS)
        .filter(([, fn]) => { try { return fn(); } catch { return false; } })
        .map(([n]) => n);
      if (detected.length) log(C.info,  `ℹ Detected libraries: ${detected.join(', ')}`);
      else                 log(C.muted, 'No common libraries detected');

      // Detect inline eval() usage via string matching.
      // Note: this may produce false positives for occurrences inside comments or string literals.
      let evalCount = 0;
      inlineScripts.forEach(s => { if (s.textContent.includes('eval(')) evalCount++; });
      if (evalCount) {
        log(C.risk, `🚨 ${evalCount} inline script(s) containing eval()`);
        _state.securitySignals.high.push(`${evalCount} inline script(s) with eval()`);
      } else {
        log(C.ok, `✓ No inline eval() found (${inlineScripts.length} inline scripts)`);
      }

      // Scripts missing Subresource Integrity
      const noSRI = externalScripts.filter(s => !s.integrity);
      if (noSRI.length) {
        log(C.warn, `⚠ ${noSRI.length} external script(s) without SRI integrity attribute`);
        _state.securitySignals.medium.push(`${noSRI.length} scripts without SRI`);
      }
      console.groupEnd();
    },
  };

  // ─── Module: SecuritySignals ─────────────────────────────────────────────────
  const SecuritySignals = {
    init() {},

    run() {
      console.groupCollapsed('%c🚨 Security Signals', C.heading);

      // Iframe embedding detection
      if (window.self !== window.top) {
        log(C.risk, '🚨 Page running inside an iframe');
        _state.securitySignals.high.push('Page inside iframe');
      } else {
        log(C.ok, '✓ Not inside an iframe');
      }

      // Mixed content on HTTPS pages
      if (location.protocol === 'https:') {
        const mixed = [...document.querySelectorAll('img[src^="http:"],script[src^="http:"],link[href^="http:"],iframe[src^="http:"]')];
        if (mixed.length) {
          log(C.risk, `🚨 ${mixed.length} mixed-content element(s) on HTTPS page`);
          _state.securitySignals.high.push(`Mixed content: ${mixed.length} element(s)`);
        } else {
          log(C.ok, '✓ No obvious mixed content');
        }
      }

      // Open redirect parameter patterns
      const redirectLinks = [...document.querySelectorAll('a[href]')].filter(a => {
        const h = a.getAttribute('href');
        return h && /[?&](url|redirect|return|next|goto|dest|destination)=/i.test(h);
      });
      if (redirectLinks.length) {
        log(C.warn, `⚠ ${redirectLinks.length} link(s) with open redirect parameter`);
        redirectLinks.slice(0, 3).forEach(a => log(C.muted, '  → ' + a.href));
        _state.securitySignals.medium.push(`Open redirect patterns: ${redirectLinks.length}`);
      } else {
        log(C.ok, '✓ No open redirect patterns');
      }

      // Inputs missing type attribute
      const untyped = document.querySelectorAll('input:not([type])');
      if (untyped.length) {
        log(C.warn, `⚠ ${untyped.length} input(s) without type attribute`);
        _state.securitySignals.low.push(`${untyped.length} untyped inputs`);
      }

      // Password fields missing explicit autocomplete
      const pwFields = document.querySelectorAll('input[type="password"]');
      pwFields.forEach(pw => {
        const ac = pw.getAttribute('autocomplete');
        if (!ac || ac === 'on') {
          log(C.warn, `⚠ Password field without explicit autocomplete: name="${pw.name}"`);
          _state.securitySignals.medium.push(`Password field missing autocomplete: ${pw.name}`);
        }
      });
      if (!pwFields.length) log(C.ok, '✓ No password fields detected');

      // POST/PUT/DELETE forms without CSRF-like token
      document.querySelectorAll('form').forEach((form, i) => {
        const method = (form.getAttribute('method') || '').toUpperCase();
        if (['POST', 'PUT', 'DELETE'].includes(method)) {
          const hasCSRF = !!form.querySelector('input[name*="csrf" i], input[name*="token" i], input[name*="xsrf" i], input[name*="nonce" i]');
          if (!hasCSRF) {
            log(C.risk, `🚨 Form #${i} (${method}) missing CSRF-like token field`);
            _state.securitySignals.high.push(`Form #${i}: ${method} without CSRF token`);
          }
        }
      });

      // Sensitive parameters in URL query string
      if (/[?&](token|key|password|secret|auth|jwt|api_key)=/i.test(location.search)) {
        log(C.risk, '🚨 Sensitive parameter in URL query string');
        _state.securitySignals.high.push('Sensitive data in URL');
      }

      // CSP meta tag presence
      const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
      log(cspMeta ? C.ok : C.warn, cspMeta ? '✓ CSP meta tag present' : '⚠ No CSP meta tag (may be set via HTTP header)');

      console.groupEnd();
    },
  };

  // ─── Module: PerformanceMonitor ──────────────────────────────────────────────
  const PerformanceMonitor = {
    init() {
      // Register long-task observer early to catch tasks during analysis
      if (typeof PerformanceObserver !== 'undefined' &&
          PerformanceObserver.supportedEntryTypes &&
          PerformanceObserver.supportedEntryTypes.includes('longtask')) {
        try {
          const po = new PerformanceObserver(list => {
            list.getEntries().forEach(entry => {
              log(C.warn, `⚠ Long task detected: ${entry.duration.toFixed(0)}ms`);
            });
          });
          po.observe({ entryTypes: ['longtask'] });
        } catch (_) {}
      }
    },

    run() {
      console.groupCollapsed('%c⚡ Performance Monitor', C.heading);
      const nodeCount = document.querySelectorAll('*').length;
      const nStyle    = nodeCount > 3000 ? C.risk : nodeCount > 1500 ? C.warn : C.ok;
      log(nStyle, `${nodeCount > 3000 ? '🚨' : nodeCount > 1500 ? '⚠' : '✓'} DOM node count: ${nodeCount}`);

      // Navigation timing via modern Performance API
      try {
        const [nav] = performance.getEntriesByType('navigation');
        if (nav) {
          const loadTime = +(nav.loadEventEnd - nav.startTime).toFixed(0);
          const lt = loadTime > 5000 ? C.risk : loadTime > 2000 ? C.warn : C.ok;
          log(lt, `${loadTime > 5000 ? '🚨' : loadTime > 2000 ? '⚠' : '✓'} Page load: ${loadTime}ms`);
        }
      } catch (_) {}

      const scriptCount = document.querySelectorAll('script').length;
      const styleCount  = document.querySelectorAll('link[rel="stylesheet"]').length;
      log(C.info, `ℹ Scripts: ${scriptCount} | Stylesheets: ${styleCount}`);

      const elapsed = (performance.now() - _state.startTime).toFixed(1);
      log(elapsed < 50 ? C.ok : C.warn, `${elapsed < 50 ? '✓' : '⚠'} Toolkit init: ${elapsed}ms`);
      console.groupEnd();
    },
  };

  // ─── Module: DOMAnalyzer ────────────────────────────────────────────────────
  const DOMAnalyzer = {
    init() {
      // Watch for dynamically injected script and iframe tags
      const observer = new MutationObserver(throttle(mutations => {
        mutations.forEach(m => {
          m.addedNodes.forEach(node => {
            if (node.nodeName === 'SCRIPT') {
              _state.scriptTagsAdded.push({ src: node.src || '(inline)', time: Date.now() });
              log(C.warn, `⚠ Dynamic script tag injected: ${node.src || '(inline)'}`);
              _state.securitySignals.medium.push(`Dynamic script injection: ${node.src || '(inline)'}`);
            }
            if (node.nodeName === 'IFRAME') {
              log(C.warn, `⚠ Dynamic iframe injected: src="${node.src || '(none)'}"`);
              _state.securitySignals.medium.push(`Dynamic iframe: ${node.src || '(none)'}`);
            }
          });
        });
      }, 100));
      observer.observe(document.documentElement, { childList: true, subtree: true });

      // Hook dangerous DOM sinks for observation (never blocks execution)
      DOMAnalyzer._hookSinks();
    },

    _hookSinks() {
      // innerHTML setter
      const _innerHTMLDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'innerHTML');
      if (_innerHTMLDesc && _innerHTMLDesc.set) {
        const _origSet = _innerHTMLDesc.set;
        Object.defineProperty(Element.prototype, 'innerHTML', {
          set(val) {
            _state.sinkInvocations.push({ sink: 'innerHTML', preview: String(val).substring(0, 80), time: Date.now() });
            if (/<script|on[a-z]+\s*=/i.test(val)) {
              log(C.risk, '🚨 innerHTML sink: dangerous HTML pattern in assigned value');
              _state.securitySignals.high.push('innerHTML: dangerous HTML pattern in value');
            }
            return _origSet.call(this, val);
          },
          get:          _innerHTMLDesc.get,
          configurable: true,
        });
      }

      // outerHTML setter
      const _outerHTMLDesc = Object.getOwnPropertyDescriptor(Element.prototype, 'outerHTML');
      if (_outerHTMLDesc && _outerHTMLDesc.set) {
        const _origSet = _outerHTMLDesc.set;
        Object.defineProperty(Element.prototype, 'outerHTML', {
          set(val) {
            _state.sinkInvocations.push({ sink: 'outerHTML', preview: String(val).substring(0, 80), time: Date.now() });
            return _origSet.call(this, val);
          },
          get:          _outerHTMLDesc.get,
          configurable: true,
        });
      }

      // insertAdjacentHTML
      const _iahOrig = Element.prototype.insertAdjacentHTML;
      Element.prototype.insertAdjacentHTML = function (position, html) {
        _state.sinkInvocations.push({ sink: 'insertAdjacentHTML', preview: String(html).substring(0, 80), time: Date.now() });
        return _iahOrig.call(this, position, html);
      };

      // document.write — observe, still allow
      const _dwrite = document.write.bind(document);
      document.write = function (...args) {
        _state.sinkInvocations.push({ sink: 'document.write', preview: String(args[0] || '').substring(0, 80), time: Date.now() });
        log(C.warn, '⚠ document.write() called');
        _state.securitySignals.medium.push('document.write() called');
        return _dwrite.apply(document, args);
      };

      // eval — observe, still allow
      const _evalOrig = window.eval;
      window.eval = function (code) {
        _state.sinkInvocations.push({ sink: 'eval', preview: String(code).substring(0, 80), time: Date.now() });
        log(C.risk, `🚨 eval() called: "${String(code).substring(0, 60)}"`);
        _state.securitySignals.high.push(`eval() called: ${String(code).substring(0, 60)}`);
        return _evalOrig.call(this, code);
      };

      // new Function — observe, still allow
      const _FuncOrig = window.Function;
      window.Function = function (...args) {
        _state.sinkInvocations.push({ sink: 'new Function', preview: String(args[args.length - 1] || '').substring(0, 80), time: Date.now() });
        log(C.risk, '🚨 new Function() called');
        _state.securitySignals.high.push('new Function() called');
        return new _FuncOrig(...args);
      };
      window.Function.prototype = _FuncOrig.prototype;
    },

    run() {
      console.groupCollapsed('%c🧩 DOM Analyzer', C.heading);
      const allNodes         = document.querySelectorAll('*');
      const nodeCount        = allNodes.length;
      const iframes          = document.querySelectorAll('iframe');
      const inlineStyleNodes = document.querySelectorAll('[style]');

      // Detect nodes with excessive child elements
      const heavyNodes = [...allNodes].filter(n => n.childElementCount > 50);
      if (heavyNodes.length) {
        log(C.warn, `⚠ ${heavyNodes.length} element(s) with >50 children`);
        _state.securitySignals.low.push(`${heavyNodes.length} heavy DOM nodes (>50 children)`);
      }

      // Estimate maximum DOM depth by sampling up to 200 nodes.
      // Sampling keeps this O(k·d) instead of O(n·d) for large DOMs;
      // the first 200 nodes in DOM order typically cover the significant depth range.
      let maxDepth = 0;
      [...allNodes].slice(0, 200).forEach(n => {
        let depth = 0, el = n;
        while (el.parentElement) { depth++; el = el.parentElement; }
        if (depth > maxDepth) maxDepth = depth;
      });

      // DOM entropy: Shannon entropy of tag-name frequency distribution
      const tagFreq  = {};
      const total    = nodeCount || 1;
      allNodes.forEach(n => { tagFreq[n.tagName] = (tagFreq[n.tagName] || 0) + 1; });
      const domEntropy = -Object.values(tagFreq).reduce((s, f) => {
        const p = f / total;
        return s + p * Math.log2(p);
      }, 0);

      _state.domScore = +domEntropy.toFixed(2);
      _state.domStats = {
        nodeCount,
        iframes:      iframes.length,
        inlineStyles: inlineStyleNodes.length,
        maxDepth,
        tagVariety:   Object.keys(tagFreq).length,
        domEntropy:   _state.domScore,
      };
      table(_state.domStats);

      if (iframes.length) {
        log(C.warn, `⚠ ${iframes.length} iframe(s) present`);
        _state.securitySignals.low.push(`${iframes.length} iframe(s) on page`);
      }

      if (_state.sinkInvocations.length) {
        log(C.warn, `⚠ ${_state.sinkInvocations.length} DOM sink invocation(s) detected`);
        table(_state.sinkInvocations.slice(0, 10).reduce((acc, s, i) => { acc[i] = `[${s.sink}] ${s.preview}`; return acc; }, {}));
      } else {
        log(C.ok, '✓ No DOM sink invocations at scan time');
      }
      console.groupEnd();
    },
  };

  // ─── Module: WebSocketMonitor ────────────────────────────────────────────────
  const WebSocketMonitor = {
    init() {
      if (typeof WebSocket === 'undefined') return;
      const _WS  = window.WebSocket;
      const self = this;

      window.WebSocket = function (url, protocols) {
        const ws    = protocols ? new _WS(url, protocols) : new _WS(url);
        const entry = { url, protocols: protocols || [], messageCount: 0, messages: [], opened: false, closed: false };
        _state.websocketConnections.push(entry);

        ws.addEventListener('open', () => {
          entry.opened = true;
          log(C.info, `ℹ WebSocket opened: ${url}`);
          if (url.startsWith('ws://')) {
            log(C.risk, `🚨 Unencrypted WebSocket (ws://) connection: ${url}`);
            _state.securitySignals.high.push(`Unencrypted WebSocket: ${url}`);
          } else {
            _state.securitySignals.low.push(`WebSocket connection: ${url}`);
          }
        });

        ws.addEventListener('message', evt => {
          entry.messageCount++;
          const preview = typeof evt.data === 'string' ? evt.data.substring(0, 100) : '[binary]';
          entry.messages.push({ direction: 'recv', preview, time: Date.now() });
          if (entry.messageCount <= 3) log(C.muted, `  ← WS recv [${url.substring(0, 50)}]: ${preview}`);
          if (typeof evt.data === 'string' && SENSITIVE_KEYS.some(k => evt.data.toLowerCase().includes(k))) {
            log(C.warn, `⚠ Potentially sensitive data in WebSocket message from ${url.substring(0, 60)}`);
            _state.securitySignals.medium.push(`Sensitive keyword in WebSocket message: ${url}`);
          }
        });

        ws.addEventListener('close', () => { entry.closed = true; });

        const _origSend = ws.send.bind(ws);
        ws.send = function (data) {
          const preview = typeof data === 'string' ? data.substring(0, 100) : '[binary]';
          entry.messages.push({ direction: 'send', preview, time: Date.now() });
          const sendCount = entry.messages.filter(m => m.direction === 'send').length;
          if (sendCount <= 3) log(C.muted, `  → WS send [${url.substring(0, 50)}]: ${preview}`);
          return _origSend(data);
        };
        return ws;
      };
      window.WebSocket.prototype  = _WS.prototype;
      window.WebSocket.CONNECTING = _WS.CONNECTING;
      window.WebSocket.OPEN       = _WS.OPEN;
      window.WebSocket.CLOSING    = _WS.CLOSING;
      window.WebSocket.CLOSED     = _WS.CLOSED;
    },

    run() {
      console.groupCollapsed('%c🔌 WebSocket Monitor', C.heading);
      if (_state.websocketConnections.length) {
        log(C.info, `ℹ ${_state.websocketConnections.length} WebSocket connection(s) detected`);
        table(_state.websocketConnections.reduce((acc, c, i) => {
          acc[i] = `${c.url.substring(0, 80)} | msgs: ${c.messageCount} | open: ${c.opened} | closed: ${c.closed}`;
          return acc;
        }, {}));
      } else {
        log(C.ok, '✓ No WebSocket connections detected — constructor hooked for future connections');
      }
      console.groupEnd();
    },
  };

  // ─── Module: PostMessageMonitor ───────────────────────────────────────────────
  // Listens for 'message' events on window (the standard cross-frame messaging API).
  const PostMessageMonitor = {
    init() {
      window.addEventListener('message', evt => {
        const dataStr  = typeof evt.data === 'string'
          ? evt.data
          : evt.data instanceof Object ? JSON.stringify(evt.data) : String(evt.data);
        const entry    = { origin: evt.origin, dataType: typeof evt.data, preview: dataStr.substring(0, 100), time: Date.now() };
        _state.postMessages.push(entry);
        const isCross  = evt.origin !== location.origin && evt.origin !== 'null';
        log(isCross ? C.warn : C.info, `${isCross ? '⚠' : 'ℹ'} postMessage from ${evt.origin}: ${entry.preview}`);
        if (isCross) {
          _state.securitySignals.medium.push(`Cross-origin postMessage from: ${evt.origin}`);
        }
        if (SENSITIVE_KEYS.some(k => dataStr.toLowerCase().includes(k))) {
          log(C.warn, `⚠ Potentially sensitive data in postMessage from ${evt.origin}`);
          _state.securitySignals.medium.push(`Sensitive keyword in postMessage from: ${evt.origin}`);
        }
      }, true);
    },

    run() {
      console.groupCollapsed('%c📨 postMessage Monitor', C.heading);
      if (_state.postMessages.length) {
        log(C.info, `ℹ ${_state.postMessages.length} postMessage(s) captured`);
        table(_state.postMessages.slice(0, 10).reduce((acc, m, i) => {
          acc[i] = `${m.origin} | ${m.preview}`;
          return acc;
        }, {}));
      } else {
        log(C.ok, '✓ No postMessage events captured — listener active for future messages');
      }
      console.groupEnd();
    },
  };

  // ─── Module: HeadersInspector ─────────────────────────────────────────────────
  const HeadersInspector = {
    _SECURITY_HEADERS: [
      'Content-Security-Policy',
      'X-Frame-Options',
      'X-Content-Type-Options',
      'Referrer-Policy',
      'Permissions-Policy',
      'Strict-Transport-Security',
    ],

    init() {},

    run() {
      console.groupCollapsed('%c🛡 Headers Inspector', C.heading);

      // Check meta http-equiv tags for security headers
      const found = {};
      document.querySelectorAll('meta[http-equiv]').forEach(m => {
        found[m.getAttribute('http-equiv').toLowerCase()] = m.getAttribute('content') || '';
      });

      this._SECURITY_HEADERS.forEach(h => {
        if (found[h.toLowerCase()] !== undefined) {
          log(C.ok, `✓ Meta security header present: ${h} = "${found[h.toLowerCase()].substring(0, 60)}"`);
        } else {
          log(C.warn, `⚠ Meta security header not in <meta>: ${h} (may be set via HTTP header)`);
          _state.securitySignals.low.push(`Security header absent from meta: ${h}`);
        }
      });

      // Transport security
      if (location.protocol === 'https:') {
        log(C.ok, '✓ Page loaded over HTTPS');
      } else {
        log(C.risk, '🚨 Page loaded over HTTP — transport not encrypted');
        _state.securitySignals.high.push('Page loaded over HTTP (no TLS)');
      }

      // Referrer-Policy via document.referrerPolicy
      const rp = document.referrerPolicy;
      if (rp) {
        const safe = ['no-referrer', 'same-origin', 'strict-origin', 'strict-origin-when-cross-origin'].includes(rp);
        log(safe ? C.ok : C.warn, `${safe ? '✓' : '⚠'} document.referrerPolicy = "${rp}"`);
        if (!safe) _state.securitySignals.low.push(`Loose referrer policy: ${rp}`);
      } else {
        log(C.warn, '⚠ No referrer policy detected');
        _state.securitySignals.low.push('No referrer policy detected');
      }

      // Report all found meta headers
      if (Object.keys(found).length) {
        log(C.info, `ℹ Meta http-equiv headers found: ${Object.keys(found).join(', ')}`);
      }
      console.groupEnd();
    },
  };

  // ─── Module: JWTAnalyzer ──────────────────────────────────────────────────────
  const JWTAnalyzer = {
    _jwtRe: /^[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*$/,

    _decode(token) {
      try {
        const parts = token.split('.');
        const b64   = s => JSON.parse(atob(s.replace(/-/g, '+').replace(/_/g, '/')));
        return { header: b64(parts[0]), payload: b64(parts[1]) };
      } catch (_) { return null; }
    },

    _check(value, source) {
      const v = (value || '').trim();
      if (!this._jwtRe.test(v)) return;
      const decoded = this._decode(v);
      if (!decoded) return;

      const alg    = decoded.header.alg || 'unknown';
      const entry  = { source, alg, sub: decoded.payload.sub || '', exp: decoded.payload.exp || null };
      _state.jwtFindings.push(entry);

      log(C.warn, `⚠ JWT detected in ${source}: alg=${alg}, sub="${entry.sub}"`);
      _state.securitySignals.medium.push(`JWT in ${source}: alg=${alg}`);

      if (alg === 'none') {
        log(C.risk, `🚨 JWT with alg=none in ${source} — signature NOT verified!`);
        _state.securitySignals.high.push(`JWT alg=none in ${source}`);
      }
      if (['HS256', 'HS384', 'HS512'].includes(alg)) {
        log(C.info, `ℹ JWT uses symmetric algorithm (${alg}) in ${source}`);
      }

      if (decoded.payload.exp) {
        const expiry   = new Date(decoded.payload.exp * 1000);
        const expired  = expiry < new Date();
        log(expired ? C.risk : C.ok, `${expired ? '🚨 Expired' : '✓ Expires'}: ${expiry.toISOString()} (${source})`);
        if (expired) _state.securitySignals.medium.push(`Expired JWT in ${source}`);
      }
    },

    init() {},

    run() {
      console.groupCollapsed('%c🪪 JWT Analyzer', C.heading);
      let found = 0;

      try {
        for (let i = 0; i < localStorage.length; i++) {
          const k = localStorage.key(i), v = localStorage.getItem(k) || '';
          if (this._jwtRe.test(v.trim())) { this._check(v, `localStorage[${k}]`); found++; }
        }
      } catch (_) {}

      try {
        for (let i = 0; i < sessionStorage.length; i++) {
          const k = sessionStorage.key(i), v = sessionStorage.getItem(k) || '';
          if (this._jwtRe.test(v.trim())) { this._check(v, `sessionStorage[${k}]`); found++; }
        }
      } catch (_) {}

      document.cookie.split(';').forEach(c => {
        const idx = c.indexOf('=');
        if (idx < 0) return;
        const name = c.substring(0, idx).trim();
        const val  = c.substring(idx + 1).trim();
        if (this._jwtRe.test(val)) { this._check(val, `cookie[${name}]`); found++; }
      });

      // Scan meta content tags (some apps embed tokens there)
      document.querySelectorAll('meta[content]').forEach(m => {
        const v = (m.getAttribute('content') || '').trim();
        if (this._jwtRe.test(v)) { this._check(v, `meta[${m.name || m.getAttribute('http-equiv') || '?'}]`); found++; }
      });

      if (!found) log(C.ok, '✓ No JWT tokens detected in storage, cookies, or meta tags');
      console.groupEnd();
    },
  };

  // ─── Module: PrototypePollutionChecker ────────────────────────────────────────
  const PrototypePollutionChecker = {
    _SINKS: ['__proto__', 'constructor', 'prototype'],

    init() {},

    run() {
      console.groupCollapsed('%c☣ Prototype Pollution Checker', C.heading);

      // Detect unexpected enumerable own-properties on Object.prototype
      const polluted = [];
      for (const key in Object.prototype) {
        if (Object.prototype.hasOwnProperty.call(Object.prototype, key)) polluted.push(key);
      }
      if (polluted.length) {
        log(C.risk, `🚨 Object.prototype polluted — unexpected own properties: ${polluted.join(', ')}`);
        _state.securitySignals.high.push(`Object.prototype pollution: ${polluted.join(', ')}`);
      } else {
        log(C.ok, '✓ Object.prototype appears clean');
      }

      // Check URL query parameters for prototype pollution payloads
      let urlPollution = false;
      try {
        const params = new URLSearchParams(location.search);
        for (const [key] of params) {
          if (this._SINKS.some(s => key.includes(s)) || /\[__proto__\]|\[constructor\]|\[prototype\]/.test(key)) {
            log(C.risk, `🚨 Prototype pollution payload in URL param: ${key}`);
            _state.securitySignals.high.push(`Prototype pollution in URL: ${key}`);
            urlPollution = true;
          }
        }
      } catch (_) {}
      if (!urlPollution) log(C.ok, '✓ No prototype pollution patterns in URL query string');

      // Check URL fragment
      if (this._SINKS.some(s => location.hash.includes(s))) {
        log(C.warn, '⚠ Prototype pollution pattern in URL fragment');
        _state.securitySignals.medium.push('Prototype pollution pattern in URL hash');
      }

      // Scan inline scripts for prototype pollution assignment patterns
      let scriptPollution = 0;
      document.querySelectorAll('script:not([src])').forEach(s => {
        if (/\.__proto__\s*=|\[['"]__proto__['"]\]\s*=|Object\.prototype\.[a-zA-Z_]+\s*=/.test(s.textContent)) {
          scriptPollution++;
        }
      });
      if (scriptPollution) {
        log(C.risk, `🚨 ${scriptPollution} inline script(s) contain prototype mutation patterns`);
        _state.securitySignals.high.push(`Prototype mutation in ${scriptPollution} inline script(s)`);
      } else {
        log(C.ok, '✓ No prototype mutation patterns in inline scripts');
      }

      console.groupEnd();
    },
  };

  // ─── Module: ServiceWorkerInspector ──────────────────────────────────────────
  const ServiceWorkerInspector = {
    init() {},

    run() {
      console.groupCollapsed('%c👷 Service Worker Inspector', C.heading);
      if (!('serviceWorker' in navigator)) {
        log(C.muted, 'Service Worker API not available in this context');
        console.groupEnd();
        return;
      }
      navigator.serviceWorker.getRegistrations().then(regs => {
        _state.serviceWorkers = regs.map(r => ({
          scope:  r.scope,
          state:  r.active ? r.active.state : 'inactive',
          script: r.active ? r.active.scriptURL : (r.installing ? r.installing.scriptURL : '(unknown)'),
        }));
        if (!regs.length) {
          log(C.ok, '✓ No service workers registered');
        } else {
          log(C.info, `ℹ ${regs.length} service worker(s) registered`);
          table(_state.serviceWorkers.reduce((acc, sw, i) => {
            acc[`SW #${i}`] = `scope=${sw.scope} | state=${sw.state} | script=${sw.script.substring(0, 80)}`;
            return acc;
          }, {}));
          regs.forEach((reg, i) => {
            const script = _state.serviceWorkers[i].script;
            _state.securitySignals.low.push(`Service Worker registered: scope=${reg.scope}`);
            try {
              if (new URL(script).origin !== location.origin) {
                log(C.risk, `🚨 Service Worker script from foreign origin: ${script}`);
                _state.securitySignals.high.push(`Cross-origin service worker: ${script}`);
              }
            } catch (_) {}
          });
        }
      }).catch(e => log(C.muted, `(Service Worker query failed: ${e.message})`));
      console.groupEnd();
    },
  };

  // ─── Module: PermissionInspector ─────────────────────────────────────────────
  const PermissionInspector = {
    _HIGH_RISK: ['geolocation', 'camera', 'microphone'],
    _ALL:       ['geolocation', 'notifications', 'camera', 'microphone', 'clipboard-read', 'clipboard-write', 'persistent-storage', 'payment-handler'],

    init() {},

    run() {
      console.groupCollapsed('%c🔏 Permission Inspector', C.heading);
      if (!navigator.permissions || !navigator.permissions.query) {
        log(C.muted, 'Permissions API not available in this context');
        console.groupEnd();
        return;
      }
      const checks = this._ALL.map(name =>
        navigator.permissions.query({ name }).then(r => ({ name, state: r.state })).catch(() => ({ name, state: 'unsupported' }))
      );
      Promise.all(checks).then(results => {
        _state.permissions = results;
        const rows = {};
        results.forEach(r => {
          const icon = r.state === 'granted' ? '🟢' : r.state === 'denied' ? '🔴' : r.state === 'prompt' ? '🟡' : '⬛';
          rows[r.name] = `${icon} ${r.state}`;
        });
        table(rows);

        const granted = results.filter(r => r.state === 'granted');
        if (granted.length) {
          granted.forEach(r => {
            if (this._HIGH_RISK.includes(r.name)) {
              log(C.risk, `🚨 Sensitive permission GRANTED: ${r.name}`);
              _state.securitySignals.high.push(`Sensitive permission granted: ${r.name}`);
            } else {
              log(C.warn, `⚠ Permission granted: ${r.name}`);
              _state.securitySignals.medium.push(`Permission granted: ${r.name}`);
            }
          });
        } else {
          log(C.ok, '✓ No sensitive permissions currently granted');
        }
      });
      console.groupEnd();
    },
  };

  // ─── Module: SensitiveDOMScanner ─────────────────────────────────────────────
  const SensitiveDOMScanner = {
    _PII: [
      // Pattern-based detection — may produce false positives; verify matches manually.
      { name: 'Credit Card',  re: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b/ },
      { name: 'Email',        re: /\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b/ },
      { name: 'US SSN',       re: /\b\d{3}-\d{2}-\d{4}\b/ },
      { name: 'AWS Key',      re: /\bAKIA[0-9A-Z]{16}\b/ },
      { name: 'JWT Token',    re: /eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*/ },
      { name: 'Private Key',  re: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/ },
      // RFC-1918 private ranges only; octet bounds are not individually validated.
      { name: 'Private IPv4', re: /\b(?:10|172\.(?:1[6-9]|2\d|3[01])|192\.168)\.\d{1,3}\.\d{1,3}\b/ },
    ],

    init() {},

    run() {
      console.groupCollapsed('%c🔎 Sensitive DOM Scanner', C.heading);
      const findings = {};
      const MAX      = 2000;
      const walker   = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT, null);
      let node, scanned = 0;

      while ((node = walker.nextNode()) && scanned < MAX) {
        const text = (node.nodeValue || '').trim();
        if (!text) continue;
        scanned++;
        this._PII.forEach(({ name, re }) => {
          if (re.test(text)) findings[name] = (findings[name] || 0) + 1;
        });
      }

      _state.piiFindings = findings;

      if (Object.keys(findings).length) {
        log(C.risk, '🚨 Potential PII / sensitive data found in visible DOM text:');
        table(Object.fromEntries(Object.entries(findings).map(([k, v]) => [k, `${v} occurrence(s)`])));
        Object.keys(findings).forEach(name => {
          if (!_state.securitySignals.high.some(s => s.includes(name))) {
            _state.securitySignals.high.push(`PII in DOM text: ${name}`);
          }
        });
      } else {
        log(C.ok, `✓ No PII patterns detected in DOM text (${scanned} text nodes scanned)`);
      }
      console.groupEnd();
    },
  };

  // ─── Security Scoring Engine ─────────────────────────────────────────────────
  function computeRiskScore() {
    const high   = _state.securitySignals.high.length;
    const medium = _state.securitySignals.medium.length;
    const low    = _state.securitySignals.low.length;
    // Weighted sum: high=10, medium=4, low=1 — capped at 100
    const score  = Math.min(100, high * 10 + medium * 4 + low * 1);
    _state.riskScore = score;
    return { high, medium, low, score };
  }

  function riskLabel(score) {
    if (score >= 60) return { label: 'HIGH ATTACK SURFACE', style: C.risk };
    if (score >= 25) return { label: 'MODERATE SURFACE',    style: C.warn };
    return               { label: 'MINIMAL RISK',           style: C.ok   };
  }

  // ─── Live Dashboard Output ───────────────────────────────────────────────────
  function printDashboard() {
    const { high, medium, low, score } = computeRiskScore();
    const { label, style }             = riskLabel(score);

    console.group('%c📋 Executive Summary', C.heading);
    table({
      'Target URL':            location.href.substring(0, 80),
      'Total Endpoints':       _state.apiEndpoints.size,
      'Requests Captured':     _state.requests.length,
      'Token Fields':          Object.keys(_state.tokens).length,
      'Third-Party Domains':   _state.thirdPartyDomains.size,
      'DOM Sink Invocations':  _state.sinkInvocations.length,
      'Dynamic Scripts Added': _state.scriptTagsAdded.length,
      'WebSocket Connections': _state.websocketConnections.length,
      'postMessages Captured': _state.postMessages.length,
      'JWTs Detected':         _state.jwtFindings.length,
      'PII Types in DOM':      Object.keys(_state.piiFindings).length,
      'Signals — High':        high,
      'Signals — Medium':      medium,
      'Signals — Low':         low,
    });

    log(C.score, `🎯 Risk Score: ${score}/100 — ${label}`);

    if (high > 0) {
      log(C.risk, '🚨 High-risk signals:');
      _state.securitySignals.high.forEach(s => log(C.risk, `   ✗ ${s}`));
    }
    if (medium > 0) {
      log(C.warn, '⚠ Medium-risk signals:');
      _state.securitySignals.medium.forEach(s => log(C.warn, `   ⚠ ${s}`));
    }
    if (low > 0) {
      log(C.muted, 'Low-risk signals:');
      _state.securitySignals.low.forEach(s => log(C.muted, `   · ${s}`));
    }

    if (_state.thirdPartyDomains.size) {
      log(C.info, `ℹ Third-party domains: ${[..._state.thirdPartyDomains].join(', ')}`);
    }

    log(style, `✅ Classification: ${label}`);
    console.log('%c Runtime inspection active. Network + WebSocket + postMessage hooks live. Use window.Toolkit.exportReport() for full JSON export. ', C.banner);
    console.groupEnd();
  }

  // ─── Central Toolkit Object ──────────────────────────────────────────────────
  const modules = [
    Core,
    NetworkMonitor,
    TokenAnalyzer,
    EventMapper,
    StorageAnalyzer,
    ScriptAnalyzer,
    SecuritySignals,
    PerformanceMonitor,
    DOMAnalyzer,
    WebSocketMonitor,
    PostMessageMonitor,
    HeadersInspector,
    JWTAnalyzer,
    PrototypePollutionChecker,
    ServiceWorkerInspector,
    PermissionInspector,
    SensitiveDOMScanner,
  ];

  window.Toolkit = {
    version: '4.0',
    state:   _state,

    /** Returns a full JSON-serialisable analysis report. */
    exportReport() {
      return {
        version:              this.version,
        timestamp:            new Date().toISOString(),
        target:               location.href,
        riskScore:            _state.riskScore,
        riskLabel:            riskLabel(_state.riskScore).label,
        signals: {
          high:   _state.securitySignals.high,
          medium: _state.securitySignals.medium,
          low:    _state.securitySignals.low,
        },
        endpoints:            [..._state.apiEndpoints],
        thirdPartyDomains:    [..._state.thirdPartyDomains],
        requests:             _state.requests.map(r => ({ method: r.method, url: r.url, status: r.status, duration: r.duration, size: r.size })),
        // Token values are redacted; only entropy metadata is exported
        tokens:               Object.fromEntries(Object.entries(_state.tokens).map(([k]) => [k, `(redacted) entropy: ${(_state.tokenEntropy[k] || 0).toFixed(2)}`])),
        cookies:              _state.cookies.map(c => ({ name: c.name, entropy: c.entropy })),
        domStats:             _state.domStats,
        sinkInvocations:      _state.sinkInvocations,
        formAnalysis:         _state.formAnalysis,
        scriptTagsAdded:      _state.scriptTagsAdded,
        websocketConnections: _state.websocketConnections.map(c => ({ url: c.url, messageCount: c.messageCount, opened: c.opened, closed: c.closed })),
        postMessages:         _state.postMessages,
        jwtFindings:          _state.jwtFindings,
        serviceWorkers:       _state.serviceWorkers,
        permissions:          _state.permissions,
        piiFindings:          _state.piiFindings,
      };
    },
  };

  // ─── Bootstrap ───────────────────────────────────────────────────────────────
  function bootstrap() {
    // init phase: install hooks and observers synchronously (must run early)
    modules.forEach(m => { try { m.init(); } catch (e) { console.warn('[Toolkit] init error:', e); } });

    // run phase: analysis and reporting deferred to avoid blocking the UI
    const runAll = () => {
      modules.forEach(m => { try { m.run(); } catch (e) { console.warn('[Toolkit] run error:', e); } });
      printDashboard();
      _state.reportReady = true;
    };

    if (typeof requestIdleCallback !== 'undefined') {
      requestIdleCallback(runAll, { timeout: 2000 }); // 2 s fallback ensures analysis runs even on heavily loaded pages
    } else {
      setTimeout(runAll, 0);
    }
  }

  bootstrap();

})();
