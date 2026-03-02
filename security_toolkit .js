(function () {
  'use strict';

  // ─── Palette ────────────────────────────────────────────────────────────────
  const C = {
    ok:      'color:#00e676;font-weight:bold',
    warn:    'color:#ffea00;font-weight:bold',
    risk:    'color:#ff1744;font-weight:bold',
    info:    'color:#40c4ff;font-weight:bold',
    muted:   'color:#90a4ae',
    heading: 'color:#e040fb;font-weight:bold;font-size:13px',
    label:   'color:#b0bec5;font-weight:bold',
    value:   'color:#ffffff',
    banner:  'color:#000;background:linear-gradient(90deg,#e040fb,#00b0ff);font-weight:bold;font-size:14px;padding:4px 10px;border-radius:4px',
  };

  const log   = (style, ...args) => console.log(`%c${args[0]}`, style, ...args.slice(1));
  const table = (data)           => data && Object.keys(data).length && console.table(data);

  // ─── State ───────────────────────────────────────────────────────────────────
  const state = {
    requests: [],
    tokens: {},
    securitySignals: [],
    thirdPartyDomains: new Set(),
    apiEndpoints: new Set(),
    startTime: performance.now(),
  };

  const API_PATTERNS      = [/\/api\//i, /\/auth\//i, /\/login/i, /\/logout/i, /\/submit/i, /\/token/i, /\/oauth/i, /\/graphql/i, /\/rest\//i, /\/v\d+\//i];
  const ANALYTICS_DOMAINS = ['google-analytics.com','googletagmanager.com','analytics.','segment.io','mixpanel.com','amplitude.com','hotjar.com','intercom.io','fullstory.com','heap.io','sentry.io','datadog','newrelic','bugsnag'];
  const SENSITIVE_KEYS    = ['token','auth','session','jwt','access','refresh','secret','password','passwd','apikey','api_key','bearer','credential','sid','ssid'];
  const KNOWN_LIBS        = {
    React:   () => !!(window.React || document.querySelector('[data-reactroot],[data-reactid]')),
    Angular: () => !!(window.angular || document.querySelector('[ng-app],[ng-controller],[_nghost],[ng-version]')),
    Vue:     () => !!(window.Vue || document.querySelector('[data-v-]')),
    jQuery:  () => !!window.jQuery,
    Next:    () => !!(window.__NEXT_DATA__ || window.next),
    Nuxt:    () => !!window.__NUXT__,
    Ember:   () => !!window.Ember,
    Svelte:  () => !!document.querySelector('[class*="svelte-"]'),
    Lodash:  () => !!window._,
    Axios:   () => !!window.axios,
    Moment:  () => !!window.moment,
  };

  // ─── 1. Network Monitoring ───────────────────────────────────────────────────
  function hookNetwork() {
    const pageOrigin = location.origin;

    // fetch
    const _fetch = window.fetch;
    window.fetch = function (...args) {
      const req = args[0];
      const url = req instanceof Request ? req.url : String(req);
      const opts = args[1] || {};
      const method = (opts.method || (req instanceof Request ? req.method : 'GET')).toUpperCase();

      return _fetch.apply(this, args).then(res => {
        const entry = buildRequestEntry(method, url, res.status, res.headers, pageOrigin);
        entry.size = parseInt(res.headers.get('content-length') || '0', 10);
        entry.contentType = res.headers.get('content-type') || '';
        entry.isJSON = /json/i.test(entry.contentType);
        state.requests.push(entry);
        logRequest(entry);
        return res;
      }).catch(err => { throw err; });
    };

    // XHR
    const _open = XMLHttpRequest.prototype.open;
    const _send = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function (method, url) {
      this._rm = method ? method.toUpperCase() : 'GET';
      this._ru = String(url);
      return _open.apply(this, arguments);
    };
    XMLHttpRequest.prototype.send = function () {
      this.addEventListener('load', () => {
        try {
          const entry = buildRequestEntry(this._rm, this._ru, this.status, null, pageOrigin);
          entry.size = (this.responseText || '').length;
          entry.contentType = this.getResponseHeader('content-type') || '';
          entry.isJSON = /json/i.test(entry.contentType);
          state.requests.push(entry);
          logRequest(entry);
        } catch (_) {}
      });
      return _send.apply(this, arguments);
    };
  }

  function buildRequestEntry(method, url, status, headers, pageOrigin) {
    let origin;
    try { origin = new URL(url).origin; } catch { origin = 'relative'; }
    const isCross     = origin !== 'relative' && origin !== pageOrigin;
    const isAPI       = API_PATTERNS.some(p => p.test(url));
    const isAnalytics = ANALYTICS_DOMAINS.some(d => url.includes(d));
    if (isAPI || isCross) state.apiEndpoints.add(url);
    if (isCross) state.thirdPartyDomains.add(origin);
    return { method, url, status, isCross, isAPI, isAnalytics, origin, size: 0, contentType: '', isJSON: false };
  }

  function logRequest(e) {
    const statusStyle = e.status >= 400 ? C.risk : e.status >= 300 ? C.warn : C.ok;
    const tags = [
      e.isCross     ? '🌐 CROSS-ORIGIN' : '',
      e.isAPI       ? '🔌 API'          : '',
      e.isAnalytics ? '📊 ANALYTICS'    : '',
      e.isJSON      ? '📦 JSON'         : '',
    ].filter(Boolean).join(' ');
    console.log(
      `%c${e.method} %c${e.status} %c${e.url}%c ${tags}`,
      C.label, statusStyle, C.muted, C.info
    );
  }

  // ─── 2. Token & Session Analysis ────────────────────────────────────────────
  function analyzeTokens() {
    console.group('%c🔑 Token & Session Analysis', C.heading);
    const hiddenInputs = document.querySelectorAll('input[type="hidden"]');
    const snapshot = {};
    hiddenInputs.forEach(inp => {
      const n = inp.name || inp.id || '(unnamed)';
      snapshot[n] = inp.value;
      if (/csrf|token|xsrf|viewstate|state|nonce|key|auth|_token/i.test(n)) {
        log(C.warn, `⚠ Possible security token: [${n}] = "${inp.value.substring(0,40)}${inp.value.length > 40 ? '…' : ''}"`);
      }
    });
    if (Object.keys(snapshot).length) {
      log(C.info, `ℹ ${Object.keys(snapshot).length} hidden input(s) found`);
      table(snapshot);
    } else {
      log(C.ok, '✓ No hidden inputs detected');
    }
    state.tokens = snapshot;

    // MutationObserver for token rotation
    const observer = new MutationObserver(mutations => {
      mutations.forEach(m => {
        if (m.type === 'attributes' && m.target.type === 'hidden') {
          const name = m.target.name || m.target.id;
          const newVal = m.target.value;
          if (state.tokens[name] !== undefined && state.tokens[name] !== newVal) {
            log(C.warn, `🔄 Token rotated: [${name}] old="${state.tokens[name].substring(0,20)}…" → new="${newVal.substring(0,20)}…"`);
            state.tokens[name] = newVal;
            state.securitySignals.push('Token rotation detected: ' + name);
          }
        }
      });
    });
    observer.observe(document.body, { attributes: true, subtree: true, attributeFilter: ['value'] });
    log(C.info, 'ℹ MutationObserver active — monitoring token changes');
    console.groupEnd();
  }

  // ─── 3. Event Surface Mapping ────────────────────────────────────────────────
  function mapEventSurface() {
    console.group('%c🗺 Event Surface Mapping', C.heading);
    const forms = document.querySelectorAll('form');
    log(C.info, `ℹ Found ${forms.length} form(s)`);
    const formData = [];
    forms.forEach((form, i) => {
      const method = (form.getAttribute('method') || '').toUpperCase();
      const action = form.action || '(none)';
      const hasCSRF = !!form.querySelector('input[name*="csrf" i], input[name*="token" i], input[name*="xsrf" i]');
      const inlineHandlers = ['onsubmit','onreset'].filter(h => form.getAttribute(h));
      if (!method) {
        state.securitySignals.push(`Form #${i} missing method attribute`);
        log(C.warn, `⚠ Form #${i}: missing method attribute — action="${action}"`);
      }
      formData.push({
        '#': i,
        method: method || '⚠ MISSING',
        action,
        'CSRF-like?': hasCSRF ? '✓' : '✗',
        'inline-handler': inlineHandlers.join(', ') || 'none',
      });
    });
    if (formData.length) table(formData);

    // Enumerate interactive elements with inline handlers
    const inlineHandlerAttrs = ['onclick','onsubmit','onchange','oninput','onkeyup','onkeydown','onfocus','onblur','onload','onerror'];
    let inlineCount = 0;
    inlineHandlerAttrs.forEach(attr => {
      const els = document.querySelectorAll(`[${attr}]`);
      if (els.length) {
        inlineCount += els.length;
        log(C.warn, `⚠ ${els.length} element(s) with inline [${attr}]`);
      }
    });
    if (inlineCount === 0) log(C.ok, '✓ No inline JS event handlers detected');

    // Buttons
    const buttons = document.querySelectorAll('button, input[type="submit"], input[type="button"]');
    log(C.info, `ℹ ${buttons.length} button/submit element(s) found`);
    console.groupEnd();
  }

  // ─── 4. Storage Analysis ────────────────────────────────────────────────────
  function analyzeStorage() {
    console.group('%c🗄 Storage Analysis', C.heading);
    const dumpStorage = (storage, label) => {
      const out = {};
      try {
        for (let i = 0; i < storage.length; i++) {
          const k = storage.key(i);
          out[k] = storage.getItem(k);
        }
      } catch (e) { log(C.muted, `(${label} inaccessible: ${e.message})`); return; }
      if (!Object.keys(out).length) { log(C.ok, `✓ ${label}: empty`); return; }
      log(C.info, `ℹ ${label}: ${Object.keys(out).length} key(s)`);
      Object.entries(out).forEach(([k, v]) => {
        const isSensitive = SENSITIVE_KEYS.some(s => k.toLowerCase().includes(s) || (v && v.toLowerCase().includes(s)));
        if (isSensitive) {
          log(C.risk, `🚨 SENSITIVE KEY [${label}] "${k}": "${String(v).substring(0,60)}…"`);
          state.securitySignals.push(`Sensitive key in ${label}: ${k}`);
        }
      });
      table(Object.fromEntries(Object.entries(out).map(([k,v]) => [k, String(v).substring(0,80)])));
    };
    dumpStorage(localStorage,   'localStorage');
    dumpStorage(sessionStorage, 'sessionStorage');

    // Cookies (names only)
    if (document.cookie) {
      const cookies = document.cookie.split(';').map(c => c.trim().split('=')[0]);
      log(C.info, `ℹ Cookies (names): ${cookies.join(', ')}`);
      const sensitiveCookies = cookies.filter(n => SENSITIVE_KEYS.some(s => n.toLowerCase().includes(s)));
      if (sensitiveCookies.length) {
        log(C.warn, `⚠ Possibly sensitive cookies: ${sensitiveCookies.join(', ')}`);
        state.securitySignals.push(`Sensitive cookie names: ${sensitiveCookies.join(', ')}`);
      }
    } else {
      log(C.ok, '✓ No accessible cookies');
    }
    console.groupEnd();
  }

  // ─── 5. Script Analysis ─────────────────────────────────────────────────────
  function analyzeScripts() {
    console.group('%c📜 Script Analysis', C.heading);
    const pageOrigin = location.origin;
    const externalScripts = [...document.querySelectorAll('script[src]')];
    const inlineScripts   = [...document.querySelectorAll('script:not([src])')];
    const domainMap = {};
    externalScripts.forEach(s => {
      try {
        const origin = new URL(s.src, location.href).origin;
        if (!domainMap[origin]) domainMap[origin] = [];
        domainMap[origin].push(s.src.substring(0, 80));
        if (origin !== pageOrigin) state.thirdPartyDomains.add(origin);
      } catch (_) {}
    });
    log(C.info, `ℹ ${externalScripts.length} external script(s) across ${Object.keys(domainMap).length} domain(s)`);
    table(Object.fromEntries(Object.entries(domainMap).map(([d,s]) => [d, `${s.length} script(s)`])));

    // Known libraries
    const detected = Object.entries(KNOWN_LIBS).filter(([,fn]) => { try { return fn(); } catch { return false; } }).map(([n]) => n);
    if (detected.length) log(C.info, `ℹ Detected libraries: ${detected.join(', ')}`);
    else log(C.muted, 'No common libraries detected');

    // Inline eval
    let evalCount = 0;
    inlineScripts.forEach(s => { if (s.textContent.includes('eval(')) evalCount++; });
    if (evalCount) {
      log(C.risk, `🚨 ${evalCount} inline script(s) containing eval()`);
      state.securitySignals.push(`${evalCount} inline script(s) with eval()`);
    } else {
      log(C.ok, `✓ No inline eval() found (${inlineScripts.length} inline scripts)`);
    }
    console.groupEnd();
  }

  // ─── 6. Security Signal Detection ───────────────────────────────────────────
  function detectSecuritySignals() {
    console.group('%c🚨 Security Signal Detection', C.heading);

    // iframe detection
    if (window.self !== window.top) {
      log(C.risk, '🚨 Page is running inside an iframe');
      state.securitySignals.push('Page inside iframe');
    } else {
      log(C.ok, '✓ Not inside an iframe');
    }

    // Mixed content
    if (location.protocol === 'https:') {
      const mixed = [...document.querySelectorAll('img[src^="http:"],script[src^="http:"],link[href^="http:"],iframe[src^="http:"]')];
      if (mixed.length) {
        log(C.risk, `🚨 ${mixed.length} potential mixed-content element(s) on HTTPS page`);
        state.securitySignals.push(`Mixed content: ${mixed.length} element(s)`);
      } else {
        log(C.ok, '✓ No obvious mixed content');
      }
    }

    // Open redirect patterns
    const redirectLinks = [...document.querySelectorAll('a[href]')].filter(a => {
      const h = a.getAttribute('href');
      return h && (/[?&](url|redirect|return|next|goto|dest|destination)=/i.test(h));
    });
    if (redirectLinks.length) {
      log(C.warn, `⚠ ${redirectLinks.length} link(s) with possible open redirect parameter`);
      redirectLinks.slice(0, 5).forEach(a => log(C.muted, '  → ' + a.href));
      state.securitySignals.push(`Open redirect patterns: ${redirectLinks.length}`);
    } else {
      log(C.ok, '✓ No open redirect patterns in links');
    }

    // Inputs without type
    const untyped = document.querySelectorAll('input:not([type])');
    if (untyped.length) {
      log(C.warn, `⚠ ${untyped.length} input(s) without type attribute`);
      state.securitySignals.push(`${untyped.length} inputs without type`);
    }

    // Password fields without autocomplete=off
    const pwFields = document.querySelectorAll('input[type="password"]');
    pwFields.forEach(pw => {
      if (!pw.getAttribute('autocomplete') || pw.getAttribute('autocomplete') === 'on') {
        log(C.warn, `⚠ Password field without autocomplete="off/current-password/new-password": name="${pw.name}"`);
        state.securitySignals.push('Password field missing autocomplete attribute');
      }
    });
    if (!pwFields.length) log(C.ok, '✓ No password fields detected');

    // Forms without CSRF-like fields
    document.querySelectorAll('form').forEach((form, i) => {
      const method = (form.getAttribute('method') || '').toUpperCase();
      if (method === 'POST' || method === 'PUT' || method === 'DELETE') {
        const hasCSRF = !!form.querySelector('input[name*="csrf" i], input[name*="token" i], input[name*="xsrf" i], input[name*="nonce" i]');
        if (!hasCSRF) {
          log(C.risk, `🚨 Form #${i} (${method}) has no CSRF-like hidden field`);
          state.securitySignals.push(`Form #${i}: POST without CSRF token`);
        }
      }
    });

    // Sensitive data in URL
    if (/[?&](token|key|password|secret|auth|jwt|api_key)=/i.test(location.search)) {
      log(C.risk, '🚨 Sensitive parameter detected in URL query string');
      state.securitySignals.push('Sensitive data in URL');
    }

    // Content-Security-Policy (meta tag)
    const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    if (!cspMeta) {
      log(C.warn, '⚠ No CSP meta tag found (may still be set via HTTP header)');
    } else {
      log(C.ok, '✓ CSP meta tag present');
    }

    console.groupEnd();
  }

  // ─── 7. Performance Insight ──────────────────────────────────────────────────
  function performanceInsight() {
    console.group('%c⚡ Performance Insight', C.heading);
    const nodeCount = document.querySelectorAll('*').length;
    const style = nodeCount > 3000 ? C.risk : nodeCount > 1500 ? C.warn : C.ok;
    log(style, `${nodeCount > 3000 ? '🚨' : nodeCount > 1500 ? '⚠' : '✓'} DOM node count: ${nodeCount}`);

    const timing = performance.timing || {};
    if (timing.loadEventEnd && timing.navigationStart) {
      const loadTime = timing.loadEventEnd - timing.navigationStart;
      const styleT = loadTime > 5000 ? C.risk : loadTime > 2000 ? C.warn : C.ok;
      log(styleT, `${loadTime > 5000 ? '🚨' : loadTime > 2000 ? '⚠' : '✓'} Page load time: ${loadTime}ms`);
    }

    const scriptCount = document.querySelectorAll('script').length;
    const styleCount  = document.querySelectorAll('link[rel="stylesheet"]').length;
    log(C.info, `ℹ Scripts: ${scriptCount} | Stylesheets: ${styleCount}`);

    // Long task observer (if supported)
    if (typeof PerformanceObserver !== 'undefined' && PerformanceObserver.supportedEntryTypes && PerformanceObserver.supportedEntryTypes.includes('longtask')) {
      try {
        const po = new PerformanceObserver(list => {
          list.getEntries().forEach(entry => {
            log(C.warn, `⚠ Long task: ${entry.duration.toFixed(0)}ms — attribution: ${entry.attribution.map(a => a.name).join(', ')}`);
          });
        });
        po.observe({ entryTypes: ['longtask'] });
        log(C.info, 'ℹ Long task observer active');
      } catch (_) {}
    }

    const elapsed = (performance.now() - state.startTime).toFixed(1);
    log(C.info, `ℹ Toolkit init took: ${elapsed}ms`);
    console.groupEnd();
  }

  // ─── 8. Final Summary ───────────────────────────────────────────────────────
  function printSummary() {
    console.group('%c📋 Final Summary', C.heading);
    const forms    = document.querySelectorAll('form').length;
    const signals  = state.securitySignals.length;
    const domains  = state.thirdPartyDomains.size;

    const summaryTable = {
      'Total forms':               forms,
      'Total endpoints observed':  state.apiEndpoints.size,
      'Total security signals':    signals,
      'Third-party script domains':domains,
      'Network requests hooked':   state.requests.length,
    };
    table(summaryTable);

    if (state.securitySignals.length) {
      log(C.risk, '🚨 Security Signals:');
      state.securitySignals.forEach(s => log(C.warn, `  ⚠ ${s}`));
    } else {
      log(C.ok, '✓ No security signals detected at page load');
    }

    if (domains) {
      log(C.info, `ℹ Third-party domains: ${[...state.thirdPartyDomains].join(', ')}`);
    }

    console.log('%c✅ Runtime inspection active. Network hooks live.', C.banner);
    console.groupEnd();
  }

  // ─── Main ────────────────────────────────────────────────────────────────────
  function main() {
    console.group('%c🔐 Browser Security Analysis Toolkit v2.0', C.banner);
    log(C.info, `ℹ Target: ${location.href}`);
    log(C.info, `ℹ Date:   ${new Date().toISOString()}`);
    log(C.muted, '──────────────────────────────────────────────────────────────');
    console.groupEnd();

    console.group('%c🌐 Runtime Network Monitoring', C.heading);
    hookNetwork();
    log(C.ok, '✓ fetch() and XMLHttpRequest hooked — monitoring live requests');
    console.groupEnd();

    try { analyzeTokens();        } catch (e) { console.warn('[Toolkit] Token analysis error:', e); }
    try { mapEventSurface();      } catch (e) { console.warn('[Toolkit] Event surface error:', e); }
    try { analyzeStorage();       } catch (e) { console.warn('[Toolkit] Storage analysis error:', e); }
    try { analyzeScripts();       } catch (e) { console.warn('[Toolkit] Script analysis error:', e); }
    try { detectSecuritySignals();} catch (e) { console.warn('[Toolkit] Signal detection error:', e); }
    try { performanceInsight();   } catch (e) { console.warn('[Toolkit] Performance insight error:', e); }
    try { printSummary();         } catch (e) { console.warn('[Toolkit] Summary error:', e); }
  }

  main();

})();
