// Content script: inspects the page's DOM.
//
//  * Reports page facts (is there a password field?) so the page itself can be
//    scored with that context, and shows a warning banner on dangerous pages.
//  * Scores every link on the page, outlines risky ones, explains why on hover,
//    and asks for confirmation before following a dangerous link.
//
// All UI lives in a closed shadow root so page CSS cannot restyle or hide it.

(() => {
  const api = globalThis.browser ?? globalThis.chrome;
  if (window.__phishGuardLoaded) return;
  window.__phishGuardLoaded = true;

  const ATTR = 'data-phishguard';
  const linkIds = new WeakMap();
  const linkResults = new Map(); // id -> result
  let nextId = 1;

  // ---------------------------------------------------------------------------
  // UI host (shadow DOM)
  // ---------------------------------------------------------------------------

  const host = document.createElement('phishguard-ui');
  host.style.cssText = 'all: initial; position: fixed; top: 0; left: 0; z-index: 2147483647;';
  const root = host.attachShadow({ mode: 'closed' });
  root.innerHTML = `
    <style>
      :host { all: initial; }
      * { box-sizing: border-box; font-family: system-ui, -apple-system, "Segoe UI", sans-serif; }
      .banner { position: fixed; top: 0; left: 0; right: 0; display: flex; gap: 12px; align-items: center;
        padding: 10px 16px; background: #b3261e; color: #fff; font-size: 14px; line-height: 1.4;
        box-shadow: 0 2px 8px rgba(0,0,0,.3); }
      .banner strong { font-weight: 700; }
      .banner .reasons { opacity: .9; }
      .banner button { margin-left: auto; flex: none; background: rgba(255,255,255,.15); color: #fff;
        border: 1px solid rgba(255,255,255,.5); border-radius: 6px; padding: 4px 10px; cursor: pointer; font-size: 13px; }
      .tip { position: fixed; max-width: 340px; padding: 8px 10px; border-radius: 8px; font-size: 12px; line-height: 1.4;
        background: #202124; color: #e8eaed; box-shadow: 0 4px 16px rgba(0,0,0,.35); pointer-events: none; }
      .tip .head { font-weight: 700; margin-bottom: 4px; }
      .tip .dangerous { color: #f28b82; } .tip .suspicious { color: #fdd663; }
      .tip ul { margin: 0; padding-left: 16px; }
      .modal-bg { position: fixed; inset: 0; background: rgba(0,0,0,.55); display: flex; align-items: center; justify-content: center; }
      .modal { width: min(440px, calc(100vw - 32px)); background: #fff; color: #202124; border-radius: 12px; padding: 20px;
        box-shadow: 0 12px 40px rgba(0,0,0,.4); font-size: 14px; line-height: 1.5; }
      .modal h2 { margin: 0 0 8px; font-size: 18px; color: #b3261e; }
      .modal code { word-break: break-all; background: #f1f3f4; padding: 2px 4px; border-radius: 4px; font-size: 12px; }
      .modal ul { padding-left: 18px; }
      .modal .actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 16px; }
      .modal button { border-radius: 6px; padding: 8px 14px; font-size: 14px; cursor: pointer; border: 1px solid #dadce0; background: #fff; color: #202124; }
      .modal button.primary { background: #1a73e8; border-color: #1a73e8; color: #fff; }
      [hidden] { display: none !important; }
    </style>
    <div class="banner" hidden></div>
    <div class="tip" hidden></div>
    <div class="modal-bg" hidden></div>`;
  const bannerEl = root.querySelector('.banner');
  const tipEl = root.querySelector('.tip');
  const modalEl = root.querySelector('.modal-bg');

  const mountUi = () => {
    if (!host.isConnected) (document.body ?? document.documentElement).appendChild(host);
  };

  const escapeHtml = (s) =>
    String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

  // ---------------------------------------------------------------------------
  // Page-level verdict
  // ---------------------------------------------------------------------------

  let reportedPasswordField = null;

  async function reportPageFacts() {
    if (window !== window.top) return; // only the top frame describes the page
    const hasPasswordField = Boolean(document.querySelector('input[type="password"]'));
    if (reportedPasswordField === hasPasswordField) return; // nothing new to say
    reportedPasswordField = hasPasswordField;

    const reply = await send({ type: 'page-facts', hasPasswordField });
    const analysis = reply?.analysis;
    if (reply?.warnOnDangerous && analysis?.verdict === 'dangerous') showBanner(analysis);
  }

  function showBanner(analysis) {
    const reasons = analysis.signals.slice(0, 3).map((s) => escapeHtml(s.title)).join(' · ');
    bannerEl.innerHTML = `
      <span>⚠️ <strong>Likely phishing page</strong> (risk ${analysis.score}/100). Don't enter passwords or payment details.
      <span class="reasons">${reasons}</span></span>
      <button type="button">Dismiss</button>`;
    bannerEl.querySelector('button').addEventListener('click', () => (bannerEl.hidden = true));
    bannerEl.hidden = false;
    mountUi();
  }

  // ---------------------------------------------------------------------------
  // Link scanning
  // ---------------------------------------------------------------------------

  const style = document.createElement('style');
  style.textContent = `
    a[${ATTR}="dangerous"] { outline: 2px solid #d93025 !important; outline-offset: 1px !important; border-radius: 2px; }
    a[${ATTR}="suspicious"] { outline: 2px dashed #f29900 !important; outline-offset: 1px !important; border-radius: 2px; }`;

  let pending = new Set();
  let flushTimer = null;

  function queueLinks(scope) {
    const anchors = [...(scope.matches?.('a[href]') ? [scope] : []), ...(scope.querySelectorAll?.('a[href]') ?? [])];
    for (const a of anchors) {
      if (linkIds.has(a)) continue;
      const href = a.href; // resolved absolute URL
      if (!/^(https?|data|javascript):/i.test(href)) continue;
      const id = nextId++;
      linkIds.set(a, id);
      pending.add(a);
    }
    if (pending.size && !flushTimer) flushTimer = setTimeout(flush, 300);
  }

  async function flush() {
    flushTimer = null;
    const batch = [...pending].slice(0, 400);
    batch.forEach((a) => pending.delete(a));
    if (pending.size) flushTimer = setTimeout(flush, 300);

    const links = batch.map((a) => ({
      id: linkIds.get(a),
      href: a.href,
      text: (a.textContent || '').trim().slice(0, 200),
    }));
    const reply = await send({ type: 'score-links', links });
    if (!reply?.results?.length) return;

    let marked = false;
    const byId = new Map(batch.map((a) => [linkIds.get(a), a]));
    for (const r of reply.results) {
      linkResults.set(r.id, r);
      if (r.verdict === 'dangerous' || r.verdict === 'suspicious') {
        byId.get(r.id)?.setAttribute(ATTR, r.verdict);
        marked = true;
      }
    }
    if (marked && !style.isConnected) (document.head ?? document.documentElement).appendChild(style);
  }

  // Hover tooltip explaining why a link was flagged.
  document.addEventListener('mouseover', (e) => {
    const a = e.target.closest?.(`a[${ATTR}]`);
    if (!a) return;
    const r = linkResults.get(linkIds.get(a));
    if (!r) return;
    tipEl.innerHTML = `
      <div class="head ${r.verdict}">${r.verdict === 'dangerous' ? 'Likely phishing link' : 'Suspicious link'} · ${r.score}/100</div>
      <div>Goes to <strong>${escapeHtml(r.registrable || a.href)}</strong></div>
      <ul>${r.signals.map((s) => `<li>${escapeHtml(s.title)}</li>`).join('')}</ul>`;
    const rect = a.getBoundingClientRect();
    tipEl.hidden = false;
    mountUi();
    const top = rect.bottom + 8 + tipEl.offsetHeight > window.innerHeight ? rect.top - tipEl.offsetHeight - 8 : rect.bottom + 8;
    tipEl.style.top = `${Math.max(8, top)}px`;
    tipEl.style.left = `${Math.min(Math.max(8, rect.left), window.innerWidth - tipEl.offsetWidth - 8)}px`;
  });
  document.addEventListener('mouseout', (e) => {
    if (e.target.closest?.(`a[${ATTR}]`)) tipEl.hidden = true;
  });

  // Confirm before following a dangerous link.
  document.addEventListener(
    'click',
    (e) => {
      const a = e.target.closest?.(`a[${ATTR}="dangerous"]`);
      if (!a || a.dataset.phishguardAllowed === '1') return;
      e.preventDefault();
      e.stopImmediatePropagation();
      confirmNavigation(a, linkResults.get(linkIds.get(a)));
    },
    true,
  );

  function confirmNavigation(a, r) {
    modalEl.innerHTML = `
      <div class="modal" role="alertdialog" aria-modal="true" aria-labelledby="pg-title">
        <h2 id="pg-title">This link looks like phishing</h2>
        <div>It goes to <code>${escapeHtml(a.href)}</code></div>
        <ul>${(r?.signals ?? []).map((s) => `<li><strong>${escapeHtml(s.title)}.</strong> ${escapeHtml(s.detail)}</li>`).join('')}</ul>
        <div class="actions">
          <button type="button" data-act="open">Open anyway</button>
          <button type="button" class="primary" data-act="cancel">Go back</button>
        </div>
      </div>`;
    modalEl.hidden = false;
    mountUi();
    modalEl.querySelector('[data-act="cancel"]').focus();
    modalEl.onclick = (ev) => {
      const act = ev.target.dataset?.act ?? (ev.target === modalEl ? 'cancel' : null);
      if (!act) return;
      modalEl.hidden = true;
      if (act === 'open') {
        a.dataset.phishguardAllowed = '1';
        a.click();
      }
    };
  }

  // ---------------------------------------------------------------------------
  // Plumbing
  // ---------------------------------------------------------------------------

  async function send(message) {
    try {
      return await api.runtime.sendMessage(message);
    } catch {
      return null; // extension reloaded or background unavailable
    }
  }

  let observerTimer = null;
  const observer = new MutationObserver((mutations) => {
    for (const m of mutations) for (const n of m.addedNodes) if (n.nodeType === 1) queueLinks(n);
    clearTimeout(observerTimer);
    observerTimer = setTimeout(reportPageFacts, 1000);
  });

  reportPageFacts();
  queueLinks(document);
  observer.observe(document.documentElement, { childList: true, subtree: true });
})();
