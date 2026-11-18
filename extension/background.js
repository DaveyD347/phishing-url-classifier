// Background service worker (Chrome) / event page (Firefox).
//
// Responsibilities:
//  * score every top-level navigation and show the result on the toolbar badge
//  * answer scoring requests from the content script and popup
//  * optionally look up domain age over RDAP (off by default, see options)
//  * on Firefox, read TLS certificate state via webRequest.getSecurityInfo

import { analyzeUrl } from './engine/classifier.js';
import { splitHost, isIpAddress } from './engine/domain.js';
import { getSettings } from './lib/settings.js';
import { lookupDomainAgeDays } from './lib/rdap.js';

const api = globalThis.browser ?? globalThis.chrome;

const BADGE = {
  dangerous: { text: '!', color: '#d93025' },
  suspicious: { text: '?', color: '#f29900' },
  safe: { text: '', color: '#1e8e3e' },
  trusted: { text: '', color: '#1e8e3e' },
};

// --- Per-tab state (kept in session storage so it survives worker restarts) ---

const tabKey = (tabId) => `tab:${tabId}`;

async function getTabState(tabId) {
  const key = tabKey(tabId);
  const stored = await api.storage.session.get(key);
  return stored[key] ?? {};
}

async function patchTabState(tabId, patch) {
  const key = tabKey(tabId);
  const current = await getTabState(tabId);
  const next = { ...current, ...patch };
  await api.storage.session.set({ [key]: next });
  return next;
}

// --- Scoring -----------------------------------------------------------------

async function buildContext(url, extra = {}) {
  const settings = await getSettings();
  const context = { allowlist: settings.allowlist, ...extra };
  if (settings.domainAgeLookup) {
    try {
      const { registrable } = splitHost(new URL(url).hostname);
      if (registrable && !isIpAddress(registrable) && registrable.includes('.')) {
        context.domainAgeDays = await lookupDomainAgeDays(registrable);
      }
    } catch {
      // Unparseable URL or lookup failure: score without domain age.
    }
  }
  return context;
}

async function scoreTab(tabId, url) {
  const state = await getTabState(tabId);
  // Navigation changed: forget page facts gathered for the previous URL.
  const pageFacts = state.url === url ? state.pageFacts ?? {} : {};
  const tlsState = state.tlsUrl === url ? state.tlsState : undefined;
  const analysis = analyzeUrl(url, await buildContext(url, { ...pageFacts, tlsState }));
  await patchTabState(tabId, { url, pageFacts, analysis });
  await updateBadge(tabId, analysis);
  return analysis;
}

async function updateBadge(tabId, analysis) {
  const style = BADGE[analysis.verdict];
  try {
    if (!style) {
      await api.action.setBadgeText({ tabId, text: '' });
      await api.action.setTitle({ tabId, title: 'Phishing URL Classifier' });
      return;
    }
    const top = analysis.signals[0];
    await api.action.setBadgeText({ tabId, text: style.text });
    await api.action.setBadgeBackgroundColor({ tabId, color: style.color });
    await api.action.setTitle({
      tabId,
      title: `Phishing risk ${analysis.score}/100 (${analysis.verdict})${top ? `: ${top.title}` : ''}`,
    });
  } catch {
    // Tab closed before we finished.
  }
}

// --- Navigation hooks --------------------------------------------------------

api.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.url || (changeInfo.status === 'loading' && tab.url)) {
    scoreTab(tabId, changeInfo.url ?? tab.url).catch(console.error);
  }
});

api.tabs.onRemoved.addListener((tabId) => {
  api.storage.session.remove(tabKey(tabId)).catch(() => {});
});

// Firefox only: real certificate state for top-level documents. Chrome does not
// expose certificate details to extensions (it shows its own interstitial for
// invalid certificates instead).
if (api.webRequest?.getSecurityInfo) {
  api.webRequest.onHeadersReceived.addListener(
    async (details) => {
      if (details.tabId < 0) return;
      try {
        const info = await api.webRequest.getSecurityInfo(details.requestId, {});
        const tlsState = info.state === 'weak' ? 'insecure' : info.state;
        await patchTabState(details.tabId, { tlsState, tlsUrl: details.url });
      } catch {
        // Not available for this request.
      }
    },
    { urls: ['https://*/*'], types: ['main_frame'] },
    ['blocking'],
  );
}

// --- Messages ----------------------------------------------------------------

const MAX_LINKS_PER_BATCH = 400;

async function handleMessage(message, sender) {
  switch (message?.type) {
    case 'page-facts': {
      // Facts the content script observed in the DOM (e.g. a password field).
      const tabId = sender.tab?.id;
      const url = sender.tab?.url;
      if (tabId === undefined || !url || sender.frameId !== 0) return null;
      await patchTabState(tabId, { url, pageFacts: { hasPasswordField: Boolean(message.hasPasswordField) } });
      const analysis = await scoreTab(tabId, url);
      const settings = await getSettings();
      return { analysis, warnOnDangerous: settings.warnOnDangerous };
    }

    case 'score-links': {
      const settings = await getSettings();
      if (!settings.highlightLinks) return { results: [] };
      const pageSite = sender.tab?.url ? safeRegistrable(sender.tab.url) : '';
      const links = (message.links ?? []).slice(0, MAX_LINKS_PER_BATCH);
      const results = links.map(({ id, href, text }) => {
        const analysis = analyzeUrl(href, { allowlist: settings.allowlist, linkText: text });
        // Same-site links are not interesting unless the text is deceptive.
        const sameSite = pageSite && analysis.registrable === pageSite;
        const deceptive = analysis.signals.some((s) => s.id === 'deceptive_link_text');
        if (sameSite && !deceptive) return { id, verdict: 'safe' };
        return {
          id,
          verdict: analysis.verdict,
          score: analysis.score,
          registrable: analysis.registrable,
          signals: analysis.signals.slice(0, 3),
        };
      });
      return { results };
    }

    case 'get-tab-analysis': {
      const state = await getTabState(message.tabId);
      if (state.analysis && state.url === message.url) return state.analysis;
      return scoreTab(message.tabId, message.url);
    }

    case 'analyze-url':
      return analyzeUrl(message.url, await buildContext(message.url));

    case 'rescore-tab':
      return scoreTab(message.tabId, message.url);

    default:
      return null;
  }
}

function safeRegistrable(url) {
  try {
    return splitHost(new URL(url).hostname).registrable;
  } catch {
    return '';
  }
}

api.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender).then(sendResponse, (err) => {
    console.error(err);
    sendResponse(null);
  });
  return true; // keep the channel open for the async response
});
