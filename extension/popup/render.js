// Renders an Analysis object into a container. Uses DOM APIs (no innerHTML
// with page-derived strings) so a crafted URL can't inject markup.

const LABELS = {
  safe: 'No phishing signs found',
  suspicious: 'Suspicious',
  dangerous: 'Likely phishing',
  trusted: 'Trusted site',
  not_applicable: 'Not a web page',
  invalid: 'Not a valid URL',
};

function el(tag, attrs = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'style') node.style.cssText = v;
    else node.setAttribute(k, v);
  }
  for (const c of children) node.append(c);
  return node;
}

function hostLine(a) {
  if (!a.displayHost) return a.url;
  // Show the raw punycode too, so homograph domains can't hide behind look-alike glyphs.
  return a.displayHost === a.host ? a.host : `${a.displayHost} (${a.host})`;
}

export function renderAnalysis(container, analysis) {
  container.replaceChildren();
  if (!analysis) {
    container.append(el('p', { class: 'muted' }, 'Could not analyse this page.'));
    return;
  }

  const showScore = ['safe', 'suspicious', 'dangerous', 'trusted'].includes(analysis.verdict);
  const gauge = el('div', { class: 'gauge', style: `--pct: ${analysis.score}` }, el('span', {}, showScore ? String(analysis.score) : '–'));
  const text = el('div', {},
    el('div', { class: 'label' }, LABELS[analysis.verdict] ?? analysis.verdict),
    el('div', { class: 'host' }, hostLine(analysis)));
  container.append(el('div', { class: `verdict ${analysis.verdict}` }, gauge, text));

  const signals = analysis.signals.filter((s) => s.weight > 0 || s.id === 'trusted');
  if (!signals.length) return;
  const list = el('ul', { class: 'signals' });
  for (const s of signals) {
    list.append(el('li', {},
      el('div', { class: 't' }, el('span', {}, s.title), el('span', { class: 'w' }, s.weight ? `+${s.weight}` : '')),
      el('div', { class: 'd' }, s.detail)));
  }
  container.append(list);
}
