// String metrics used by the heuristics.

/** Shannon entropy in bits per character. */
export function shannonEntropy(str) {
  if (!str) return 0;
  const counts = new Map();
  for (const ch of str) counts.set(ch, (counts.get(ch) ?? 0) + 1);
  const len = [...str].length;
  let h = 0;
  for (const c of counts.values()) {
    const p = c / len;
    h -= p * Math.log2(p);
  }
  return h;
}

/**
 * Optimal-string-alignment distance (Damerau-Levenshtein restricted to
 * adjacent transpositions). Handles "paypla" -> "paypal" as distance 1.
 */
export function editDistance(a, b) {
  const m = a.length, n = b.length;
  if (Math.abs(m - n) > 3) return Math.abs(m - n); // early exit, never a match
  const d = Array.from({ length: m + 1 }, (_, i) => {
    const row = new Array(n + 1).fill(0);
    row[0] = i;
    return row;
  });
  for (let j = 0; j <= n; j++) d[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      const cost = a[i - 1] === b[j - 1] ? 0 : 1;
      d[i][j] = Math.min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost);
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) {
        d[i][j] = Math.min(d[i][j], d[i - 2][j - 2] + 1);
      }
    }
  }
  return d[m][n];
}

// Visual look-alikes mapped to the ASCII letter they imitate. Covers common
// digit swaps plus Cyrillic/Greek homoglyphs used in IDN homograph attacks.
const CHAR_CONFUSABLES = {
  '0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '9': 'g', '$': 's', '!': 'i', '|': 'l',
  // Cyrillic
  'а': 'a', 'в': 'b', 'е': 'e', 'ё': 'e', 'і': 'i', 'ї': 'i', 'ј': 'j', 'к': 'k', 'м': 'm', 'н': 'h',
  'о': 'o', 'р': 'p', 'с': 'c', 'т': 't', 'у': 'y', 'х': 'x', 'ѕ': 's', 'ԁ': 'd', 'ɡ': 'g', 'ӏ': 'l', 'ԛ': 'q', 'ԝ': 'w',
  // Greek
  'α': 'a', 'β': 'b', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x',
  // Latin extended look-alikes
  'ı': 'i', 'ł': 'l', 'ø': 'o', 'ð': 'd', 'ß': 'b',
};

// Multi-character sequences that render like a single letter in many fonts.
const SEQUENCE_CONFUSABLES = [
  ['rn', 'm'],
  ['vv', 'w'],
  ['cl', 'd'],
];

/**
 * Reduces a label to a "visual skeleton" so that "paypa1", "pаypal" (Cyrillic а)
 * and "pàypal" all collapse to "paypal". Accents are stripped via NFKD.
 */
export function skeleton(label) {
  let out = '';
  for (const ch of label.normalize('NFKD').replace(/[̀-ͯ]/g, '').toLowerCase()) {
    out += CHAR_CONFUSABLES[ch] ?? ch;
  }
  return out;
}

/** Variant of the skeleton with multi-character look-alikes also collapsed. */
export function sequenceSkeleton(label) {
  let s = skeleton(label);
  for (const [from, to] of SEQUENCE_CONFUSABLES) s = s.split(from).join(to);
  return s;
}

/** Returns the set of Unicode scripts used by letters in `str`. */
export function scriptsUsed(str) {
  const scripts = new Set();
  for (const ch of str) {
    if (/\p{Script=Latin}/u.test(ch)) scripts.add('Latin');
    else if (/\p{Script=Cyrillic}/u.test(ch)) scripts.add('Cyrillic');
    else if (/\p{Script=Greek}/u.test(ch)) scripts.add('Greek');
    else if (/\p{Script=Armenian}/u.test(ch)) scripts.add('Armenian');
    else if (/\p{L}/u.test(ch)) scripts.add('Other');
  }
  return scripts;
}
