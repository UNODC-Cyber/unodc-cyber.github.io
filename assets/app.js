// app.js - UI wiring for the lookup page. All verification logic lives in verifier.js
// (see the contract at the top of that file); this file only talks to it.
// No inline handlers, no storage of identifiers/names/keys, no third-party requests.

import { checkId, formatId, normaliseId, normaliseReveal } from './id.js';
import { verify, reveal } from './verifier.js';

const $ = (id) => document.getElementById(id);
const LOCALES = [
  ['en', 'English'], ['th', 'ไทย'], ['vi', 'Tiếng Việt'], ['km', 'ភាសាខ្មែរ'], ['lo', 'ລາວ'],
  ['my', 'မြန်မာ'], ['id', 'Bahasa Indonesia'], ['ms', 'Bahasa Melayu'], ['fil', 'Filipino'], ['zh', '中文'],
  ['ja', '日本語'], ['ko', '한국어'], ['ne', 'नेपाली'], ['bn', 'বাংলা'], ['hi', 'हिन्दी'],
  ['si', 'සිංහල'], ['mn', 'Монгол'],
];

// ---- i18n -------------------------------------------------------------------------
let en = {}; let dict = {}; let lang = 'en';
async function loadJson(path) {
  try {
    const r = await fetch(path, { credentials: 'omit', referrerPolicy: 'no-referrer' });
    return r.ok ? await r.json() : {};
  } catch { return {}; }
}
const has = (k) => typeof dict[k] === 'string' && dict[k] !== '';
const t = (key, params) => ((has(key) ? dict[key] : en[key]) || key).replace(/\{(\w+)\}/g, (m, k) => (params && k in params ? String(params[k]) : m));
function applyI18n() {
  document.documentElement.lang = lang; document.documentElement.dir = 'ltr'; // all launch locales are LTR
  document.querySelectorAll('[data-i18n]').forEach((el) => { el.textContent = t(el.getAttribute('data-i18n')); });
}
async function setLang(l) {
  lang = LOCALES.some(([c]) => c === l) ? l : 'en';
  dict = lang === 'en' ? en : await loadJson(`i18n/${lang}.json`);
  applyI18n(); renderResult(); renderRevealOut(); updateFeedback(false);
}
function pickLang() {
  for (const raw of navigator.languages || [navigator.language || 'en']) {
    const base = String(raw).toLowerCase().split('-')[0];
    const code = base === 'tl' ? 'fil' : base;
    if (LOCALES.some(([c]) => c === code)) return code;
  }
  return 'en';
}

// ---- state ------------------------------------------------------------------------
let seq = 0; let ctl = null; let revealCtl = null;
let lastResult = null; // { kind:'result', data } | { kind:'error', code } | { kind:'checking' } | null
let currentId = null; let fragmentKey = null;
let lastReveal = null; // { ok, details } | { ok:false, error } | { working:true } | { msg } | null

// ---- id input ---------------------------------------------------------------------
const idInput = $('id');
function updateFeedback(announceProgress) {
  const c = checkId(idInput.value);
  const box = $('id-feedback');
  box.className = 'feedback';
  let progress = ''; let msg = '';
  if (c.kind === 'too-short') progress = t('fb.progress', { n: c.length });
  else if (c.kind === 'invalid-symbol') { msg = t('fb.invalidSymbol', { pos: c.pos, ch: c.ch }); box.classList.add('bad'); }
  else if (c.kind === 'too-long') { msg = t('fb.tooLong', { n: c.length }); box.classList.add('bad'); }
  else if (c.kind === 'bad-check') { msg = t('fb.badCheck'); box.classList.add('bad'); }
  else if (c.kind === 'ok') { msg = t('fb.ok'); box.classList.add('good'); }
  if (announceProgress && progress) { msg = progress; progress = ''; }
  $('fb-progress').textContent = progress;
  $('fb-live').textContent = msg;
  idInput.setAttribute('aria-invalid', ['invalid-symbol', 'too-long', 'bad-check'].includes(c.kind) ? 'true' : 'false');
  return c;
}
function reformat() {
  const raw = idInput.value;
  const caret = idInput.selectionStart ?? raw.length;
  const symbolsBefore = normaliseId(raw.slice(0, caret)).canonical.length;
  const { canonical } = normaliseId(raw);
  const out = formatId(canonical);
  if (out !== raw) {
    idInput.value = out;
    let n = 0; let pos = 0;
    while (pos < out.length && n < symbolsBefore) { if (out[pos] !== '-') n++; pos++; }
    try { idInput.setSelectionRange(pos, pos); } catch { /* not focusable */ }
  }
}
idInput.addEventListener('input', () => { reformat(); updateFeedback(false); clearOutputs(); });

// ---- result rendering -------------------------------------------------------------
const STATE_ICON = { 'valid-completion': '✓', 'valid-attendance': '✓', 'valid-appreciation': '✓', 'valid-contribution': '✓', revoked: '✕', 'not-found': '?', error: '!' };
function fillWithNode(el, template, name, node) {
  el.textContent = '';
  const [a, b = ''] = template.split(`{${name}}`);
  el.append(a, node, b);
}
function titleWithEnglish(el, key) {
  el.textContent = t(key);
  if (lang !== 'en' && has(key)) {
    const sp = document.createElement('span'); sp.className = 'en-word'; sp.lang = 'en'; sp.textContent = ` (${en[key]})`; el.append(sp);
  }
}
function renderResult() {
  const card = $('result'); const dev = $('dev-banner');
  card.className = 'card';
  if (!lastResult) { card.hidden = true; dev.hidden = true; $('reveal').hidden = true; return; }
  card.hidden = false;
  const asof = $('result-asof'); const stale = $('result-stale'); const hint = $('result-hint');
  asof.hidden = true; stale.hidden = true; hint.hidden = true;
  if (lastResult.kind === 'checking') {
    card.classList.add('state-not-found'); $('result-icon').textContent = '…';
    $('result-title').textContent = t('state.checking'); $('result-text').textContent = '';
    dev.hidden = true; $('reveal').hidden = true; return;
  }
  if (lastResult.kind === 'error') {
    // "Not live yet" is an announcement, not a failure of this certificate: neutral card, its own title.
    const notLive = lastResult.code === 'not-live';
    card.classList.add(notLive ? 'state-not-found' : 'state-error'); $('result-icon').textContent = notLive ? 'i' : STATE_ICON.error;
    $('result-title').textContent = t(notLive ? 'err.not-live.title' : 'err.title'); $('result-text').textContent = t(`err.${lastResult.code}`);
    dev.hidden = true; $('reveal').hidden = true; return;
  }
  const d = lastResult.data;
  card.classList.add(`state-${d.state}`);
  $('result-icon').textContent = STATE_ICON[d.state];
  titleWithEnglish($('result-title'), `state.${d.state}.title`);
  $('result-text').textContent = t(`state.${d.state}.text`);
  const time = document.createElement('time');
  time.dateTime = d.asOf; time.title = d.asOf;
  try { time.textContent = new Intl.DateTimeFormat(lang, { dateStyle: 'long', timeZone: 'UTC' }).format(new Date(d.asOf)); } catch { time.textContent = d.asOf; }
  fillWithNode(asof, t('state.asof', { date: '{date}' }), 'date', time); asof.hidden = false;
  if (d.stale) { stale.textContent = t('state.stale'); stale.hidden = false; }
  // A valid status is about the identifier, not the person: say so, and point to the name check in the reveal.
  if (d.canReveal) { hint.textContent = t('state.holderHint'); hint.hidden = false; }
  // A TEST key list (keys.json "production": false) is never silent: the banner says results are test data.
  dev.hidden = d.integrity === 'verified' && d.production !== false;
  dev.textContent = t(d.integrity === 'verified' ? 'dev.testKeys' : 'dev.banner');
  $('reveal').hidden = !d.canReveal;
}
function clearOutputs() {
  seq++; if (ctl) ctl.abort(); if (revealCtl) revealCtl.abort();
  lastResult = null; lastReveal = null; currentId = null;
  renderResult(); renderRevealOut(); $('factor').value = '';
}

// ---- verify -----------------------------------------------------------------------
async function runVerify(canonical) {
  const mine = ++seq; if (ctl) ctl.abort(); ctl = new AbortController();
  currentId = canonical; lastReveal = null; renderRevealOut();
  lastResult = { kind: 'checking' }; renderResult();
  let r;
  try { r = await verify(canonical, { signal: ctl.signal }); } catch (e) { if (e && e.name === 'AbortError') return; r = { ok: false, error: 'network' }; }
  if (mine !== seq) return;
  lastResult = r.ok ? { kind: 'result', data: r } : { kind: 'error', code: r.error };
  renderResult();
}
$('lookup').addEventListener('submit', (ev) => {
  ev.preventDefault();
  const c = updateFeedback(true);
  if (c.kind !== 'ok') { idInput.focus(); return; }
  runVerify(c.canonical);
});

// ---- reveal -----------------------------------------------------------------------
function codeFieldState() { $('code-field').hidden = !!fragmentKey; $('code-from-link').hidden = !fragmentKey; }
function renderRevealOut() {
  const out = $('reveal-out'); out.textContent = ''; out.className = 'out';
  const r = lastReveal;
  $('reveal-progress').hidden = !(r && r.working); $('reveal-button').disabled = !!(r && r.working);
  if (!r) return;
  if (r.working) { out.textContent = t(r.slow ? 'reveal.slow' : 'reveal.working'); return; }
  if (r.msg) { out.textContent = r.msg; out.classList.add('bad'); return; }
  if (!r.ok) { out.textContent = t(`reveal.error.${r.error}`); out.classList.add('bad'); return; }
  // "Issued to" comes first and stands out: the verifier must compare it with the certificate / the person.
  const holder = document.createElement('div'); holder.className = 'holder' + (r.details.name ? '' : ' unrecorded'); holder.id = 'holder';
  const lab = document.createElement('p'); lab.className = 'label'; lab.textContent = t('reveal.issuedTo');
  const nm = document.createElement('p'); nm.className = 'name'; nm.id = 'holder-name';
  nm.textContent = r.details.name || t('reveal.nameNotRecorded'); // text only, never markup
  const chk = document.createElement('p'); chk.className = 'check'; chk.textContent = t(r.details.name ? 'reveal.nameCheck' : 'reveal.nameNotRecordedCheck');
  holder.append(lab, nm, chk);
  const dl = document.createElement('dl'); dl.className = 'details';
  // r.details.type is the PUBLIC registry type (verifier.js contract), never the sealed copy's.
  const typ = en[`type.${r.details.type}`] ? t(`type.${r.details.type}`) : r.details.type;
  for (const [k, v] of [['course', r.details.course], ['dates', r.details.dates], ['venue', r.details.venue], ['type', typ]]) {
    const dt = document.createElement('dt'); dt.textContent = t(`reveal.detail.${k}`);
    const dd = document.createElement('dd'); dd.textContent = v; dl.append(dt, dd);
  }
  out.append(holder, dl);
}
$('reveal-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  if (!currentId) return;
  const factor = $('factor').value.trim();
  if (!factor) { lastReveal = { msg: t('reveal.needFactor') }; renderRevealOut(); $('factor').focus(); return; }
  const code = fragmentKey || normaliseReveal($('code').value);
  if (!code) { lastReveal = { msg: t('reveal.needCode') }; renderRevealOut(); $('code').focus(); return; }
  const mine = seq; lastReveal = { working: true }; renderRevealOut();
  if (revealCtl) revealCtl.abort();
  revealCtl = new AbortController();
  // Slow devices (or no WebAssembly) can take much longer: say so instead of looking stuck.
  const slow = setTimeout(() => { if (mine === seq && lastReveal && lastReveal.working) { lastReveal = { working: true, slow: true }; renderRevealOut(); } }, 8000);
  let r;
  try {
    r = await reveal(currentId, { factor, factorKind: factor.includes('@') ? 'email' : 'surname', revealCode: code }, { signal: revealCtl.signal });
  } catch (e) { if (e && e.name === 'AbortError') return; r = { ok: false, error: 'network' }; } finally { clearTimeout(slow); }
  if (mine !== seq) return;
  lastReveal = r; renderRevealOut();
});

// ---- startup ----------------------------------------------------------------------
function readFragment() {
  const m = /(?:^#|&)k=([^&]*)/.exec(location.hash);
  let raw = m ? m[1] : '';
  try { raw = decodeURIComponent(raw); } catch { /* keep as is */ }
  if (m) fragmentKey = normaliseReveal(raw);
  // The reveal key is a secret: keep it in memory only, and remove it from the address bar and history.
  if (location.hash) { try { history.replaceState(history.state, '', location.pathname + location.search); } catch { /* ignore */ } }
  codeFieldState();
}
// Frame busting (no frame-ancestors via meta CSP): a framed copy could be overlaid with a fake result.
function framed() { try { return window.top !== window.self; } catch { return true; } }
function showFramedNotice() {
  const p = document.createElement('p'); p.className = 'note'; p.id = 'framed'; p.textContent = t('framed.text');
  const a = document.createElement('a'); a.href = location.href; a.target = '_blank'; a.rel = 'noopener noreferrer'; a.textContent = t('framed.link');
  $('main').replaceChildren(p, a); // the lookup form and every result element are removed, not just hidden
}
async function init() {
  en = await loadJson('i18n/en.json'); dict = en;
  if (framed()) { showFramedNotice(); return; }
  const sel = $('lang');
  for (const [c, name] of LOCALES) { const o = document.createElement('option'); o.value = c; o.textContent = name; o.lang = c; sel.append(o); }
  lang = pickLang(); sel.value = lang;
  sel.addEventListener('change', () => setLang(sel.value));
  readFragment();
  window.addEventListener('hashchange', readFragment);
  // Clear typed secrets on navigation away (back/forward cache included).
  window.addEventListener('pagehide', () => { $('factor').value = ''; $('code').value = ''; });
  await setLang(lang);
  const q = new URLSearchParams(location.search).get('id');
  if (q) {
    $('qr-note').hidden = false;
    idInput.value = formatId(normaliseId(q.slice(0, 64)).canonical); // text only, never markup
    const c = updateFeedback(true);
    if (c.kind === 'ok') runVerify(c.canonical);
  }
}
init();
