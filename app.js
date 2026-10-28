'use strict';
/* Tootline — 自動更新に強いMastodonクライアント(ホーム / ローカル / 通知)
   外部ライブラリなし。ログイン情報はこの端末のlocalStorageにだけ保存される。 */

const APP_NAME = 'Tootline';
const SCOPES = 'read write push';
const VERSION = '1.5';
const REDIRECT = location.origin + location.pathname.replace(/index\.html$/, '');
const POLL_MS = 30000;      // 画面を開いている間の取りこぼし確認の間隔
const KEEP = 300;           // 1つのタイムラインに保持する最大件数

/* ---------- 小さな道具 ---------- */
const $ = (s, r = document) => r.querySelector(s);
const store = {
  get(k) { try { return JSON.parse(localStorage.getItem(k)); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} },
  del(k) { try { localStorage.removeItem(k); } catch {} },
};
function el(tag, props = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (v == null || v === false) continue;
    if (k === 'class') e.className = v;
    else if (k === 'text') e.textContent = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat()) if (c != null) e.append(c);
  return e;
}
const cmpId = (a, b) => (a.length - b.length) || (a < b ? -1 : a > b ? 1 : 0);
const maxId = (list) => list.reduce((m, x) => (m == null || cmpId(x.id, m) > 0 ? x.id : m), null);
const minId = (list) => list.reduce((m, x) => (m == null || cmpId(x.id, m) < 0 ? x.id : m), null);
const b64u = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const rand = (n = 32) => b64u(crypto.getRandomValues(new Uint8Array(n)));
const sha256 = (s) => crypto.subtle.digest('SHA-256', new TextEncoder().encode(s));
const isLocalHost = (h) => /^(localhost|127\.0\.0\.1)(:\d+)?$/.test(h);
const httpBase = (h) => (isLocalHost(h) ? 'http://' : 'https://') + h;

let toastTimer;
function toast(msg) {
  const t = $('#toast');
  t.textContent = msg; t.hidden = false;
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => { t.hidden = true; }, 3500);
}

function ago(iso) {
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 10) return 'いま';
  if (s < 60) return `${Math.floor(s)}秒`;
  if (s < 3600) return `${Math.floor(s / 60)}分`;
  if (s < 86400) return `${Math.floor(s / 3600)}時間`;
  if (s < 86400 * 7) return `${Math.floor(s / 86400)}日`;
  const d = new Date(iso);
  return `${d.getMonth() + 1}/${d.getDate()}`;
}

/* ---------- セッション ---------- */
let S = null; // {host, token, me, stream, maxChars, maxMedia}

async function api(path, { method = 'GET', params, body } = {}) {
  const url = new URL(httpBase(S.host) + path);
  if (params) for (const [k, v] of Object.entries(params)) if (v != null) url.searchParams.append(k, v);
  const headers = { Authorization: `Bearer ${S.token}` };
  let payload;
  if (body instanceof FormData) payload = body;
  else if (body) {
    const { __key, ...rest } = body;
    if (__key) headers['Idempotency-Key'] = __key;
    headers['Content-Type'] = 'application/json';
    payload = JSON.stringify(rest);
  }
  const res = await fetch(url, { method, headers, body: payload });
  if (res.status === 401) { toast('ログインの期限が切れました。もう一度ログインしてください。'); setTimeout(logout, 1500); throw new Error('401'); }
  if (!res.ok && res.status !== 202) {
    let msg = `通信エラー(${res.status})`;
    try { const j = await res.json(); if (j.error) msg = j.error; } catch {}
    throw new Error(msg);
  }
  const j = await res.json();
  j.__status = res.status;
  return j;
}

/* ---------- ログイン(OAuth + PKCE) ---------- */
function normalizeHost(v) {
  return v.trim().replace(/^https?:\/\//i, '').replace(/\/.*$/, '').toLowerCase();
}

async function startLogin(rawHost) {
  const host = normalizeHost(rawHost);
  if (!host || !/^[a-z0-9.-]+(:\d+)?$/.test(host)) throw new Error('ドメインの形が正しくありません。例: mstdn.jp');
  const apps = store.get('tl.apps') || {};
  let app = apps[host];
  if (!app || app.redirect !== REDIRECT || app.scopes !== SCOPES) {
    let r;
    try {
      r = await fetch(httpBase(host) + '/api/v1/apps', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ client_name: APP_NAME, redirect_uris: REDIRECT, scopes: SCOPES, website: REDIRECT }),
      });
    } catch { throw new Error(`${host} に接続できません。ドメインを確かめてください。`); }
    if (!r.ok) throw new Error(`${host} がアプリの登録を受け付けませんでした(${r.status})。`);
    const j = await r.json();
    app = { client_id: j.client_id, client_secret: j.client_secret, redirect: REDIRECT, scopes: SCOPES, vapid: j.vapid_key || null };
    apps[host] = app; store.set('tl.apps', apps);
  }
  const verifier = rand(48), state = rand(16);
  store.set('tl.pending', { host, verifier, state });
  const u = new URL(httpBase(host) + '/oauth/authorize');
  u.search = new URLSearchParams({
    client_id: app.client_id, response_type: 'code', redirect_uri: REDIRECT, scope: SCOPES,
    code_challenge: b64u(await sha256(verifier)), code_challenge_method: 'S256', state,
  });
  location.href = u.toString();
}

async function finishLogin(code, state) {
  const p = store.get('tl.pending');
  if (!p || p.state !== state) throw new Error('ログインの確認が一致しませんでした。もう一度ログインしてください。');
  const app = (store.get('tl.apps') || {})[p.host];
  const r = await fetch(httpBase(p.host) + '/oauth/token', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ grant_type: 'authorization_code', client_id: app.client_id, client_secret: app.client_secret,
      redirect_uri: REDIRECT, code, code_verifier: p.verifier, scope: SCOPES }),
  });
  if (!r.ok) throw new Error(`ログインを完了できませんでした(${r.status})。`);
  const tok = await r.json();
  store.del('tl.pending');
  store.set('tl.session', { host: p.host, token: tok.access_token, scope: tok.scope || '' });
}

async function logout() {
  const ses = store.get('tl.session');
  const app = ses && (store.get('tl.apps') || {})[ses.host];
  if (ses && app) {
    try {
      await fetch(httpBase(ses.host) + '/oauth/revoke', { method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ client_id: app.client_id, client_secret: app.client_secret, token: ses.token }) });
    } catch {}
  }
  try { for (const k of Object.keys(localStorage)) if (k.startsWith('tl.cache.')) store.del(k); } catch {}
  store.del('tl.session');
  location.replace(REDIRECT);
}

async function loadInstance() {
  const base = { stream: 'wss://' + S.host, maxChars: 500, maxMedia: 4, vapid: null };
  if (isLocalHost(S.host)) base.stream = 'ws://' + S.host;
  try {
    const r = await fetch(httpBase(S.host) + '/api/v2/instance');
    if (r.ok) {
      const j = await r.json();
      const c = j.configuration || {};
      if (c.urls && c.urls.streaming) base.stream = c.urls.streaming;
      if (c.vapid && c.vapid.public_key) base.vapid = c.vapid.public_key;
      if (c.statuses) { base.maxChars = c.statuses.max_characters || 500; base.maxMedia = c.statuses.max_media_attachments || 4; }
      return base;
    }
  } catch {}
  try {
    const r = await fetch(httpBase(S.host) + '/api/v1/instance');
    if (r.ok) {
      const j = await r.json();
      if (j.urls && j.urls.streaming_api) base.stream = j.urls.streaming_api;
      const c = j.configuration && j.configuration.statuses;
      if (c) { base.maxChars = c.max_characters || 500; base.maxMedia = c.max_media_attachments || 4; }
    }
  } catch {}
  return base;
}

/* ---------- 表示用の部品 ---------- */
const OK_TAGS = new Set(['P', 'BR', 'A', 'SPAN', 'STRONG', 'EM', 'B', 'I', 'U', 'DEL', 'S', 'CODE', 'PRE', 'BLOCKQUOTE', 'UL', 'OL', 'LI']);
const DROP_TAGS = new Set(['SCRIPT', 'STYLE', 'IFRAME', 'OBJECT', 'EMBED', 'TEMPLATE']);
const OK_CLASS = new Set(['invisible', 'ellipsis', 'mention', 'hashtag', 'u-url', 'h-card']);

function withEmoji(text, emojis) {
  if (!emojis || !emojis.length || !text.includes(':')) return [text];
  const map = new Map(emojis.map((e) => [e.shortcode, e.static_url || e.url]));
  const out = [];
  let last = 0;
  for (const m of text.matchAll(/:([A-Za-z0-9_]+):/g)) {
    const url = map.get(m[1]);
    if (!url) continue;
    if (m.index > last) out.push(text.slice(last, m.index));
    out.push(el('img', { class: 'emoji', src: url, alt: m[0], title: m[0], loading: 'lazy' }));
    last = m.index + m[0].length;
  }
  if (last < text.length) out.push(text.slice(last));
  return out;
}

function sanitize(html, emojis) {
  const doc = new DOMParser().parseFromString(html || '', 'text/html');
  const out = document.createDocumentFragment();
  const walk = (src, dst) => {
    for (const n of src.childNodes) {
      if (n.nodeType === 3) dst.append(...withEmoji(n.nodeValue, emojis));
      else if (n.nodeType === 1) {
        if (DROP_TAGS.has(n.tagName)) continue;
        if (!OK_TAGS.has(n.tagName)) { walk(n, dst); continue; }
        const c = document.createElement(n.tagName.toLowerCase());
        if (n.tagName === 'A') {
          const h = n.getAttribute('href') || '';
          if (/^https?:\/\//i.test(h)) { c.href = h; c.target = '_blank'; c.rel = 'noopener noreferrer nofollow'; }
        }
        const cls = [...n.classList].filter((x) => OK_CLASS.has(x));
        if (cls.length) c.className = cls.join(' ');
        walk(n, c);
        dst.append(c);
      }
    }
  };
  walk(doc.body, out);
  return out;
}

// 名前をタップするとその人のプロフィールが開く
const whoNode = (acc) => { const n = nameNode(acc); n.addEventListener('click', () => openProfile(acc.id)); return n; };
const nameNode = (acc) => el('span', { class: 'nm' }, ...withEmoji(acc.display_name || acc.username, acc.emojis));
const VIS = { unlisted: 'ひかえめ', private: '限定', direct: 'DM' };
const ICON = {
  reply: '<path d="M9 14 4 9l5-5"/><path d="M4 9h10a6 6 0 0 1 6 6v3"/>',
  boost: '<path d="m17 2 4 4-4 4"/><path d="M3 11V9a3 3 0 0 1 3-3h15"/><path d="m7 22-4-4 4-4"/><path d="M21 13v2a3 3 0 0 1-3 3H3"/>',
  edit: '<path d="M12 20h9"/><path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4Z"/>',
  fav: '<path d="m12 3 2.8 5.7 6.2.9-4.5 4.4 1.1 6.2L12 17.2 6.4 20.2l1.1-6.2L3 9.6l6.2-.9z"/>',
};
function icon(name) {
  const s = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  s.setAttribute('viewBox', '0 0 24 24'); s.setAttribute('aria-hidden', 'true');
  s.innerHTML = ICON[name];
  return s;
}

function mediaBlock(s) {
  const items = (s.media_attachments || []).slice(0, 4);
  if (!items.length) return null;
  const box = el('div', { class: `media n${items.length === 1 ? 1 : 2}` });
  for (const m of items) {
    const sens = s.sensitive;
    let inner;
    if (m.type === 'video' || m.type === 'gifv') {
      inner = el('video', { src: m.url, poster: m.preview_url || '', muted: true, playsinline: true, preload: 'metadata',
        ...(m.type === 'gifv' ? { autoplay: true, loop: true } : {}) });
    } else {
      inner = el('img', { src: m.preview_url || m.url, alt: m.description || '', loading: 'lazy' });
    }
    const b = el('button', { class: 'm' + (sens ? ' sens' : ''), type: 'button', 'aria-label': m.description || '添付メディアを開く' }, inner);
    b.addEventListener('click', () => {
      if (b.classList.contains('sens')) { b.classList.remove('sens'); return; }
      openViewer(items, items.indexOf(m));
    });
    if (items.length === 1) { // 1枚だけの画像は横幅いっぱいに(左右のグレーの余白をなくす)
      const ar = (m.meta && ((m.meta.small && m.meta.small.aspect) || (m.meta.original && m.meta.original.aspect))) || 1.6;
      b.style.setProperty('--ar', String(Math.min(2.2, Math.max(0.8, ar))));
    }
    box.append(b);
  }
  return box;
}

const VW_CSS = `
.viewer { display: block; padding: 0; background: rgba(0,0,0,.94); }
.vw-track { position: absolute; inset: 0; display: flex; overflow-x: auto; scroll-snap-type: x mandatory; -webkit-overflow-scrolling: touch; overscroll-behavior: contain; scrollbar-width: none; }
.vw-track::-webkit-scrollbar { display: none; }
.vw-slide { flex: 0 0 100%; width: 100%; height: 100%; scroll-snap-align: center; scroll-snap-stop: always; display: grid; place-items: center; padding: calc(env(safe-area-inset-top) + 60px) 0 calc(env(safe-area-inset-bottom) + 24px); }
.vw-slide img, .vw-slide video { max-width: 100%; max-height: 100%; object-fit: contain; }
.vw-close { position: absolute; top: calc(env(safe-area-inset-top) + 10px); right: 12px; z-index: 2; width: 44px; height: 44px; border: 0; border-radius: 50%; background: rgba(255,255,255,.2); color: #fff; font-size: 28px; line-height: 1; padding: 0; }
.media.n1 .m { aspect-ratio: var(--ar, 1.6); max-height: none; }
.media.n1 img, .media.n1 video { object-fit: cover; max-height: none; }
.col, .prof-scroll { overflow-x: hidden; }
.media img, .media video { pointer-events: none; -webkit-user-drag: none; -webkit-touch-callout: none; user-select: none; }
.list, .post, .pb, .content, .media { min-width: 0; max-width: 100%; }
.content img:not(.emoji), .content video, .content table { max-width: 100%; }
.content pre { max-width: 100%; overflow-x: auto; }
html, body { overflow-x: hidden; }
.col { touch-action: pan-y pinch-zoom; visibility: visible; will-change: transform; transition: transform .24s cubic-bezier(.22,.8,.26,1); }
#cols { overflow: hidden; }
.col:not(.on) { pointer-events: none; }
@keyframes inl { from { transform: translateX(36px); opacity: .4; } to { transform: none; opacity: 1; } }
@keyframes inr { from { transform: translateX(-36px); opacity: .4; } to { transform: none; opacity: 1; } }
.col.in-l { animation: inl .2s ease-out; }
.col.in-r { animation: inr .2s ease-out; }
@media (prefers-reduced-motion: reduce) { .col.in-l, .col.in-r { animation: none; } }
.vw-count { position: absolute; top: calc(env(safe-area-inset-top) + 21px); left: 16px; z-index: 2; color: #fff; font-size: 14px; font-variant-numeric: tabular-nums; }
`;
(function injectViewerStyles() { const st = document.createElement('style'); st.textContent = VW_CSS; document.head.append(st); })();

// 背景テーマ: 白 / 黒 / 動画色(青みのグレー)。選んだものを覚えておく
const THEMES = {
  white: { name: '白', bg: '#F4F6F8', css: ':root, :root * { color-scheme: light; } :root { --bg:#F4F6F8; --surface:#FFFFFF; --ink:#101820; --sub:#5B6773; --rule:#DDE2E8; --home:#0B6BCB; --local:#138A5B; --notif:#D9530A; --danger:#C62828; }' },
  black: { name: '黒', bg: '#000000', css: ':root, :root * { color-scheme: dark; } :root { --bg:#000000; --surface:#0E0E10; --ink:#EDEFF5; --sub:#9AA0AE; --rule:#26282E; --home:#5AA9FF; --local:#3DD68C; --notif:#FF9A52; --danger:#FF6B6B; }' },
  video: { name: 'グレー', bg: '#282B36', css: ':root, :root * { color-scheme: dark; } :root { --bg:#282B36; --surface:#313543; --ink:#EDEFF5; --sub:#9BA3B5; --rule:#424A5A; --home:#5AA9FF; --local:#3DD68C; --notif:#FF9A52; --danger:#FF6B6B; }' },
};
const themeStyle = document.createElement('style');
document.head.append(themeStyle);
function applyTheme(k) {
  const t = THEMES[k] || THEMES.video;
  themeStyle.textContent = t.css + ` html, body { background:${t.bg}; } .pill, .badge { color:${k === 'white' ? '#fff' : '#101820'}; }`;
  document.querySelectorAll('meta[name=theme-color]').forEach((m) => m.setAttribute('content', t.bg));
  document.querySelectorAll('#themeSel button').forEach((b) => b.classList.toggle('on', b.dataset.t === k));
}
let curTheme = 'video';
try { curTheme = localStorage.getItem('tootline.theme') || 'video'; } catch {}
applyTheme(curTheme);
function wireTheme() {
  const card = $('.menu-card');
  const box = el('div', { id: 'themeSel' });
  box.style.cssText = 'display:flex;gap:8px;margin:12px 0';
  for (const k of ['white', 'black', 'video']) {
    const b = el('button', { type: 'button', text: THEMES[k].name });
    b.dataset.t = k;
    b.style.cssText = 'flex:1;padding:10px 0;border-radius:8px;border:2px solid var(--rule);background:' + THEMES[k].bg + ';color:' + (k === 'white' ? '#101820' : '#EDEFF5') + ';font-weight:700';
    b.addEventListener('click', () => { curTheme = k; try { localStorage.setItem('tootline.theme', k); } catch {} applyTheme(k); });
    box.append(b);
  }
  card.insertBefore(box, $('#menuClose'));
  const st = document.createElement('style');
  st.textContent = '#themeSel button.on { border-color: var(--home) !important; }';
  document.head.append(st);
  applyTheme(curTheme);
}

function closeViewer() {
  const v = $('#viewer');
  for (const x of v.querySelectorAll('video')) x.pause();
  v.hidden = true; v.textContent = '';
  document.removeEventListener('keydown', onViewerKey);
}
function onViewerKey(e) { if (e.key === 'Escape') closeViewer(); }

// 画像・動画ビューア: 左右スワイプで同じ投稿の次の画像へ。右上の×で元の画面に戻る
function openViewer(items, start = 0) {
  const v = $('#viewer'); v.textContent = '';
  const track = el('div', { class: 'vw-track' });
  const count = el('div', { class: 'vw-count' });
  for (const m of items) {
    const isVid = m.type === 'video' || m.type === 'gifv';
    const media = isVid
      ? el('video', { src: m.url, controls: m.type === 'video', playsinline: true, preload: 'metadata', ...(m.type === 'gifv' ? { loop: true, muted: true } : {}) })
      : el('img', { src: m.url, alt: m.description || '' });
    const slide = el('div', { class: 'vw-slide' }, media);
    slide.addEventListener('click', (e) => { if (e.target === slide) closeViewer(); });
    track.append(slide);
  }
  const close = el('button', { class: 'vw-close', type: 'button', 'aria-label': '閉じる', text: '×' });
  close.addEventListener('click', closeViewer);
  v.append(track, count, close);
  v.hidden = false;
  const index = () => Math.round(track.scrollLeft / (track.clientWidth || 1));
  const sync = () => {
    const i = index();
    count.textContent = items.length > 1 ? `${i + 1} / ${items.length}` : '';
    [...track.children].forEach((s, k) => {
      const vid = s.querySelector('video');
      if (!vid) return;
      if (k === i) { if (vid.loop) vid.play().catch(() => {}); } else vid.pause();
    });
  };
  track.addEventListener('scroll', sync, { passive: true });
  track.scrollLeft = start * track.clientWidth;
  sync();
  const first = track.children[start] && track.children[start].querySelector('video');
  if (first) first.play().catch(() => {});
  document.addEventListener('keydown', onViewerKey);
}

function actBtn(kind, label, count, on, handler) {
  return el('button', { class: `act ${kind}${on ? ' on' : ''}`, type: 'button', 'aria-label': label, 'aria-pressed': (kind === 'reply' || kind === 'edit') ? null : String(!!on), onclick: handler },
    icon(kind), el('span', { class: 'n', text: count > 0 ? String(count) : '' }));
}

function contentBlock(s) {
  const body = el('div', { class: 'content' }, sanitize(s.content, s.emojis));
  body.addEventListener('click', (e) => {
    const link = e.target.closest('a.mention');
    if (!link) return;
    const m = (s.mentions || []).find((x) => x.url === link.getAttribute('href'));
    if (m) { e.preventDefault(); openProfile(m.id); }
  });
  if (!s.spoiler_text) return body;
  const wrap = el('div', { class: 'cw' }, el('div', { class: 'cw-t' }, ...withEmoji(s.spoiler_text, s.emojis)));
  body.hidden = true;
  const btn = el('button', { type: 'button', text: '表示する' });
  btn.addEventListener('click', () => { body.hidden = !body.hidden; btn.textContent = body.hidden ? '表示する' : '隠す'; });
  wrap.append(btn, body);
  return wrap;
}

function renderStatus(st, { notice } = {}) {
  const s = st.reblog || st;
  const a = s.account;
  const root = el('article', { class: 'post' + (st.reblog ? ' boosted' : ''), 'data-oid': s.id });
  const body = el('div', { class: 'pb' });
  if (notice) body.append(el('div', { class: 'hint' }, notice));
  else if (st.reblog) body.append(el('div', { class: 'hint' }, whoNode(st.account), 'がブースト'));
  const hd = el('div', { class: 'hd' }, nameNode(a), el('span', { class: 'ac', text: '@' + a.acct }));
  if (VIS[s.visibility]) hd.append(el('span', { class: 'vis', text: VIS[s.visibility] }));
  if (s.edited_at) hd.append(el('span', { class: 'vis', text: '編集済み' }));
  hd.append(el('a', { class: 'tm', href: s.url || s.uri, target: '_blank', rel: 'noopener', 'data-t': s.created_at, text: ago(s.created_at) }));
  for (const n of hd.querySelectorAll('.nm, .ac')) n.addEventListener('click', () => openProfile(a.id));
  body.append(hd, contentBlock(s));
  const mb = mediaBlock(s); if (mb) body.append(mb);
  if (s.poll) body.append(el('div', { class: 'poll', text: '投票つき(このバージョンでは表示のみ・投票はブラウザで)' }));
  const acts = el('div', { class: 'acts' },
    actBtn('reply', '返信', s.replies_count, false, () => openCompose(s)),
    actBtn('boost', 'ブースト', s.reblogs_count, s.reblogged, (e) => toggle(s, 'reblog', e.currentTarget)),
    actBtn('fav', 'お気に入り', s.favourites_count, s.favourited, (e) => toggle(s, 'favourite', e.currentTarget)));
  if (S && S.me && a.id === S.me.id) acts.append(actBtn('edit', '編集', 0, false, () => openEdit(s)));
  body.append(acts);
  const av = el('img', { class: 'av', src: a.avatar_static || a.avatar, alt: '', loading: 'lazy' });
  av.addEventListener('click', () => openProfile(a.id));
  root.append(el('span', { class: 'node' }), av, body);
  return root;
}

const NOTICE = {
  favourite: 'がお気に入りにしました', reblog: 'がブーストしました', follow: 'にフォローされました',
  follow_request: 'からフォローリクエスト', poll: '投票が終了しました', update: 'が投稿を編集しました', status: 'が投稿しました',
};
function renderNotification(n) {
  if (n.type === 'mention' && n.status) {
    const e = renderStatus(n.status, { notice: el('span', {}, whoNode(n.account), 'からの返信・メンション') });
    e.classList.add('notice');
    return e;
  }
  const label = NOTICE[n.type] || (n.type || '通知');
  if (n.status) {
    const e = renderStatus(n.status, { notice: el('span', {}, whoNode(n.account), label) });
    e.classList.add('notice');
    return e;
  }
  const a = n.account;
  const root = el('article', { class: 'post notice' });
  const nav = el('img', { class: 'av', src: a.avatar_static || a.avatar, alt: '', loading: 'lazy' });
  nav.addEventListener('click', () => openProfile(a.id));
  const nname = nameNode(a); nname.addEventListener('click', () => openProfile(a.id));
  root.append(el('span', { class: 'node' }), nav,
    el('div', { class: 'pb' },
      el('div', { class: 'hd' }, nname, el('span', { class: 'ac', text: '@' + a.acct }),
        el('span', { class: 'tm', 'data-t': n.created_at, text: ago(n.created_at) })),
      el('div', { class: 'content' }, label)));
  return root;
}

/* ---------- タイムライン(列) ---------- */
const COLS = {
  home: { title: 'ホーム', path: '/api/v1/timelines/home', params: {}, kind: 'status' },
  local: { title: 'ローカル', path: '/api/v1/timelines/public', params: { local: 'true' }, kind: 'status' },
  notif: { title: '通知', path: '/api/v1/notifications', params: {}, kind: 'notif' },
};
let current = 'home';

function buildCols() {
  const host = $('#cols');
  host.textContent = '';
  for (const [k, c] of Object.entries(COLS)) {
    Object.assign(c, { key: k, byId: new Map(), newest: null, oldest: null, busy: false, loadingOld: false, ended: false,
      pending: 0, unread: 0, loaded: false });
    c.list = el('ul', { class: 'list' });
    c.pill = el('button', { class: 'pill', type: 'button', hidden: true });
    c.state = el('div', { class: 'state', hidden: true });
    c.scroller = el('section', { class: 'col' + (k === current ? ' on' : ''), 'data-k': k, 'aria-label': c.title }, c.pill, c.list, c.state);
    c.scroller.addEventListener('scroll', () => onScroll(c), { passive: true });
    c.pill.addEventListener('click', () => { c.scroller.scrollTo({ top: 0, behavior: 'smooth' }); });
    host.append(c.scroller);
  }
}

function onScroll(c) {
  const sc = c.scroller;
  if (sc.scrollLeft) sc.scrollLeft = 0; // 横にずれたら必ず元に戻す
  if (sc.scrollTop < 8) { c.pending = 0; if (c.key === current) c.unread = 0; refreshBadges(); }
  c.pill.hidden = c.pending === 0;
  c.pill.textContent = `新着 ${c.pending}件`;
  if (sc.scrollHeight - sc.scrollTop - sc.clientHeight < 700) loadOlder(c);
}

function refreshBadges() {
  for (const t of document.querySelectorAll('.tab')) {
    const c = COLS[t.dataset.k];
    const b = $('.badge', t);
    const n = t.dataset.k === current ? 0 : c.unread;
    b.hidden = n === 0;
    b.textContent = n > 99 ? '99+' : String(n);
  }
}

function renderItem(c, it) {
  const node = c.kind === 'notif' ? renderNotification(it) : renderStatus(it);
  node.dataset.id = it.id;
  const li = el('li', { 'data-id': it.id });
  li.append(node);
  return li;
}

// アプリを開いている間に通知が来たら、画面の上にポップアップで知らせる(タップで通知タブへ)
let popTimer;
function popupNotif(list) {
  if (document.visibilityState !== 'visible') return;
  const n = list[0];
  const a = n.account || {};
  const name = a.display_name || a.username || '';
  const snip = n.status && n.status.content ? new DOMParser().parseFromString(n.status.content, 'text/html').body.textContent.trim().slice(0, 40) : '';
  let box = document.getElementById('notifPop');
  if (!box) {
    box = el('div', { id: 'notifPop' });
    box.style.cssText = 'position:fixed;left:50%;transform:translateX(-50%);top:calc(env(safe-area-inset-top) + 8px);z-index:70;width:92%;max-width:420px;padding:10px 14px;border-radius:12px;background:var(--surface);color:var(--ink);border:1px solid var(--rule);box-shadow:0 6px 20px rgba(0,0,0,.35);font-size:14px;line-height:1.4;cursor:pointer';
    box.addEventListener('click', () => { box.hidden = true; show('notif'); });
    document.body.append(box);
  }
  box.textContent = '';
  box.append(el('b', { text: name }), (NOTICE[n.type] || '') + (list.length > 1 ? `(ほか${list.length - 1}件)` : ''));
  if (snip) box.append(el('div', { text: snip, style: 'color:var(--sub);font-size:13px;margin-top:2px' }));
  box.hidden = false;
  clearTimeout(popTimer);
  popTimer = setTimeout(() => { box.hidden = true; }, 4500);
}

function addItems(c, items, mode) {
  const fresh = items.filter((x) => x && !c.byId.has(x.id));
  if (!fresh.length) return 0;
  fresh.sort((a, b) => cmpId(b.id, a.id));
  const sc = c.scroller;
  const prevH = sc.scrollHeight, prevTop = sc.scrollTop;
  for (const it of fresh) {
    c.byId.set(it.id, it);
    const li = renderItem(c, it);
    if (mode === 'live') li.firstChild.classList.add('fresh');
    let ref = null;
    for (const x of c.list.children) { if (cmpId(x.dataset.id, it.id) < 0) { ref = x; break; } }
    c.list.insertBefore(li, ref);
  }
  c.newest = c.list.firstElementChild ? c.list.firstElementChild.dataset.id : null;
  c.oldest = c.list.lastElementChild ? c.list.lastElementChild.dataset.id : null;
  if (mode === 'live' || mode === 'newer') {
    if (prevTop > 8) {
      sc.scrollTop = prevTop + (sc.scrollHeight - prevH); // 読んでいる位置を動かさない
      c.pending += fresh.length;
    }
    if (c.key !== current) c.unread += fresh.length;
    if (c.key === 'notif' && current !== 'notif') popupNotif(fresh);
    onScroll(c); refreshBadges();
    if (prevTop <= 8) trim(c);
  }
  c.state.hidden = c.list.children.length > 0 && !c.state.textContent;
  saveCache();
  return fresh.length;
}

function trim(c) {
  while (c.list.children.length > KEEP) {
    const last = c.list.lastElementChild;
    c.byId.delete(last.dataset.id); last.remove();
    c.oldest = c.list.lastElementChild ? c.list.lastElementChild.dataset.id : null;
    c.ended = false;
  }
}

async function fetchNewer(c) {
  if (c.busy) return;
  c.busy = true;
  try {
    if (!c.newest) {
      const r = await api(c.path, { params: { ...c.params, limit: 40 } });
      addItems(c, r, 'initial');
      c.loaded = true;
      if (!r.length) { c.state.textContent = 'まだ投稿がありません。'; c.state.hidden = false; }
      return;
    }
    let min = c.newest, drained = false;
    for (let i = 0; i < 5; i++) {
      const r = await api(c.path, { params: { ...c.params, min_id: min, limit: 40 } });
      if (!r.length) { drained = true; break; }
      addItems(c, r, 'newer');
      min = maxId(r);
      if (r.length < 40) { drained = true; break; }
    }
    if (!drained) { // 長く離れていて追いつけない: 最新から読み直す
      c.byId.clear(); c.list.textContent = ''; c.newest = c.oldest = null; c.pending = c.unread = 0;
      const r = await api(c.path, { params: { ...c.params, limit: 40 } });
      addItems(c, r, 'initial');
    }
  } catch (e) {
    if (!c.loaded) { c.state.textContent = `読み込めませんでした: ${e.message}`; c.state.hidden = false; }
  } finally { c.busy = false; }
}

async function loadOlder(c) {
  if (c.loadingOld || c.ended || !c.oldest || !c.loaded) return;
  c.loadingOld = true;
  try {
    const r = await api(c.path, { params: { ...c.params, max_id: c.oldest, limit: 40 } });
    if (!r.length) c.ended = true;
    addItems(c, r, 'older');
  } catch {} finally { c.loadingOld = false; }
}

const catchUpAll = () => Promise.all(Object.values(COLS).map(fetchNewer));

// 前回のタイムラインを端末に控えておき、次に開いたとき最初から表示する(読み込み待ちの空白を出さない)
const cacheKey = () => `tl.cache.${S.host}.${S.me && S.me.id}`;
let saveTimer;
function saveCache() {
  clearTimeout(saveTimer);
  saveTimer = setTimeout(() => {
    const out = {};
    for (const [k, c] of Object.entries(COLS)) out[k] = [...c.list.children].slice(0, 40).map((li) => c.byId.get(li.dataset.id)).filter(Boolean);
    store.set(cacheKey(), out);
  }, 1500);
}
function restoreCache() {
  const d = store.get(cacheKey());
  if (!d) return;
  for (const [k, c] of Object.entries(COLS)) if (d[k] && d[k].length) { addItems(c, d[k], 'initial'); c.loaded = true; }
}


function removeStatus(id) {
  for (const c of Object.values(COLS)) {
    for (const n of c.list.querySelectorAll(`[data-oid="${id}"]`)) {
      const li = n.closest('li');
      if (li) { c.byId.delete(li.dataset.id); li.remove(); }
    }
    c.newest = c.list.firstElementChild ? c.list.firstElementChild.dataset.id : null;
    c.oldest = c.list.lastElementChild ? c.list.lastElementChild.dataset.id : null;
  }
}

function replaceStatus(s) {
  for (const c of Object.values(COLS)) {
    for (const li of [...c.list.children]) {
      const it = c.byId.get(li.dataset.id);
      if (!it) continue;
      let hit = false;
      if (c.kind === 'notif') { if (it.status && (it.status.id === s.id)) { it.status = s; hit = true; } else if (it.status && it.status.reblog && it.status.reblog.id === s.id) { it.status.reblog = s; hit = true; } }
      else if (it.id === s.id) { c.byId.set(it.id, s); Object.assign(it, s); hit = true; }
      else if (it.reblog && it.reblog.id === s.id) { it.reblog = s; hit = true; }
      if (hit) li.replaceWith(renderItem(c, c.byId.get(li.dataset.id)));
    }
  }
}

/* ---------- ブースト・お気に入り ---------- */
function setAct(oid, kind, on, count) {
  const cls = kind === 'reblog' ? 'boost' : 'fav';
  for (const b of document.querySelectorAll(`[data-oid="${oid}"] .act.${cls}`)) {
    b.classList.toggle('on', on); b.setAttribute('aria-pressed', String(on));
    if (count != null) $('.n', b).textContent = count > 0 ? String(count) : '';
  }
}
async function toggle(s, kind, btn) {
  const on = btn.classList.contains('on');
  const cur = parseInt($('.n', btn).textContent || '0', 10) || 0;
  setAct(s.id, kind, !on, Math.max(0, cur + (on ? -1 : 1)));
  try {
    const r = await api(`/api/v1/statuses/${s.id}/${on ? 'un' : ''}${kind}`, { method: 'POST' });
    const o = r.reblog || r;
    setAct(s.id, kind, kind === 'reblog' ? !!o.reblogged : !!o.favourited, kind === 'reblog' ? o.reblogs_count : o.favourites_count);
  } catch (e) {
    setAct(s.id, kind, on, cur);
    toast(`操作できませんでした: ${e.message}`);
  }
}

/* ---------- ライブ更新(ストリーミング) ---------- */
const Live = { ws: null, tries: 0, timer: null, hiddenAt: 0 };

function setLink(state) {
  const l = $('#link');
  l.dataset.s = state;
  $('#linkText').textContent = state === 'live' ? 'ライブ' : state === 'down' ? '再接続中' : '接続中';
}

function connect() {
  clearTimeout(Live.timer);
  if (Live.ws) { const o = Live.ws; Live.ws = null; o.onopen = o.onclose = o.onerror = o.onmessage = null; try { o.close(); } catch {} }
  setLink('connecting');
  let ws;
  try { ws = new WebSocket(`${S.stream}/api/v1/streaming?access_token=${encodeURIComponent(S.token)}`); }
  catch { setLink('down'); scheduleReconnect(); return; }
  Live.ws = ws;
  ws.onopen = () => {
    Live.tries = 0; setLink('live');
    ws.send(JSON.stringify({ type: 'subscribe', stream: 'user' }));
    ws.send(JSON.stringify({ type: 'subscribe', stream: 'public:local' }));
    catchUpAll(); // 切れていた間の分を取り直す
  };
  ws.onmessage = (ev) => { try { onEvent(JSON.parse(ev.data)); } catch {} };
  ws.onclose = () => { if (Live.ws !== ws) return; setLink('down'); scheduleReconnect(); };
  ws.onerror = () => { try { ws.close(); } catch {} };
}
function scheduleReconnect() {
  const d = Math.min(1000 * 2 ** Live.tries++, 15000);
  clearTimeout(Live.timer);
  Live.timer = setTimeout(connect, d);
}

function onEvent(m) {
  const streams = Array.isArray(m.stream) ? m.stream : [m.stream];
  if (m.event === 'update') {
    const st = JSON.parse(m.payload);
    if (streams.includes('user')) addItems(COLS.home, [st], 'live');
    if (streams.includes('public:local')) addItems(COLS.local, [st], 'live');
  } else if (m.event === 'notification') {
    addItems(COLS.notif, [JSON.parse(m.payload)], 'live');
  } else if (m.event === 'delete') {
    removeStatus(String(m.payload));
  } else if (m.event === 'status.update') {
    replaceStatus(JSON.parse(m.payload));
  }
}

function startLiveUpdates() {
  connect();
  setInterval(() => { if (document.visibilityState === 'visible') catchUpAll(); }, POLL_MS);
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState === 'hidden') { Live.hiddenAt = Date.now(); return; }
    // iPhoneは裏に回ると接続が静かに死ぬことがあるので、戻ってきたら必ずつなぎ直す
    if (!Live.ws || Live.ws.readyState !== 1 || Date.now() - Live.hiddenAt > 15000) connect();
    catchUpAll();
    tickTimes();
  });
  window.addEventListener('online', () => { connect(); });
  window.addEventListener('pageshow', (e) => { if (e.persisted) { connect(); catchUpAll(); } });
  setInterval(tickTimes, 30000);
}

function tickTimes() {
  for (const t of document.querySelectorAll('.tm[data-t]')) t.textContent = ago(t.dataset.t);
}

/* ---------- タブ・メニュー ---------- */
function show(k, dir) {
  if (k === current) {
    const c = COLS[k];
    c.scroller.scrollTo({ top: 0, behavior: 'smooth' });
    fetchNewer(c);
    return;
  }
  current = k;
  document.body.dataset.k = k;
  $('#title').textContent = COLS[k].title;
  for (const t of document.querySelectorAll('.tab')) t.setAttribute('aria-current', String(t.dataset.k === k));
  for (const [key, c] of Object.entries(COLS)) c.scroller.classList.toggle('on', key === k);
  const c = COLS[k];
  if (c.scroller.scrollTop < 8) { c.unread = 0; c.pending = 0; }
  onScroll(c); refreshBadges();
  store.set('tl.tab', k);
  layoutCols(0, true);
  for (const [key, col] of Object.entries(COLS)) col.scroller.setAttribute('aria-hidden', String(key !== k));
}


/* ---------- 左右スワイプ: 指に列がついてきて、隣の列が見える(Subway Tooter風) ---------- */
const TAB_ORDER = ['home', 'local', 'notif'];
function layoutCols(dx = 0, animate = true) {
  const cur = TAB_ORDER.indexOf(current);
  TAB_ORDER.forEach((k, i) => {
    const sc = COLS[k].scroller;
    sc.style.transition = animate ? '' : 'none';
    sc.style.transform = `translate3d(calc(${(i - cur) * 100}% + ${dx}px), 0, 0)`;
  });
}
function wireSwipe() {
  const host = $('#cols');
  let sx = 0, sy = 0, t0 = 0, dx = 0, mode = null; // mode: null | 'wait' | 'h'(横にドラッグ中) | 'v'(縦スクロール)
  host.addEventListener('touchstart', (e) => {
    const t = e.touches[0];
    // 2本指・コードの上・画面の左端(iPhoneの「戻る」スワイプ)から始まった操作は対象外
    if (e.touches.length !== 1 || t.clientX < 24 || e.target.closest('pre')) { mode = null; return; }
    sx = t.clientX; sy = t.clientY; t0 = Date.now(); dx = 0; mode = 'wait';
  }, { passive: true });
  host.addEventListener('touchmove', (e) => {
    if (mode !== 'wait' && mode !== 'h') return;
    const t = e.touches[0], mx = t.clientX - sx, my = t.clientY - sy;
    if (mode === 'wait') {
      if (Math.abs(mx) < 8 && Math.abs(my) < 8) return;
      mode = Math.abs(mx) > Math.abs(my) * 1.2 ? 'h' : 'v';
      if (mode === 'v') return;
    }
    const i = TAB_ORDER.indexOf(current);
    const edge = (mx > 0 && i === 0) || (mx < 0 && i === TAB_ORDER.length - 1);
    dx = edge ? mx * 0.25 : mx; // 端では重くして「これ以上ない」と伝える
    layoutCols(dx, false);
  }, { passive: true });
  const end = (cancelled) => {
    if (mode !== 'h') { mode = null; return; }
    mode = null;
    const w = host.clientWidth || 1, dt = Math.max(1, Date.now() - t0);
    const fast = Math.abs(dx) > 30 && Math.abs(dx) / dt > 0.45;
    let i = TAB_ORDER.indexOf(current);
    if (!cancelled && (Math.abs(dx) > w * 0.25 || fast)) i += dx < 0 ? 1 : -1;
    i = Math.max(0, Math.min(TAB_ORDER.length - 1, i));
    dx = 0;
    if (TAB_ORDER[i] !== current) show(TAB_ORDER[i]); else layoutCols(0, true);
  };
  host.addEventListener('touchend', () => end(false), { passive: true });
  host.addEventListener('touchcancel', () => end(true), { passive: true });
}

/* ---------- 投稿 ---------- */
const C = { reply: null, edit: null, media: [], key: null, sending: false };
const cText = $('#cText'), cVis = $('#cVis'), cCw = $('#cCw'), cSend = $('#cSend'), cCount = $('#cCount');

function openCompose(replyTo) {
  if (C.edit) resetComposer();
  C.reply = replyTo || null;
  C.key = rand(12);
  const box = $('#cReply');
  if (replyTo) {
    box.hidden = false; box.textContent = '';
    box.append(`${replyTo.account.display_name || replyTo.account.username} (@${replyTo.account.acct}) への返信: `, (replyTo.content ? sanitizeText(replyTo.content) : ''));
    const draft = `@${replyTo.account.acct} `;
    cText.value = draft;
    cVis.value = replyTo.visibility === 'public' ? (store.get('tl.vis') || 'public') : (replyTo.visibility || 'public');
  } else {
    box.hidden = true;
    cText.value = store.get('tl.draft') || '';
    cVis.value = store.get('tl.vis') || 'public';
  }
  $('#composer').hidden = false;
  fitComposer(); updateCompose();
  setTimeout(() => { cText.focus(); cText.setSelectionRange(cText.value.length, cText.value.length); }, 50);
}
function sanitizeText(html) { const d = new DOMParser().parseFromString(html, 'text/html'); return d.body.textContent.slice(0, 120); }

function closeCompose() { $('#composer').hidden = true; }

function resetComposer() {
  cText.value = ''; cCw.value = ''; cCw.hidden = true; $('#cSens').checked = false; $('#cCwBtn').setAttribute('aria-pressed', 'false');
  C.media = []; C.reply = null; C.edit = null; cVis.disabled = false; cSend.textContent = '投稿する';
  renderMedia();
}

async function openEdit(s) {
  if (s.poll) { toast('投票つきの投稿は、このバージョンでは編集できません。'); return; }
  let src;
  try { src = await api(`/api/v1/statuses/${s.id}/source`); }
  catch (e) { toast(`編集を始められませんでした: ${e.message}`); return; }
  resetComposer();
  C.edit = s; C.key = null;
  cText.value = src.text || '';
  if (src.spoiler_text) { cCw.hidden = false; cCw.value = src.spoiler_text; $('#cCwBtn').setAttribute('aria-pressed', 'true'); }
  cVis.value = s.visibility; cVis.disabled = true;
  C.media = (s.media_attachments || []).map((m) => ({ id: m.id, existing: true, type: m.type, preview: m.preview_url || m.url, alt: m.description || '', origAlt: m.description || '' }));
  $('#cSens').checked = !!s.sensitive;
  const box = $('#cReply'); box.hidden = false; box.textContent = '投稿を編集中です。編集した履歴は、ほかの人にも見えることがあります。';
  cSend.textContent = '保存する';
  renderMedia();
  $('#composer').hidden = false;
  fitComposer(); updateCompose();
  setTimeout(() => { cText.focus(); }, 50);
}

function countChars() {
  const t = cText.value.replace(/https?:\/\/\S+/g, 'x'.repeat(23)).replace(/(^|\s)@([\w.-]+)@[\w.-]+/g, '$1@$2');
  return [...t].length + [...cCw.value].length;
}
function updateCompose() {
  const left = S.maxChars - countChars();
  cCount.textContent = String(left);
  cCount.classList.toggle('over', left < 0);
  const uploading = C.media.some((m) => !m.id);
  const hasContent = cText.value.trim() || C.media.length;
  cSend.disabled = !hasContent || left < 0 || uploading || C.sending;
  $('#cSensWrap').hidden = C.media.length === 0;
}

function fitComposer() {
  const v = window.visualViewport, c = $('#composer');
  if (!v) return;
  c.style.height = v.height + 'px';
  c.style.top = v.offsetTop + 'px';
}
if (window.visualViewport) {
  window.visualViewport.addEventListener('resize', fitComposer);
  window.visualViewport.addEventListener('scroll', fitComposer);
}

cText.addEventListener('input', () => { if (!C.reply && !C.edit) store.set('tl.draft', cText.value); updateCompose(); });
cCw.addEventListener('input', updateCompose);
cVis.addEventListener('change', () => store.set('tl.vis', cVis.value));
$('#cCwBtn').addEventListener('click', (e) => {
  cCw.hidden = !cCw.hidden;
  e.currentTarget.setAttribute('aria-pressed', String(!cCw.hidden));
  if (!cCw.hidden) cCw.focus(); else cCw.value = '';
  updateCompose();
});
$('#cCancel').addEventListener('click', () => { if (C.edit) resetComposer(); closeCompose(); });

// 大きすぎる写真は、アップロード前に長辺2048pxへ縮小する(失敗したら元のまま送る)
async function shrinkImage(f, max = 2048) {
  if (!/^image\/(jpeg|png|heic|heif|webp)$/i.test(f.type)) return f;
  try {
    const bmp = await createImageBitmap(f, { imageOrientation: 'from-image' });
    const sc = Math.min(1, max / Math.max(bmp.width, bmp.height));
    if (sc >= 1 && f.size < 4 * 1024 * 1024) { bmp.close?.(); return f; }
    const w = Math.round(bmp.width * sc), h = Math.round(bmp.height * sc);
    const cv = document.createElement('canvas'); cv.width = w; cv.height = h;
    cv.getContext('2d').drawImage(bmp, 0, 0, w, h); bmp.close?.();
    const png = /png/i.test(f.type);
    const blob = await new Promise((ok) => cv.toBlob(ok, png ? 'image/png' : 'image/jpeg', 0.9));
    if (!blob) return f;
    return new File([blob], f.name.replace(/\.[^.]+$/, '') + (png ? '.png' : '.jpg'), { type: blob.type });
  } catch { return f; }
}

$('#cFile').addEventListener('change', async (e) => {
  const files = [...e.target.files]; e.target.value = '';
  for (const f of files) {
    if (C.media.length >= S.maxMedia) { toast(`添付は${S.maxMedia}つまでです。`); break; }
    const m = { id: null, file: f, alt: '' };
    C.media.push(m); renderMedia(); updateCompose();
    try {
      const fd = new FormData(); fd.append('file', await shrinkImage(f), f.name);
      let r = await api('/api/v2/media', { method: 'POST', body: fd });
      for (let i = 0; r.__status === 202 && i < 60; i++) {
        await new Promise((ok) => setTimeout(ok, 1500));
        r = await api(`/api/v1/media/${r.id}`);
        if (r.__status !== 206) break;
      }
      m.id = r.id;
    } catch (err) {
      C.media.splice(C.media.indexOf(m), 1);
      toast(`アップロードできませんでした: ${err.message}`);
    }
    renderMedia(); updateCompose();
  }
});

function renderMedia() {
  const box = $('#cMedia'); box.textContent = '';
  for (const m of C.media) {
    const isVid = m.file ? m.file.type.startsWith('video/') : false;
    const url = m.file ? URL.createObjectURL(m.file) : m.preview;
    const pv = el('div', { class: 'pv' }, isVid ? el('video', { src: url, muted: true, playsinline: true }) : el('img', { src: url, alt: '' }));
    if (!m.id) pv.append(el('div', { class: 'busy', text: '送信中…' }));
    pv.append(el('button', { class: 'x', type: 'button', 'aria-label': '添付を外す', text: '×', onclick: () => { C.media.splice(C.media.indexOf(m), 1); renderMedia(); updateCompose(); } }));
    const alt = el('input', { type: 'text', placeholder: '代替テキスト(任意)', value: m.alt });
    alt.addEventListener('input', () => { m.alt = alt.value; });
    box.append(el('div', { class: 'thumb' }, pv, alt));
  }
}

cSend.addEventListener('click', async () => {
  if (cSend.disabled) return;
  C.sending = true; updateCompose();
  try {
    for (const m of C.media) if (!m.existing && m.alt.trim()) await api(`/api/v1/media/${m.id}`, { method: 'PUT', body: { description: m.alt.trim() } });
    if (C.edit) {
      const e = C.edit;
      const body = { status: cText.value, spoiler_text: cCw.hidden ? '' : cCw.value.trim(), language: e.language || 'ja',
        sensitive: C.media.length ? $('#cSens').checked : false, media_ids: C.media.map((m) => m.id) };
      const attrs = C.media.filter((m) => m.existing && m.alt.trim() !== m.origAlt).map((m) => ({ id: m.id, description: m.alt.trim() }));
      if (attrs.length) body.media_attributes = attrs;
      const upd = await api(`/api/v1/statuses/${e.id}`, { method: 'PUT', body });
      replaceStatus(upd);
      resetComposer(); closeCompose(); toast('保存しました');
      return;
    }
    const body = { status: cText.value, visibility: cVis.value, language: 'ja', __key: C.key };
    if (C.reply) body.in_reply_to_id = C.reply.id;
    if (!cCw.hidden && cCw.value.trim()) body.spoiler_text = cCw.value.trim();
    if (C.media.length) { body.media_ids = C.media.map((m) => m.id); body.sensitive = $('#cSens').checked; }
    await api('/api/v1/statuses', { method: 'POST', body });
    store.del('tl.draft');
    cText.value = ''; cCw.value = ''; cCw.hidden = true; $('#cSens').checked = false; $('#cCwBtn').setAttribute('aria-pressed', 'false');
    C.media = []; C.reply = null; renderMedia();
    closeCompose();
    toast('投稿しました');
    fetchNewer(COLS.home);
  } catch (e) {
    toast(`${C.edit ? '保存' : '投稿'}できませんでした: ${e.message}`);
  } finally { C.sending = false; updateCompose(); }
});



/* ---------- プロフィール(投稿した人のページ・自分のページ) ---------- */
const PROFILE_CSS = `
.av, .nm, .ac { cursor: pointer; }
.prof { position: fixed; inset: 0; z-index: 25; background: var(--bg); display: flex; flex-direction: column; --line: var(--home); }
.prof-bar { flex: none; display: flex; align-items: center; gap: 6px; height: calc(var(--bar-h) + env(safe-area-inset-top)); padding: env(safe-area-inset-top) 12px 0 6px; background: var(--surface); border-bottom: 3px solid var(--line); }
.prof-bar button { border: 0; background: none; padding: 8px 10px; font-weight: 700; font-size: 15px; }
.prof-bar h2 { margin: 0; font-size: 16px; flex: 1; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.prof-scroll { flex: 1; min-height: 0; overflow-y: auto; -webkit-overflow-scrolling: touch; overscroll-behavior-y: contain; }
.prof-hdr { height: 110px; background: var(--rule) center / cover no-repeat; }
.prof-main { padding: 0 16px 14px; background: var(--surface); border-bottom: 1px solid var(--rule); }
.prof-top { display: flex; align-items: flex-end; justify-content: space-between; margin-top: -34px; }
.prof-av { width: 72px; height: 72px; border-radius: 14px; border: 3px solid var(--surface); background: var(--rule); object-fit: cover; display: block; }
.prof-name { font-size: 19px; font-weight: 800; margin: 8px 0 0; overflow-wrap: anywhere; line-height: 1.3; }
.prof-acct { color: var(--sub); font-size: 13.5px; overflow-wrap: anywhere; display: flex; flex-wrap: wrap; gap: 6px; align-items: center; }
.fbtn { border: 1px solid var(--ink); background: var(--ink); color: var(--bg); border-radius: 8px; padding: 7px 16px; font-weight: 700; }
.fbtn.on { background: none; color: var(--ink); }
.fbtn:disabled { opacity: .4; }
.prof-note { margin-top: 10px; }
.prof-fields { margin: 10px 0 0; border: 1px solid var(--rule); border-radius: 8px; overflow: hidden; }
.prof-fields > div { display: grid; grid-template-columns: 96px minmax(0, 1fr); gap: 8px; padding: 6px 10px; border-top: 1px solid var(--rule); font-size: 13.5px; }
.prof-fields > div:first-child { border-top: 0; }
.prof-fields dt { color: var(--sub); font-weight: 600; overflow-wrap: anywhere; }
.prof-fields dd { margin: 0; overflow-wrap: anywhere; }
.prof-fields a { color: var(--line); text-decoration: none; }
.prof-counts { display: flex; gap: 18px; margin-top: 10px; color: var(--sub); font-size: 13.5px; }
.prof-counts b { color: var(--ink); font-size: 15px; margin-right: 3px; }
.prof-tabs { display: flex; background: var(--surface); border-bottom: 1px solid var(--rule); }
.prof-tabs button { flex: 1; padding: 10px 4px; border: 0; background: none; color: var(--sub); font-weight: 600; border-bottom: 3px solid transparent; }
.prof-tabs button[aria-current="true"] { color: var(--ink); border-bottom-color: var(--line); }
`;
(function injectProfileStyles() {
  const st = document.createElement('style'); st.textContent = PROFILE_CSS; document.head.append(st);
})();

const Prof = { stack: [], box: null, token: 0, id: null, tab: 'posts', oldest: null, ended: false, loading: false, list: null, state: null, scroller: null, rel: null };
const PROF_TABS = { posts: { label: '投稿', params: { exclude_replies: 'true' } }, replies: { label: '返信も', params: {} }, media: { label: 'メディア', params: { only_media: 'true' } } };

function ensureProfileBox() {
  if (Prof.box) return Prof.box;
  const back = el('button', { type: 'button', text: '← 戻る', 'aria-label': '戻る' });
  back.addEventListener('click', () => history.back());
  Prof.title = el('h2');
  Prof.scroller = el('div', { class: 'prof-scroll' });
  Prof.scroller.addEventListener('scroll', () => {
    const sc = Prof.scroller;
    if (sc.scrollHeight - sc.scrollTop - sc.clientHeight < 700) loadProfilePosts();
  }, { passive: true });
  Prof.box = el('section', { class: 'prof', hidden: true, 'aria-label': 'プロフィール' },
    el('div', { class: 'prof-bar' }, back, Prof.title), Prof.scroller);
  document.body.append(Prof.box);
  return Prof.box;
}

function openProfile(id) {
  if (!id) return;
  const box = ensureProfileBox();
  if (Prof.stack[Prof.stack.length - 1] === id && !box.hidden) return;
  Prof.stack.push(id);
  history.pushState({ tl: 'prof', n: Prof.stack.length }, '');
  box.hidden = false;
  renderProfile(id);
}

window.addEventListener('popstate', (e) => {
  if (!Prof.box) return;
  const n = e.state && e.state.tl === 'prof' ? e.state.n : 0;
  Prof.stack.length = Math.min(Prof.stack.length, n);
  if (n === 0) { Prof.box.hidden = true; Prof.token++; return; }
  renderProfile(Prof.stack[n - 1]);
});

const num = (n) => Number(n || 0).toLocaleString('ja-JP');

async function renderProfile(id) {
  const my = ++Prof.token;
  Prof.id = id; Prof.tab = 'posts'; Prof.oldest = null; Prof.ended = false; Prof.loading = false;
  Prof.title.textContent = '';
  const sc = Prof.scroller; sc.textContent = ''; sc.scrollTop = 0;
  sc.append(el('div', { class: 'state', text: '読み込み中…' }));
  let acc, rel = null;
  try {
    const isMe = S.me && id === S.me.id;
    [acc, rel] = await Promise.all([
      api(`/api/v1/accounts/${id}`),
      isMe ? null : api('/api/v1/accounts/relationships', { params: { 'id[]': id } }).then((r) => r[0] || null).catch(() => null),
    ]);
  } catch (e) {
    if (my !== Prof.token) return;
    sc.textContent = ''; sc.append(el('div', { class: 'state', text: `読み込めませんでした: ${e.message}` }));
    return;
  }
  if (my !== Prof.token) return;
  Prof.rel = rel;
  Prof.title.replaceChildren(...withEmoji(acc.display_name || acc.username, acc.emojis));
  sc.textContent = '';

  const hdr = el('div', { class: 'prof-hdr' });
  const hdrUrl = acc.header_static || acc.header;
  if (hdrUrl && !/missing\.png$/.test(hdrUrl)) hdr.style.backgroundImage = `url("${hdrUrl.replace(/"/g, '%22')}")`;
  const top = el('div', { class: 'prof-top' }, el('img', { class: 'prof-av', src: acc.avatar_static || acc.avatar, alt: '' }));
  if (rel) {
    const fb = el('button', { type: 'button', class: 'fbtn' });
    const paint = () => {
      const r = Prof.rel || {};
      fb.className = 'fbtn' + (r.following || r.requested ? ' on' : '');
      fb.textContent = r.following ? 'フォロー中' : r.requested ? 'リクエスト済み' : 'フォローする';
    };
    paint();
    fb.addEventListener('click', async () => {
      const r = Prof.rel || {}; fb.disabled = true;
      try { Prof.rel = await api(`/api/v1/accounts/${id}/${r.following || r.requested ? 'unfollow' : 'follow'}`, { method: 'POST' }); }
      catch (e) { toast(`操作できませんでした: ${e.message}`); }
      fb.disabled = false; paint();
    });
    top.append(fb);
  }
  const acctLine = el('div', { class: 'prof-acct' }, '@' + acc.acct);
  if (rel && rel.followed_by) acctLine.append(el('span', { class: 'vis', text: 'フォローされています' }));
  if (acc.locked) acctLine.append(el('span', { class: 'vis', text: '承認制' }));
  if (acc.bot) acctLine.append(el('span', { class: 'vis', text: 'Bot' }));
  const main = el('div', { class: 'prof-main' }, top,
    el('h3', { class: 'prof-name' }, ...withEmoji(acc.display_name || acc.username, acc.emojis)), acctLine);
  if (acc.note && acc.note !== '<p></p>') main.append(el('div', { class: 'content prof-note' }, sanitize(acc.note, acc.emojis)));
  const fields = (acc.fields || []).filter((f) => f.name);
  if (fields.length) {
    const dl = el('dl', { class: 'prof-fields' });
    for (const f of fields) dl.append(el('div', {}, el('dt', {}, ...withEmoji(f.name, acc.emojis)), el('dd', {}, sanitize(f.value, acc.emojis))));
    main.append(dl);
  }
  main.append(el('div', { class: 'prof-counts' },
    el('span', {}, el('b', { text: num(acc.statuses_count) }), '投稿'),
    el('span', {}, el('b', { text: num(acc.following_count) }), 'フォロー'),
    el('span', {}, el('b', { text: num(acc.followers_count) }), 'フォロワー')));

  const tabs = el('div', { class: 'prof-tabs', role: 'tablist' });
  for (const [k, t] of Object.entries(PROF_TABS)) {
    const b = el('button', { type: 'button', role: 'tab', 'aria-current': String(k === Prof.tab), text: t.label });
    b.addEventListener('click', () => {
      if (Prof.tab === k) return;
      Prof.tab = k; Prof.oldest = null; Prof.ended = false;
      for (const x of tabs.children) x.setAttribute('aria-current', String(x === b));
      Prof.list.textContent = '';
      loadProfilePosts();
    });
    tabs.append(b);
  }
  Prof.list = el('ul', { class: 'list' });
  Prof.state = el('div', { class: 'state', text: '読み込み中…' });
  sc.append(hdr, main, tabs, Prof.list, Prof.state);
  loadProfilePosts();
}

async function loadProfilePosts() {
  if (Prof.loading || Prof.ended || !Prof.list) return;
  Prof.loading = true;
  const my = Prof.token, tab = Prof.tab, first = !Prof.oldest;
  try {
    const r = await api(`/api/v1/accounts/${Prof.id}/statuses`, { params: { ...PROF_TABS[tab].params, limit: 20, max_id: Prof.oldest } });
    if (my !== Prof.token || tab !== Prof.tab) return;
    for (const st of r) {
      const li = el('li', { 'data-id': st.id }); li.append(renderStatus(st)); Prof.list.append(li);
    }
    if (r.length) Prof.oldest = minId(r);
    if (r.length < 5) Prof.ended = true;
    Prof.state.hidden = Prof.list.children.length > 0;
    if (!Prof.list.children.length) Prof.state.textContent = '投稿はありません。';
  } catch (e) {
    if (first && my === Prof.token) { Prof.state.hidden = false; Prof.state.textContent = `読み込めませんでした: ${e.message}`; }
  } finally { Prof.loading = false; }
}

/* ---------- プッシュ通知(アプリを閉じていても届く) ---------- */
const PUSH_KINDS = ['mention', 'reblog', 'favourite', 'follow'];
const PUSH_DEFAULT = { mention: true, reblog: true, favourite: true, follow: true, follow_request: true, poll: true, status: false, update: false };
const pushSupported = () => 'serviceWorker' in navigator && 'PushManager' in window && typeof Notification !== 'undefined';
const hasPushScope = () => (S.scope || '').split(/\s+/).includes('push');
const b64uToBytes = (s) => { const p = '='.repeat((4 - (s.length % 4)) % 4); const b = atob((s + p).replace(/-/g, '+').replace(/_/g, '/')); return Uint8Array.from(b, (c) => c.charCodeAt(0)); };

async function getVapidKey() {
  if (S.vapid) return S.vapid;
  const app = (store.get('tl.apps') || {})[S.host];
  if (app && app.vapid) return app.vapid;
  try { const r = await api('/api/v1/apps/verify_credentials'); if (r.vapid_key) return r.vapid_key; } catch {}
  throw new Error('このサーバーは通知の設定を公開していません。');
}

async function pushState() {
  // 'unsupported' | 'noscope' | 'off' | 'on'
  if (!pushSupported()) return { s: 'unsupported' };
  if (!hasPushScope()) return { s: 'noscope' };
  try {
    const r = await api('/api/v1/push/subscription');
    const reg = await navigator.serviceWorker.ready;
    const sub = await reg.pushManager.getSubscription();
    if (sub && sub.endpoint === r.endpoint) return { s: 'on', alerts: r.alerts || {} };
  } catch {}
  return { s: 'off' };
}

async function enablePush() {
  if (Notification.permission === 'denied') throw new Error('通知が拒否されています。iPhoneの「設定」→「通知」→ Tootline で許可してください。');
  const perm = await Notification.requestPermission();
  if (perm !== 'granted') throw new Error('通知が許可されませんでした。');
  const reg = await navigator.serviceWorker.ready;
  const old = await reg.pushManager.getSubscription();
  if (old) { try { await old.unsubscribe(); } catch {} }
  const key = await getVapidKey();
  const sub = await reg.pushManager.subscribe({ userVisibleOnly: true, applicationServerKey: b64uToBytes(key) });
  const j = sub.toJSON();
  const alerts = store.get('tl.pushAlerts') || PUSH_DEFAULT;
  await api('/api/v1/push/subscription', { method: 'POST', body: {
    subscription: { endpoint: j.endpoint, keys: { p256dh: j.keys.p256dh, auth: j.keys.auth } },
    data: { alerts: { ...PUSH_DEFAULT, ...alerts }, policy: 'all' } } });
}

async function disablePush() {
  try { await api('/api/v1/push/subscription', { method: 'DELETE' }); } catch {}
  try { const reg = await navigator.serviceWorker.ready; const sub = await reg.pushManager.getSubscription(); if (sub) await sub.unsubscribe(); } catch {}
}

async function refreshPushUi() {
  const btn = $('#pushBtn'), note = $('#pushNote'), kinds = $('#pushKinds');
  btn.disabled = true; kinds.hidden = true;
  const st = await pushState();
  btn.disabled = false; btn.dataset.s = st.s;
  if (st.s === 'unsupported') {
    btn.textContent = '通知は使えません'; btn.disabled = true;
    note.textContent = 'ホーム画面に追加したTootlineのアイコンから開いたときだけ使えます(iOS 16.4以降)。';
  } else if (st.s === 'noscope') {
    btn.textContent = '通知のためにログインし直す';
    note.textContent = '通知を受け取る権限が必要です。ログインし直すと付与されます。';
  } else if (st.s === 'on') {
    btn.textContent = '通知をオフにする';
    note.textContent = 'アプリを閉じていても通知が届きます。';
    kinds.hidden = false;
    for (const k of PUSH_KINDS) $(`#pk-${k}`).checked = st.alerts[k] !== false;
  } else {
    btn.textContent = '通知をオンにする';
    note.textContent = 'アプリを閉じていても、返信やブーストなどを通知します。';
  }
}

function wirePush() {
  $('#pushBtn').addEventListener('click', async (e) => {
    const b = e.currentTarget, s = b.dataset.s;
    if (s === 'noscope') { logout(); return; }
    b.disabled = true;
    try {
      if (s === 'on') { await disablePush(); toast('通知をオフにしました'); }
      else { await enablePush(); toast('通知をオンにしました'); }
    } catch (err) { toast(err.message); }
    refreshPushUi();
  });
  for (const k of PUSH_KINDS) {
    $(`#pk-${k}`).addEventListener('change', async () => {
      const alerts = { ...PUSH_DEFAULT, ...(store.get('tl.pushAlerts') || {}) };
      for (const x of PUSH_KINDS) alerts[x] = $(`#pk-${x}`).checked;
      store.set('tl.pushAlerts', alerts);
      try { await api('/api/v1/push/subscription', { method: 'PUT', body: { data: { alerts } } }); }
      catch (err) { toast(`変更できませんでした: ${err.message}`); }
    });
  }
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.addEventListener('message', (e) => {
      if (e.data && e.data.type === 'open-notif') { show('notif'); fetchNewer(COLS.notif); }
    });
  }
}

/* ---------- 起動 ---------- */
function showLogin(msg) {
  $('#login').hidden = false; $('#app').hidden = true;
  const standalone = window.navigator.standalone === true || matchMedia('(display-mode: standalone)').matches;
  const ios = /iPhone|iPad|iPod/.test(navigator.userAgent);
  $('#installHint').hidden = !(ios && !standalone);
  if (msg) { const e = $('#loginError'); e.textContent = msg; e.hidden = false; }
  const last = store.get('tl.lastHost'); if (last) $('#host').value = last;
}

$('#loginForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  const btn = e.submitter || $('#loginForm button'); btn.disabled = true;
  $('#loginError').hidden = true;
  try { store.set('tl.lastHost', normalizeHost($('#host').value)); await startLogin($('#host').value); }
  catch (err) { const m = $('#loginError'); m.textContent = err.message; m.hidden = false; btn.disabled = false; }
});

async function boot() {
  if ('serviceWorker' in navigator && (location.protocol === 'https:' || isLocalHost(location.host))) {
    navigator.serviceWorker.register('sw.js').catch(() => {});
  }
  const q = new URLSearchParams(location.search);
  const wantTab = q.get('tab');
  if (wantTab && COLS[wantTab]) { current = wantTab; history.replaceState(null, '', REDIRECT); }
  if (q.has('code') || q.has('error')) {
    const code = q.get('code'), state = q.get('state'), err = q.get('error_description') || q.get('error');
    history.replaceState(null, '', REDIRECT);
    if (err) return showLogin(`ログインがキャンセルされました(${err})`);
    try { await finishLogin(code, state); } catch (e) { return showLogin(e.message); }
  }
  const ses = store.get('tl.session');
  if (!ses) return showLogin();
  S = { ...ses };
  $('#login').hidden = true; $('#app').hidden = false;
  Object.assign(S, await loadInstance());
  try {
    S.me = await api('/api/v1/accounts/verify_credentials');
  } catch (e) { if (e.message !== '401') toast('アカウント情報を取得できませんでした'); S.me = { acct: ses.host, avatar: '', display_name: '' }; }
  $('#meImg').src = S.me.avatar_static || S.me.avatar || '';
  const savedTab = store.get('tl.tab'); if (COLS[savedTab] && !(wantTab && COLS[wantTab])) current = savedTab;
  document.body.dataset.k = current; $('#title').textContent = COLS[current].title;
  for (const t of document.querySelectorAll('.tab')) t.setAttribute('aria-current', String(t.dataset.k === current));
  buildCols();
  layoutCols(0, false);
  wireSwipe();
  restoreCache();
  for (const t of document.querySelectorAll('.tab')) t.addEventListener('click', () => show(t.dataset.k));
  $('#composeBtn').addEventListener('click', () => openCompose(null));
  $('#meBtn').addEventListener('click', () => { $('#menuWho').textContent = `@${S.me.acct}@${S.host}`; $('#menu').hidden = false; refreshPushUi(); });
  $('#ver').textContent = `Tootline ${VERSION}`;
  wireTheme();
  if (S.me && S.me.id) {
    const pb = el('button', { type: 'button', id: 'profBtn', text: '自分のプロフィール' });
    pb.addEventListener('click', () => { $('#menu').hidden = true; openProfile(S.me.id); });
    $('#menuWho').after(pb);
  }
  wirePush();
  $('#menuClose').addEventListener('click', () => { $('#menu').hidden = true; });
  $('#menu').addEventListener('click', (e) => { if (e.target.id === 'menu') $('#menu').hidden = true; });
  $('#logoutBtn').addEventListener('click', logout);
  $('#reloadBtn').addEventListener('click', () => {
    $('#menu').hidden = true;
    for (const c of Object.values(COLS)) { c.byId.clear(); c.list.textContent = ''; c.newest = c.oldest = null; c.ended = false; c.loaded = false; c.pending = c.unread = 0; c.state.hidden = true; c.state.textContent = ''; }
    refreshBadges(); catchUpAll();
  });
  await catchUpAll();
  startLiveUpdates();
}

boot();
