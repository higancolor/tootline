'use strict';
/* Tootline — 自動更新に強いMastodonクライアント(ホーム / ローカル / 通知)
   外部ライブラリなし。ログイン情報はこの端末のlocalStorageにだけ保存される。 */

const APP_NAME = 'Tootline';
const SCOPES = 'read write';
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
  if (!app || app.redirect !== REDIRECT) {
    let r;
    try {
      r = await fetch(httpBase(host) + '/api/v1/apps', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ client_name: APP_NAME, redirect_uris: REDIRECT, scopes: SCOPES, website: REDIRECT }),
      });
    } catch { throw new Error(`${host} に接続できません。ドメインを確かめてください。`); }
    if (!r.ok) throw new Error(`${host} がアプリの登録を受け付けませんでした(${r.status})。`);
    const j = await r.json();
    app = { client_id: j.client_id, client_secret: j.client_secret, redirect: REDIRECT };
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
  store.set('tl.session', { host: p.host, token: tok.access_token });
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
  store.del('tl.session');
  location.replace(REDIRECT);
}

async function loadInstance() {
  const base = { stream: 'wss://' + S.host, maxChars: 500, maxMedia: 4 };
  if (isLocalHost(S.host)) base.stream = 'ws://' + S.host;
  try {
    const r = await fetch(httpBase(S.host) + '/api/v2/instance');
    if (r.ok) {
      const j = await r.json();
      const c = j.configuration || {};
      if (c.urls && c.urls.streaming) base.stream = c.urls.streaming;
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

const nameNode = (acc) => el('span', { class: 'nm' }, ...withEmoji(acc.display_name || acc.username, acc.emojis));
const VIS = { unlisted: 'ひかえめ', private: '限定', direct: 'DM' };
const ICON = {
  reply: '<path d="M9 14 4 9l5-5"/><path d="M4 9h10a6 6 0 0 1 6 6v3"/>',
  boost: '<path d="m17 2 4 4-4 4"/><path d="M3 11V9a3 3 0 0 1 3-3h15"/><path d="m7 22-4-4 4-4"/><path d="M21 13v2a3 3 0 0 1-3 3H3"/>',
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
      openViewer(m);
    });
    box.append(b);
  }
  return box;
}

function openViewer(m) {
  const v = $('#viewer');
  v.textContent = '';
  if (m.type === 'video' || m.type === 'gifv') v.append(el('video', { src: m.url, controls: true, autoplay: true, playsinline: true, ...(m.type === 'gifv' ? { loop: true } : {}) }));
  else v.append(el('img', { src: m.url, alt: m.description || '' }));
  v.hidden = false;
}
$('#viewer').addEventListener('click', () => { const v = $('#viewer'); v.hidden = true; v.textContent = ''; });

function actBtn(kind, label, count, on, handler) {
  return el('button', { class: `act ${kind}${on ? ' on' : ''}`, type: 'button', 'aria-label': label, 'aria-pressed': kind === 'reply' ? null : String(!!on), onclick: handler },
    icon(kind), el('span', { class: 'n', text: count > 0 ? String(count) : '' }));
}

function contentBlock(s) {
  const body = el('div', { class: 'content' }, sanitize(s.content, s.emojis));
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
  else if (st.reblog) body.append(el('div', { class: 'hint' }, nameNode(st.account), 'がブースト'));
  const hd = el('div', { class: 'hd' }, nameNode(a), el('span', { class: 'ac', text: '@' + a.acct }));
  if (VIS[s.visibility]) hd.append(el('span', { class: 'vis', text: VIS[s.visibility] }));
  hd.append(el('a', { class: 'tm', href: s.url || s.uri, target: '_blank', rel: 'noopener', 'data-t': s.created_at, text: ago(s.created_at) }));
  body.append(hd, contentBlock(s));
  const mb = mediaBlock(s); if (mb) body.append(mb);
  if (s.poll) body.append(el('div', { class: 'poll', text: '投票つき(このバージョンでは表示のみ・投票はブラウザで)' }));
  const acts = el('div', { class: 'acts' },
    actBtn('reply', '返信', s.replies_count, false, () => openCompose(s)),
    actBtn('boost', 'ブースト', s.reblogs_count, s.reblogged, (e) => toggle(s, 'reblog', e.currentTarget)),
    actBtn('fav', 'お気に入り', s.favourites_count, s.favourited, (e) => toggle(s, 'favourite', e.currentTarget)));
  body.append(acts);
  root.append(el('span', { class: 'node' }), el('img', { class: 'av', src: a.avatar_static || a.avatar, alt: '', loading: 'lazy' }), body);
  return root;
}

const NOTICE = {
  favourite: 'がお気に入りにしました', reblog: 'がブーストしました', follow: 'にフォローされました',
  follow_request: 'からフォローリクエスト', poll: '投票が終了しました', update: 'が投稿を編集しました', status: 'が投稿しました',
};
function renderNotification(n) {
  if (n.type === 'mention' && n.status) {
    const e = renderStatus(n.status, { notice: el('span', {}, nameNode(n.account), 'からの返信・メンション') });
    e.classList.add('notice');
    return e;
  }
  const label = NOTICE[n.type] || (n.type || '通知');
  if (n.status) {
    const e = renderStatus(n.status, { notice: el('span', {}, nameNode(n.account), label) });
    e.classList.add('notice');
    return e;
  }
  const a = n.account;
  const root = el('article', { class: 'post notice' });
  root.append(el('span', { class: 'node' }), el('img', { class: 'av', src: a.avatar_static || a.avatar, alt: '', loading: 'lazy' }),
    el('div', { class: 'pb' },
      el('div', { class: 'hd' }, nameNode(a), el('span', { class: 'ac', text: '@' + a.acct }),
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
    c.state = el('div', { class: 'state', text: '読み込み中…' });
    c.scroller = el('section', { class: 'col' + (k === current ? ' on' : ''), 'data-k': k, 'aria-label': c.title }, c.pill, c.list, c.state);
    c.scroller.addEventListener('scroll', () => onScroll(c), { passive: true });
    c.pill.addEventListener('click', () => { c.scroller.scrollTo({ top: 0, behavior: 'smooth' }); });
    host.append(c.scroller);
  }
}

function onScroll(c) {
  const sc = c.scroller;
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
    onScroll(c); refreshBadges();
    if (prevTop <= 8) trim(c);
  }
  c.state.hidden = c.list.children.length > 0;
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
function show(k) {
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
}

/* ---------- 投稿 ---------- */
const C = { reply: null, media: [], key: null, sending: false };
const cText = $('#cText'), cVis = $('#cVis'), cCw = $('#cCw'), cSend = $('#cSend'), cCount = $('#cCount');

function openCompose(replyTo) {
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

cText.addEventListener('input', () => { if (!C.reply) store.set('tl.draft', cText.value); updateCompose(); });
cCw.addEventListener('input', updateCompose);
cVis.addEventListener('change', () => store.set('tl.vis', cVis.value));
$('#cCwBtn').addEventListener('click', (e) => {
  cCw.hidden = !cCw.hidden;
  e.currentTarget.setAttribute('aria-pressed', String(!cCw.hidden));
  if (!cCw.hidden) cCw.focus(); else cCw.value = '';
  updateCompose();
});
$('#cCancel').addEventListener('click', closeCompose);

$('#cFile').addEventListener('change', async (e) => {
  const files = [...e.target.files]; e.target.value = '';
  for (const f of files) {
    if (C.media.length >= S.maxMedia) { toast(`添付は${S.maxMedia}つまでです。`); break; }
    const m = { id: null, file: f, alt: '' };
    C.media.push(m); renderMedia(); updateCompose();
    try {
      const fd = new FormData(); fd.append('file', f);
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
    const isVid = m.file.type.startsWith('video/');
    const url = URL.createObjectURL(m.file);
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
    for (const m of C.media) if (m.alt.trim()) await api(`/api/v1/media/${m.id}`, { method: 'PUT', body: { description: m.alt.trim() } });
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
    toast(`投稿できませんでした: ${e.message}`);
  } finally { C.sending = false; updateCompose(); }
});

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
  const savedTab = store.get('tl.tab'); if (COLS[savedTab]) current = savedTab;
  document.body.dataset.k = current; $('#title').textContent = COLS[current].title;
  for (const t of document.querySelectorAll('.tab')) t.setAttribute('aria-current', String(t.dataset.k === current));
  buildCols();
  for (const t of document.querySelectorAll('.tab')) t.addEventListener('click', () => show(t.dataset.k));
  $('#composeBtn').addEventListener('click', () => openCompose(null));
  $('#meBtn').addEventListener('click', () => { $('#menuWho').textContent = `@${S.me.acct}@${S.host}`; $('#menu').hidden = false; });
  $('#menuClose').addEventListener('click', () => { $('#menu').hidden = true; });
  $('#menu').addEventListener('click', (e) => { if (e.target.id === 'menu') $('#menu').hidden = true; });
  $('#logoutBtn').addEventListener('click', logout);
  $('#reloadBtn').addEventListener('click', () => {
    $('#menu').hidden = true;
    for (const c of Object.values(COLS)) { c.byId.clear(); c.list.textContent = ''; c.newest = c.oldest = null; c.ended = false; c.loaded = false; c.pending = c.unread = 0; c.state.hidden = false; c.state.textContent = '読み込み中…'; }
    refreshBadges(); catchUpAll();
  });
  await catchUpAll();
  startLiveUpdates();
}

boot();
