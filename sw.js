// Tootline service worker: アプリ本体(HTML/CSS/JS)だけをキャッシュする。
// Mastodon のAPI(別ドメイン)には一切触れない。
const CACHE = 'tootline-v3';
const SHELL = ['./', 'index.html', 'style.css', 'app.js', 'manifest.webmanifest',
  'icon-192.png', 'icon-512.png', 'apple-touch-icon.png'];

self.addEventListener('install', (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener('activate', (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (e) => {
  const req = e.request;
  const url = new URL(req.url);
  if (req.method !== 'GET' || url.origin !== self.location.origin) return;
  // 先にキャッシュを返し、裏で最新版を取り直す(次回起動で新しくなる)
  e.respondWith(
    caches.open(CACHE).then(async (cache) => {
      const hit = await cache.match(req, { ignoreSearch: true });
      const net = fetch(req).then((res) => {
        if (res.ok) cache.put(req, res.clone());
        return res;
      }).catch(() => hit);
      return hit || net;
    })
  );
});

// ---- プッシュ通知(Mastodon から Apple/Google の通知サーバー経由で届く) ----
self.addEventListener('push', (e) => {
  let d = {};
  try { d = e.data ? e.data.json() : {}; } catch { d = { body: e.data ? e.data.text() : '' }; }
  // iPhoneは、届いた通知を必ず表示しないと購読を取り消されるので、常に表示する
  e.waitUntil(self.registration.showNotification(d.title || 'Tootline', {
    body: d.body || '',
    icon: d.icon || 'icon-192.png',
    badge: 'icon-192.png',
    tag: d.notification_id ? 'n' + d.notification_id : undefined,
    data: { id: d.notification_id || null },
  }));
});

self.addEventListener('notificationclick', (e) => {
  e.notification.close();
  e.waitUntil(self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((list) => {
    for (const c of list) {
      if ('focus' in c) { c.postMessage({ type: 'open-notif' }); return c.focus(); }
    }
    return self.clients.openWindow('./?tab=notif');
  }));
});
