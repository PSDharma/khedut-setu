const STATIC_CACHE = 'khedut-setu-static-v7.3.0-pro';
const CDN_CACHE = 'khedut-setu-cdn-v7.3.0-pro';
const MAX_CDN_ENTRIES = 60;
const NAV_TIMEOUT_MS = 4000;

const CORE_ASSETS = ['./', './index.html', './manifest.json', './icon-192.png'];

const ALLOWED_CDN_HOSTS = new Set([
  'cdn.tailwindcss.com',
  'cdn.jsdelivr.net',
  'unpkg.com',
  'fonts.googleapis.com',
  'fonts.gstatic.com'
]);

const NEVER_CACHE_HOSTS = [
  'supabase.co',
  'data.gov.in',
  'generativelanguage.googleapis.com'
];

function isSensitiveHost(hostname) {
  return NEVER_CACHE_HOSTS.some((h) => hostname === h || hostname.endsWith('.' + h));
}

async function trimCache(cacheName, maxItems) {
  try {
    const cache = await caches.open(cacheName);
    const keys = await cache.keys();
    if (keys.length > maxItems) {
      await Promise.all(keys.slice(0, keys.length - maxItems).map((k) => cache.delete(k)));
    }
  } catch {}
}

function fetchWithTimeout(request, timeoutMs) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  return fetch(request, { signal: controller.signal }).finally(() => clearTimeout(timer));
}

function offlineFallbackResponse() {
  const html = `<!DOCTYPE html><html lang="gu"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>KHEDUT SETU — Offline</title><style>body{font-family:system-ui,sans-serif;background:#f6f8f5;color:#1e293b;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;padding:20px;text-align:center}.card{background:#fff;border:1px solid #cbd5e1;border-radius:16px;padding:24px;max-width:380px}button{background:#15803d;color:#fff;border:0;border-radius:10px;padding:10px 20px;font-weight:700;cursor:pointer;margin-top:12px}</style></head><body><div class="card"><h2>🌾 KHEDUT SETU</h2><p>હાલ ઇન્ટરનેટ બંધ છે. કૃપા કરીને નેટવર્ક ચાલુ કરી ફરી પ્રયાસ કરો.</p><p style="font-size:12px;color:#64748b">You are offline. Reconnect and reload.</p><button onclick="location.reload()">🔄 Retry / રિફ્રેશ</button></div></body></html>`;
  return new Response(html, {
    status: 503,
    headers: { 'Content-Type': 'text/html; charset=utf-8' }
  });
}

self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(STATIC_CACHE).then(async (cache) => {
      await Promise.allSettled(
        CORE_ASSETS.map(async (url) => {
          const res = await fetch(url, { cache: 'no-cache' });
          if (res && res.ok) await cache.put(url, res.clone());
        })
      );
    })
  );
});

self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys()
      .then((keys) =>
        Promise.all(
          keys
            .filter((k) => k !== STATIC_CACHE && k !== CDN_CACHE)
            .map((k) => caches.delete(k))
        )
      )
      .then(() => self.clients.claim())
  );
});

self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

self.addEventListener('fetch', (event) => {
  const req = event.request;
  if (req.method !== 'GET') return;

  let reqUrl;
  try {
    reqUrl = new URL(req.url);
  } catch {
    return;
  }

  if (reqUrl.protocol !== 'http:' && reqUrl.protocol !== 'https:') return;
  if (isSensitiveHost(reqUrl.hostname)) return;

  const isSameOrigin = reqUrl.origin === self.location.origin;
  if (isSameOrigin && reqUrl.pathname.endsWith('/sw.js')) return;

  const isAllowedCdn = ALLOWED_CDN_HOSTS.has(reqUrl.hostname);
  if (!isSameOrigin && !isAllowedCdn) return;

  const isHtml = req.mode === 'navigate' || req.destination === 'document';
  if (isSameOrigin && isHtml) {
    event.respondWith(
      fetchWithTimeout(req, NAV_TIMEOUT_MS)
        .then((res) => {
          if (res && res.ok) {
            const copy = res.clone();
            caches.open(STATIC_CACHE).then((c) => c.put('./index.html', copy)).catch(() => {});
          }
          return res;
        })
        .catch(() =>
          caches.match(req)
            .then((r) => r || caches.match('./index.html'))
            .then((r) => r || caches.match('./'))
            .then((r) => r || offlineFallbackResponse())
        )
    );
    return;
  }

  const targetCache = isSameOrigin ? STATIC_CACHE : CDN_CACHE;
  event.respondWith(
    caches.open(targetCache).then(async (cache) => {
      const cached = await cache.match(req);
      const networkPromise = fetch(req)
        .then((res) => {
          if (res && (res.ok || res.type === 'opaque')) {
            cache.put(req, res.clone()).catch(() => {});
            if (targetCache === CDN_CACHE) trimCache(CDN_CACHE, MAX_CDN_ENTRIES);
          }
          return res;
        })
        .catch(() => null);

      if (cached) {
        event.waitUntil(networkPromise);
        return cached;
      }
      const netRes = await networkPromise;
      return netRes || new Response('', { status: 504 });
    })
  );
});
