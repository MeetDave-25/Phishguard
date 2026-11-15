// PhishGuard service worker: makes the site installable, shows an offline page, and receives shared text.
// Privacy: it caches only the site's own static files. It NEVER caches pages, API calls or anything you paste.
const VERSION = "__VERSION__";
const STATIC = "pg-static-" + VERSION;
const SHELL = ["/offline", "/static/style.css", "/static/site.js", "/static/favicon.svg", "/static/icon-192.png"];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(STATIC).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys()
      .then((keys) => Promise.all(keys.filter((k) => k.startsWith("pg-static-") && k !== STATIC).map((k) => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

async function staleWhileRevalidate(req) {
  const cache = await caches.open(STATIC);
  const hit = await cache.match(req);
  const net = fetch(req).then((res) => { if (res.ok) cache.put(req, res.clone()); return res; }).catch(() => hit);
  return hit || net;
}

// "Share to PhishGuard": the shared text is stored in the browser only, then the page picks it up and checks it.
async function handleShare(req) {
  try {
    const fd = await req.formData();
    const text = [fd.get("title"), fd.get("text"), fd.get("url")].filter(Boolean).join("\n").slice(0, 5000);
    const cache = await caches.open("pg-share");
    await cache.put("/__shared", new Response(text));
  } catch (_) { /* fall through to the page with nothing shared */ }
  return Response.redirect("/?shared=1#checker", 303);
}

self.addEventListener("fetch", (e) => {
  const req = e.request, url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  if (req.method === "POST" && url.pathname === "/share-target") { e.respondWith(handleShare(req)); return; }
  if (req.method !== "GET") return;
  if (url.pathname.startsWith("/api/")) return;                      // scans always go to the network, never cached
  if (url.pathname.startsWith("/static/")) { e.respondWith(staleWhileRevalidate(req)); return; }
  if (req.mode === "navigate") {                                     // pages: always fresh; offline page only if the network is down
    e.respondWith(fetch(req).catch(() => caches.match("/offline")));
  }
});
