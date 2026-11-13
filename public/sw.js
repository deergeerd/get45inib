// Minimal service worker. Its only jobs: let the browser treat the site as an installable app,
// and show a friendly screen when there's no connection. It never touches /api/*, so messages and
// photos always come live from the server and can never be served stale.
const CACHE = "chat-shell-v1";
const OFFLINE = "/offline.html";

self.addEventListener("install", (event) => {
  event.waitUntil((async () => {
    const res = await fetch(OFFLINE, { cache: "reload" });
    if (!res.ok) throw new Error("offline page unavailable");
    // Re-wrap the body: a response that was redirected can't be used to answer a navigation.
    const clean = new Response(await res.blob(), { status: 200, headers: { "Content-Type": "text/html; charset=utf-8" } });
    await (await caches.open(CACHE)).put(OFFLINE, clean);
    await self.skipWaiting();
  })());
});

self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    for (const k of await caches.keys()) if (k !== CACHE) await caches.delete(k);
    await self.clients.claim();
  })());
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;
  if (url.pathname.startsWith("/api/")) return;               // never intercepted
  if (req.mode === "navigate") {
    // Network first, so a new deploy shows up on the next load; the offline page only if the network fails.
    event.respondWith(fetch(req).catch(async () => (await caches.match(OFFLINE)) || Response.error()));
  }
  // everything else (icons, manifest, ...) is left to the browser's normal handling
});
