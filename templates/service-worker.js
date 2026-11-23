// TimeStat service worker.
//
// Strategies:
//   * Static assets under /static/  -> stale-while-revalidate (serves cached,
//     refreshes in the background). Keeps the app usable offline / on flaky
//     networks and loads fast on repeat visits.
//   * Navigation (HTML document) requests -> network-first, falling back to a
//     cached copy of the requested page, then the cached /login shell, so a
//     reload while offline still works without redirect loops.
//   * Everything else (API, SSE, auth POSTs) -> passthrough; never cached.
//
// CACHE_VERSION is the server-computed content hash of the static directory
// (see app.py _compute_static_version), injected when this file is served.
// A deploy that changes any asset therefore produces a new cache name AND new
// versioned asset URLs together - no hand-bumping required.

const CACHE_VERSION = "timestat-cache-{{ cache_version }}";
const ASSET_VERSION = "{{ cache_version }}";
const CORE_ASSETS = [
  "/static/app.css?v=" + ASSET_VERSION,
  "/static/js/common.js?v=" + ASSET_VERSION,
  "/static/js/theme.js?v=" + ASSET_VERSION,
  "/static/manifest.json?v=" + ASSET_VERSION,
  "/static/logo.svg?v=" + ASSET_VERSION,
  // Unversioned to match the URL the stylesheet's @font-face resolves to
  // (see the preload comment in base.html); a versioned entry here would
  // never be hit by the real request. Deploy-time invalidation still works:
  // the whole cache is keyed by CACHE_VERSION.
  "/static/fonts/material-symbols-rounded.woff2",
  // The dashboard (start_url) always loads Chart.js, so precaching it costs
  // nothing extra and makes the first offline visit render charts too.
  "/static/vendor/chart.umd.min.js?v=" + ASSET_VERSION,
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(CACHE_VERSION);
      // core assets are best-effort; don't fail install if one is missing
      await cache.addAll(CORE_ASSETS).catch(() => {});
      await self.skipWaiting();
    })()
  );
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    (async () => {
      const keys = await caches.keys();
      const hadOlderCache = keys.some((k) => k !== CACHE_VERSION);
      await Promise.all(
        keys.filter((k) => k !== CACHE_VERSION).map((k) => caches.delete(k))
      );
      await self.clients.claim();
      // clients.claim() takes over already-open tabs immediately, with no
      // prompt - tell them a new version is active so stale in-memory JS
      // doesn't silently keep running against newer cached assets.
      if (hadOlderCache) {
        const clients = await self.clients.matchAll({ type: "window" });
        clients.forEach((client) => client.postMessage({ type: "sw-updated" }));
      }
    })()
  );
});

self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.method !== "GET") return;

  const url = new URL(request.url);
  // Only handle same-origin requests; let cross-origin (CDNs) hit the network.
  if (url.origin !== self.location.origin) return;
  // Never intercept the SSE stream or any API call.
  if (url.pathname.startsWith("/api/")) return;

  // Navigation (HTML page loads): network-first with cached-shell fallback.
  if (request.mode === "navigate") {
    event.respondWith(
      (async () => {
        try {
          const fresh = await fetch(request);
          const cache = await caches.open(CACHE_VERSION);
          // Cache under the actual request, not a fixed literal key - every
          // navigation used to overwrite the same "/dashboard" entry
          // regardless of which page was fetched, so the offline fallback
          // could serve a completely different page's stale HTML under the
          // URL the user actually requested.
          cache.put(request, fresh.clone()).catch(() => {});
          return fresh;
        } catch (_err) {
          const cached = await caches.match(request);
          // Offline navigation falls back to the cached login page, never
          // /dashboard: when signed out /dashboard redirects to /login, so
          // serving it here would loop the redirect forever.
          return cached || (await caches.match("/login")) || Response.error();
        }
      })()
    );
    return;
  }

  // Static assets: stale-while-revalidate.
  if (url.pathname.startsWith("/static/")) {
    event.respondWith(
      (async () => {
        const cache = await caches.open(CACHE_VERSION);
        const cached = await cache.match(request);
        const network = fetch(request)
          .then((response) => {
            if (response && response.status === 200) {
              cache.put(request, response.clone()).catch(() => {});
            }
            return response;
          })
          .catch(() => null);
        return cached || (await network) || Response.error();
      })()
    );
  }
});
