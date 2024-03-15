var CACHE_NAME = 'luadrop-cache-v1';
var urlsToCache = [
  '/',
  'index.html',
  'styles.css',
  'manifest.json',
  'scripts/network.js',
  'scripts/ui.js',
  'scripts/theme.js',
  'scripts/clipboard.js',
  'scripts/qr-code.js',
  'scripts/qr-code.resources.js',
  'scripts/qr-code.animation.js',
  'sounds/blop.mp3',
  'sounds/blop.ogg',
  'images/logo_transparent_128x128.png',
  'images/favicon-96x96.png',
  'images/android-chrome-192x192.png'
];

self.addEventListener('install', function(event) {
  // Perform install steps
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(function(cache) {
        console.log('Opened cache');
        return cache.addAll(urlsToCache);
      })
  );
});

self.addEventListener('fetch', function(event) {
  event.respondWith(
    caches.match(event.request)
      .then(function(response) {
        // Cache hit - return response
        if (response) {
          return response;
        }
        return fetch(event.request);
      }
    )
  );
});

self.addEventListener('activate', function(event) {
  console.log('Updating Service Worker...')
  event.waitUntil(
    caches.keys().then(function(cacheNames) {
      return Promise.all(
        cacheNames.filter(function(cacheName) {
          // Return true if you want to remove this cache,
          // but remember that caches are shared across
          // the whole origin
          return true
        }).map(function(cacheName) {
          return caches.delete(cacheName);
        })
      );
    })
  );
});
