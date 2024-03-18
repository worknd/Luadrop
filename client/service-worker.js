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
        caches.open(CACHE_NAME).then((cache) => {
            console.log('Filling cache...');
            return cache.addAll(urlsToCache);
        }).then(() => {self.skipWaiting();console.log('...Ok');})
    );
});

self.addEventListener('activate', function(event) {
    event.waitUntil(
        caches.keys().then((cacheNames) => {
            return Promise.all(cacheNames.map((cache) => {
                if(cache !== CACHE_NAME) {
                    console.log('Deleting old cache:', cache);
                    return caches.delete(cache);
                }
            }))
        })
    )
});

function fromCache(request) {
    return caches.open(CACHE_NAME).then((cache) =>
        cache.match(request).then((matching) =>
            matching || fetch(request).then((response) =>
                {cache.put(request, response.clone());return response;}
            )
        )
    );
}

self.addEventListener('fetch', function(event) {
    event.respondWith(fromCache(event.request));
});
