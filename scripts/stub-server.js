'use strict';

/**
 * Throwaway stub HTTP server for the disposable-environment example
 * (docker-compose.yml). It stands in for a benchmark Spring Boot app: it
 * echoes any JSON request body back in the response, so the dynamic
 * scanner's reflection check can be exercised end to end.
 *
 * This is NOT a benchmark application and its behaviour is NOT one of the
 * paper's CVA / SCA / SRA benchmarks. To scan a real benchmark, replace the
 * `app` service in docker-compose.yml with that application's image.
 *
 * Run directly (no Docker needed):  node scripts/stub-server.js [port]
 */

const http = require('http');

const PORT = parseInt(process.argv[2] || process.env.PORT || '8080', 10);

const server = http.createServer((req, res) => {
    if (req.url === '/health') {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ status: 'ok' }));
        return;
    }
    let body = '';
    req.on('data', (chunk) => { body += chunk; });
    req.on('end', () => {
        let parsed = null;
        try { parsed = body ? JSON.parse(body) : null; } catch (_) { parsed = null; }
        res.writeHead(200, { 'Content-Type': 'application/json' });
        // Echo the received body back, so injected fields are reflected.
        res.end(JSON.stringify(parsed === null ? { received: body } : parsed));
    });
});

server.listen(PORT, () => {
    console.log(`stub server listening on http://localhost:${PORT}`);
});
