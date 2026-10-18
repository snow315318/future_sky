// The public front door on Vercel. Every request to the Vercel address is passed on to the server on your PC
// (ORIGIN_URL, e.g. https://103.179.45.80:8443) together with the visitor's own IP address and a secret only this
// proxy knows (PROXY_SECRET — the same value is in server/.env on the PC). The connection to the PC is encrypted, and
// only the PC's own certificate (origin-cert.pem, whose fingerprint must also match ORIGIN_FINGERPRINT) is accepted.
// Responses stream straight back, so videos, uploads, chat and the live updates of open pages keep working; when the
// PC cannot be reached, visitors see a short maintenance page.
import http from 'node:http';
import https from 'node:https';
import { readFileSync } from 'node:fs';
import path from 'node:path';

const CERT = readFileSync(path.join(process.cwd(), 'origin-cert.pem'), 'utf8');
// headers about the hop to Vercel, not about the request itself
const DROP = new Set(['host', 'connection', 'content-length', 'transfer-encoding', 'keep-alive', 'upgrade', 'forwarded', 'x-forwarded-for', 'x-forwarded-host', 'x-forwarded-port', 'x-forwarded-proto', 'x-real-ip', 'x-client-ip', 'x-proxy-secret', 'x-vercel-id', 'x-vercel-deployment-url', 'x-vercel-forwarded-for', 'x-vercel-ip-country', 'x-vercel-ip-country-region', 'x-vercel-ip-city', 'x-vercel-ip-latitude', 'x-vercel-ip-longitude', 'x-vercel-ip-timezone', 'x-vercel-proxied-for', 'x-vercel-proxy-signature', 'x-vercel-proxy-signature-ts', 'x-vercel-sc-headers', 'x-vercel-sc-host', 'x-vercel-sc-basepath', 'x-matched-path', 'x-invoke-path', 'x-invoke-query', 'x-invoke-output']);

export default function handler(req, res) {
  const origin = new URL(String(process.env.ORIGIN_URL || 'https://127.0.0.1:8443'));
  const secret = String(process.env.PROXY_SECRET || '');
  const pin = String(process.env.ORIGIN_FINGERPRINT || '').toUpperCase();
  if (!secret || !pin) return void res.writeHead(500, { 'content-type': 'text/plain; charset=utf-8' }).end('The proxy is not configured yet (ORIGIN_URL / PROXY_SECRET / ORIGIN_FINGERPRINT).');

  // the path the visitor asked for (vercel.json sends every path here as ?__p=/<path>, with the original query)
  const url = new URL(req.url, 'http://x');
  const wanted = url.searchParams.get('__p') || '/';
  url.searchParams.delete('__p');
  const target = (wanted.startsWith('/') ? wanted : `/${wanted}`) + (url.search || '');

  const headers = {};
  for (const [k, v] of Object.entries(req.headers)) if (!DROP.has(k)) headers[k] = v;
  headers.host = origin.host;
  headers['x-proxy-secret'] = secret;
  headers['x-client-ip'] = String(req.headers['x-real-ip'] || String(req.headers['x-forwarded-for'] || '').split(',')[0]).trim();
  headers['x-forwarded-proto'] = 'https';
  if (req.headers['content-length']) headers['content-length'] = req.headers['content-length'];
  if (req.headers['transfer-encoding']) headers['transfer-encoding'] = req.headers['transfer-encoding'];

  const secure = origin.protocol === 'https:';
  const options = {
    host: origin.hostname,
    port: origin.port || (secure ? 443 : 80),
    method: req.method,
    path: target,
    headers,
    // only the PC's own certificate: trusted as its own authority, and its fingerprint must match
    ...(secure
      ? {
          ca: CERT,
          servername: 'futuresky-origin',
          checkServerIdentity: (_host, cert) => (String(cert.fingerprint256 || '').toUpperCase() === pin ? undefined : new Error('origin certificate does not match')),
        }
      : {}),
  };
  const up = (secure ? https : http).request(options, (r) => {
    const out = { ...r.headers };
    delete out.connection;
    delete out['keep-alive'];
    delete out['transfer-encoding'];
    // a redirect to the PC's address comes back to the Vercel address
    if (typeof out.location === 'string' && out.location.startsWith(origin.origin)) out.location = out.location.slice(origin.origin.length) || '/';
    res.writeHead(r.statusCode || 502, out);
    r.pipe(res);
  });
  up.setTimeout(55_000, () => up.destroy(new Error('timeout')));
  up.on('error', () => {
    if (res.headersSent) return void res.end();
    res.writeHead(503, { 'content-type': 'text/html; charset=utf-8', 'retry-after': '120', 'cache-control': 'no-store' }).end(MAINTENANCE);
  });
  req.pipe(up);
}

const MAINTENANCE = `<!doctype html><html lang="ja"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>フューチャースカイ</title>
<style>body{margin:0;min-height:100vh;display:grid;place-items:center;background:linear-gradient(160deg,#1c2466,#4a3a8f 60%,#b0508a);color:#fff;font-family:'Hiragino Mincho ProN','Yu Mincho',serif;text-align:center}main{padding:40px 28px;max-width:440px}h1{font-size:1.6rem;letter-spacing:.2em;margin:0 0 16px}p{line-height:2;opacity:.9}span{font-size:2.6rem}</style></head>
<body><main><span>🛠</span><h1>フューチャースカイ</h1><p>ただいまメンテナンス中です。<br>お手数ですが、しばらくしてから<br>もう一度ご覧ください。</p></main></body></html>`;
