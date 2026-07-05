'use strict';

const http = require('http');
const https = require('https');
const tls = require('tls');
const net = require('net');
const dns = require('dns');
const fs = require('fs');
const path = require('path');

const PORT = Number(process.env.PORT) || 3000;
const REQUEST_TIMEOUT_MS = 12000;
const MAX_REDIRECTS = 5;
const MAX_BODY_BYTES = 1024 * 1024;
const USER_AGENT = 'ServerPulse/1.0 (url-health-check)';

// ---------------------------------------------------------------------------
// SSRF guard — never probe private / link-local / loopback address space
// ---------------------------------------------------------------------------

function isPrivateAddress(addr) {
  if (net.isIPv4(addr)) {
    const o = addr.split('.').map(Number);
    return (
      o[0] === 0 ||
      o[0] === 10 ||
      o[0] === 127 ||
      (o[0] === 100 && o[1] >= 64 && o[1] <= 127) ||
      (o[0] === 169 && o[1] === 254) ||
      (o[0] === 172 && o[1] >= 16 && o[1] <= 31) ||
      (o[0] === 192 && o[1] === 168)
    );
  }
  const a = addr.toLowerCase();
  if (a === '::' || a === '::1') return true;
  if (a.startsWith('fe80') || a.startsWith('fc') || a.startsWith('fd')) return true;
  const mapped = a.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return isPrivateAddress(mapped[1]);
  return false;
}

// dns.lookup-compatible resolver that rejects private address space; passed
// as the `lookup` option so validation happens on the address the socket
// actually connects to (no resolve-then-reconnect race).
function guardedLookup(hostname, options, callback) {
  if (typeof options === 'function') {
    callback = options;
    options = {};
  }
  dns.lookup(hostname, options, (err, address, family) => {
    if (err) return callback(err);
    const addrs = Array.isArray(address) ? address : [{ address, family }];
    for (const a of addrs) {
      if (isPrivateAddress(a.address ?? a)) {
        const e = new Error('target resolves to a private address');
        e.code = 'EPRIVATE';
        return callback(e);
      }
    }
    callback(null, address, family);
  });
}

// net/tls skip the lookup function for IP-literal hosts, so those need an
// explicit check before any connection attempt.
function assertPublicHost(urlObj) {
  const host = urlObj.hostname.replace(/^\[|\]$/g, '');
  if (net.isIP(host) && isPrivateAddress(host)) {
    throw Object.assign(new Error('target is a private address'), { code: 'EPRIVATE' });
  }
}

// ---------------------------------------------------------------------------
// Probing
// ---------------------------------------------------------------------------

function fetchOnce(urlObj) {
  return new Promise((resolve, reject) => {
    const isHttps = urlObj.protocol === 'https:';
    const mod = isHttps ? https : http;
    const t = { start: performance.now(), dns: null, connect: null, secure: null, firstByte: null, end: null };
    const out = { tls: null, remoteAddress: null };
    let settled = false;

    const req = mod.request(urlObj, {
      method: 'GET',
      agent: false,
      lookup: guardedLookup,
      timeout: REQUEST_TIMEOUT_MS,
      headers: {
        'user-agent': USER_AGENT,
        accept: 'text/html,application/xhtml+xml,*/*;q=0.8',
        'accept-encoding': 'br, gzip, deflate',
      },
    }, (res) => {
      t.firstByte = performance.now();
      let bodyBytes = 0;
      res.on('data', (chunk) => {
        bodyBytes += chunk.length;
        if (bodyBytes > MAX_BODY_BYTES) res.destroy();
      });
      const finish = () => {
        if (settled) return;
        settled = true;
        t.end = performance.now();
        resolve({
          statusCode: res.statusCode,
          httpVersion: res.httpVersion,
          headers: res.headers,
          bodyBytes,
          timings: t,
          tlsInfo: out.tls,
          remoteAddress: out.remoteAddress,
        });
      };
      res.on('end', finish);
      res.on('close', finish);
    });

    req.on('socket', (socket) => {
      socket.once('lookup', () => { t.dns = performance.now(); });
      socket.once('connect', () => {
        t.connect = performance.now();
        out.remoteAddress = socket.remoteAddress;
      });
      socket.once('secureConnect', () => {
        t.secure = performance.now();
        const cert = socket.getPeerCertificate();
        out.tls = {
          protocol: socket.getProtocol(),
          issuer: cert && cert.issuer ? (cert.issuer.O || cert.issuer.CN || null) : null,
          validTo: cert ? cert.valid_to || null : null,
        };
      });
    });

    req.on('timeout', () => {
      req.destroy(Object.assign(new Error('request timed out'), { code: 'ETIMEDOUT' }));
    });
    req.on('error', (err) => {
      if (!settled) { settled = true; reject(err); }
    });
    req.end();
  });
}

function alpnProbe(hostname, port) {
  return new Promise((resolve) => {
    const socket = tls.connect({
      host: hostname,
      port,
      servername: hostname,
      ALPNProtocols: ['h2', 'http/1.1'],
      lookup: guardedLookup,
      rejectUnauthorized: false,
      timeout: 5000,
    }, () => {
      const proto = socket.alpnProtocol || null;
      socket.destroy();
      resolve(proto);
    });
    socket.on('error', () => resolve(null));
    socket.on('timeout', () => { socket.destroy(); resolve(null); });
  });
}

async function probe(inputUrl) {
  let raw = String(inputUrl || '').trim();
  if (!raw) throw Object.assign(new Error('no URL provided'), { code: 'EINPUT' });
  if (!/^https?:\/\//i.test(raw)) raw = 'https://' + raw;

  let url;
  try {
    url = new URL(raw);
  } catch {
    throw Object.assign(new Error('that does not look like a valid URL'), { code: 'EINPUT' });
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw Object.assign(new Error('only http and https URLs are supported'), { code: 'EINPUT' });
  }

  const chain = [];
  let current = url;
  let hop = null;

  for (let i = 0; i <= MAX_REDIRECTS; i++) {
    assertPublicHost(current);
    hop = await fetchOnce(current);
    chain.push({ url: current.href, status: hop.statusCode });
    const loc = hop.headers.location;
    if ([301, 302, 303, 307, 308].includes(hop.statusCode) && loc) {
      if (i === MAX_REDIRECTS) {
        throw Object.assign(new Error('too many redirects'), { code: 'ELOOP' });
      }
      current = new URL(loc, current);
      if (current.protocol !== 'http:' && current.protocol !== 'https:') {
        throw Object.assign(new Error('redirected to a non-http URL'), { code: 'EINPUT' });
      }
      continue;
    }
    break;
  }

  const finalUrl = current;
  const isHttps = finalUrl.protocol === 'https:';
  const alpn = isHttps
    ? await alpnProbe(finalUrl.hostname, Number(finalUrl.port) || 443)
    : null;

  return { requestedUrl: url.href, finalUrl: finalUrl.href, isHttps, chain, hop, alpn };
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

function ms(a, b) {
  return a != null && b != null ? Math.max(0, Math.round(b - a)) : null;
}

function scale(value, bands) {
  for (const [limit, pts] of bands) {
    if (value <= limit) return pts;
  }
  return bands[bands.length - 1][1];
}

function buildReport(p) {
  const { hop, chain, isHttps, alpn } = p;
  const h = hop.headers;
  const t = hop.timings;

  const timings = {
    dns: ms(t.start, t.dns),
    tcp: ms(t.dns ?? t.start, t.connect),
    tls: ms(t.connect, t.secure),
    ttfb: ms(t.start, t.firstByte),
    total: ms(t.start, t.end),
  };

  const checks = [];
  const add = (category, id, label, status, value, points, max, hint) => {
    checks.push({ category, id, label, status, value, points, max, hint: hint || null });
  };

  // --- Performance (40) ---
  const ttfb = timings.ttfb ?? 9999;
  add('performance', 'ttfb', 'Time to first byte',
    ttfb <= 400 ? 'good' : ttfb <= 1000 ? 'warn' : 'bad',
    `${ttfb} ms`,
    scale(ttfb, [[200, 20], [400, 16], [800, 10], [1500, 5], [Infinity, 1]]), 20,
    ttfb > 400 ? 'Aim for under 400 ms — CDN, caching, or faster backend' : null);

  const total = timings.total ?? 9999;
  add('performance', 'total', 'Full response time',
    total <= 1200 ? 'good' : total <= 2500 ? 'warn' : 'bad',
    `${total} ms`,
    scale(total, [[500, 10], [1200, 7], [2500, 4], [Infinity, 1]]), 10);

  if (isHttps && timings.tls != null) {
    add('performance', 'tlstime', 'TLS handshake',
      timings.tls <= 200 ? 'good' : timings.tls <= 500 ? 'warn' : 'bad',
      `${timings.tls} ms`,
      scale(timings.tls, [[150, 5], [400, 3], [Infinity, 1]]), 5);
  } else {
    add('performance', 'tlstime', 'TLS handshake', 'bad', 'no TLS', 0, 5,
      'Plain HTTP — no encrypted transport');
  }

  const dnst = timings.dns;
  add('performance', 'dns', 'DNS lookup',
    dnst == null || dnst <= 150 ? 'good' : dnst <= 400 ? 'warn' : 'bad',
    dnst == null ? 'cached' : `${dnst} ms`,
    dnst == null ? 5 : scale(dnst, [[100, 5], [300, 3], [Infinity, 1]]), 5);

  // --- Security (35) ---
  add('security', 'https', 'HTTPS', isHttps ? 'good' : 'bad',
    isHttps ? 'enabled' : 'not used', isHttps ? 10 : 0, 10,
    isHttps ? null : 'Serve the site over HTTPS');

  const tlsProto = hop.tlsInfo ? hop.tlsInfo.protocol : null;
  add('security', 'tlsver', 'TLS version',
    tlsProto === 'TLSv1.3' ? 'good' : tlsProto === 'TLSv1.2' ? 'warn' : 'bad',
    tlsProto || 'none',
    tlsProto === 'TLSv1.3' ? 5 : tlsProto === 'TLSv1.2' ? 3 : 0, 5,
    tlsProto === 'TLSv1.2' ? 'TLS 1.3 has faster handshakes and drops legacy ciphers' : null);

  let certDays = null;
  if (hop.tlsInfo && hop.tlsInfo.validTo) {
    certDays = Math.floor((new Date(hop.tlsInfo.validTo) - Date.now()) / 86400000);
  }
  add('security', 'cert', 'Certificate validity',
    certDays == null ? 'bad' : certDays > 30 ? 'good' : certDays > 7 ? 'warn' : 'bad',
    certDays == null ? 'none' : `${certDays} days left`,
    certDays == null ? 0 : certDays > 30 ? 3 : certDays > 7 ? 1 : 0, 3);

  const hsts = !!h['strict-transport-security'];
  add('security', 'hsts', 'Strict-Transport-Security', hsts ? 'good' : 'bad',
    hsts ? 'set' : 'missing', hsts ? 5 : 0, 5,
    hsts ? null : 'HSTS stops protocol-downgrade attacks');

  const csp = !!h['content-security-policy'];
  add('security', 'csp', 'Content-Security-Policy', csp ? 'good' : 'bad',
    csp ? 'set' : 'missing', csp ? 5 : 0, 5,
    csp ? null : 'CSP is the strongest defense against XSS');

  const xcto = (h['x-content-type-options'] || '').toLowerCase() === 'nosniff';
  add('security', 'xcto', 'X-Content-Type-Options', xcto ? 'good' : 'bad',
    xcto ? 'nosniff' : 'missing', xcto ? 3 : 0, 3);

  const frame = !!h['x-frame-options'] || /frame-ancestors/i.test(h['content-security-policy'] || '');
  add('security', 'frame', 'Clickjacking protection', frame ? 'good' : 'bad',
    frame ? 'set' : 'missing', frame ? 2 : 0, 2);

  const refpol = !!h['referrer-policy'];
  add('security', 'refpol', 'Referrer-Policy', refpol ? 'good' : 'warn',
    refpol ? h['referrer-policy'] : 'missing', refpol ? 2 : 0, 2);

  // --- Best practices (25) ---
  const enc = (h['content-encoding'] || '').toLowerCase();
  const compressed = /\b(br|gzip|deflate|zstd)\b/.test(enc);
  const tiny = hop.bodyBytes < 1024;
  add('practices', 'compression', 'Compression',
    compressed ? 'good' : tiny ? 'warn' : 'bad',
    compressed ? enc : tiny ? 'small response' : 'none',
    enc.includes('br') || enc.includes('zstd') ? 7 : compressed ? 5 : tiny ? 4 : 0, 7,
    compressed || tiny ? null : 'Enable gzip or brotli on text responses');

  add('practices', 'h2', 'HTTP/2 support',
    alpn === 'h2' ? 'good' : 'warn',
    alpn === 'h2' ? 'yes' : isHttps ? 'HTTP/1.1 only' : 'n/a',
    alpn === 'h2' ? 6 : 0, 6,
    alpn === 'h2' ? null : 'HTTP/2 multiplexes requests over one connection');

  const cacheCtl = !!h['cache-control'];
  const validator = !!h.etag || !!h['last-modified'];
  add('practices', 'caching', 'Caching headers',
    cacheCtl && validator ? 'good' : cacheCtl || validator ? 'warn' : 'bad',
    [cacheCtl && 'cache-control', validator && 'validator'].filter(Boolean).join(' + ') || 'none',
    (cacheCtl ? 3 : 0) + (validator ? 2 : 0), 5);

  const redirects = chain.length - 1;
  add('practices', 'redirects', 'Redirect chain',
    redirects <= 1 ? 'good' : 'warn',
    redirects === 0 ? 'direct' : `${redirects} hop${redirects > 1 ? 's' : ''}`,
    redirects === 0 ? 4 : redirects === 1 ? 3 : 1, 4,
    redirects > 1 ? 'Each redirect adds a full round trip' : null);

  const server = h.server || '';
  const leaky = /\d/.test(server);
  add('practices', 'server', 'Server disclosure',
    leaky ? 'warn' : 'good',
    server ? server.slice(0, 40) : 'hidden',
    leaky ? 0 : 3, 3,
    leaky ? 'Version numbers in the Server header help attackers target exploits' : null);

  const categories = [
    { id: 'performance', label: 'Performance' },
    { id: 'security', label: 'Security' },
    { id: 'practices', label: 'Best practices' },
  ].map((c) => {
    const list = checks.filter((x) => x.category === c.id);
    return {
      ...c,
      points: list.reduce((s, x) => s + x.points, 0),
      max: list.reduce((s, x) => s + x.max, 0),
    };
  });

  const score = categories.reduce((s, c) => s + c.points, 0);
  const grade = score >= 95 ? 'A+' : score >= 90 ? 'A' : score >= 80 ? 'B'
    : score >= 65 ? 'C' : score >= 50 ? 'D' : 'F';

  return {
    requestedUrl: p.requestedUrl,
    finalUrl: p.finalUrl,
    ip: hop.remoteAddress,
    httpStatus: hop.statusCode,
    issuer: hop.tlsInfo ? hop.tlsInfo.issuer : null,
    score,
    grade,
    timings,
    categories,
    checks,
    fetchedAt: new Date().toISOString(),
  };
}

function friendlyError(err) {
  switch (err.code) {
    case 'EINPUT': case 'ELOOP': return err.message;
    case 'EPRIVATE': return 'That host resolves to a private address — refusing to probe it.';
    case 'ENOTFOUND': case 'EAI_AGAIN': return 'Could not resolve that hostname.';
    case 'ECONNREFUSED': return 'The server refused the connection.';
    case 'ETIMEDOUT': return 'The server did not respond in time.';
    case 'ECONNRESET': return 'The server dropped the connection.';
    case 'CERT_HAS_EXPIRED': return 'The TLS certificate has expired.';
    default:
      if (String(err.code || '').startsWith('ERR_TLS') || /certificate/i.test(err.message)) {
        return `TLS problem: ${err.message}`;
      }
      return `Could not analyze that URL (${err.code || err.message}).`;
  }
}

// ---------------------------------------------------------------------------
// HTTP server
// ---------------------------------------------------------------------------

const INDEX_HTML = fs.readFileSync(path.join(__dirname, 'public', 'index.html'));

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  });
  res.end(body);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');

  if (url.pathname === '/status') {
    return sendJson(res, 200, { ok: true });
  }

  if (url.pathname === '/api/analyze') {
    let target = url.searchParams.get('url');
    if (req.method === 'POST') {
      target = await new Promise((resolve) => {
        let data = '';
        req.on('data', (c) => { data += c; if (data.length > 4096) req.destroy(); });
        req.on('end', () => {
          try { resolve(JSON.parse(data).url); } catch { resolve(null); }
        });
      });
    }
    try {
      const report = buildReport(await probe(target));
      return sendJson(res, 200, report);
    } catch (err) {
      return sendJson(res, 400, { error: friendlyError(err) });
    }
  }

  if (url.pathname === '/' && req.method === 'GET') {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    return res.end(INDEX_HTML);
  }

  sendJson(res, 404, { error: 'not found' });
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`server-pulse listening on 0.0.0.0:${PORT}`);
});
