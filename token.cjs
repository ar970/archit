#!/usr/bin/env node
'use strict';

/**
 * Shopify OAuth token helper – inhaus-coffee.myshopify.com
 *
 * Usage:
 *   SHOPIFY_API_KEY=<key> SHOPIFY_API_SECRET=<secret> node token.cjs
 *
 * Optional env vars:
 *   SHOPIFY_SHOP     – defaults to inhaus-coffee.myshopify.com
 *   SHOPIFY_SCOPES   – comma-separated API scopes (see defaults below)
 *   PORT             – local callback port (default 3000)
 *
 * The granted access token is printed to stdout and saved to .shopify-token.json.
 */

const http     = require('http');
const https    = require('https');
const crypto   = require('crypto');
const fs       = require('fs');
const path     = require('path');
const { exec } = require('child_process');
const { URL }  = require('url');

// ── Config ────────────────────────────────────────────────────────────────────
const SHOP          = process.env.SHOPIFY_SHOP    || 'inhaus-coffee.myshopify.com';
const API_KEY       = process.env.SHOPIFY_API_KEY    || '';
const API_SECRET    = process.env.SHOPIFY_API_SECRET || '';
const SCOPES        = process.env.SHOPIFY_SCOPES  ||
  'read_products,write_products,read_orders,write_orders,read_customers,read_inventory';
const PORT          = parseInt(process.env.PORT || '3000', 10);
const REDIRECT_URI  = `http://localhost:${PORT}/callback`;
const TOKEN_FILE    = path.join(__dirname, '.shopify-token.json');

// ── Helpers ───────────────────────────────────────────────────────────────────

function generateNonce() {
  return crypto.randomBytes(16).toString('hex');
}

/**
 * Verifies the HMAC Shopify appends to the redirect callback.
 * https://shopify.dev/docs/apps/auth/oauth/getting-started#verify-the-callback
 */
function validateHmac(params) {
  const { hmac, ...rest } = params;
  if (!hmac) return false;

  const message = Object.keys(rest)
    .sort()
    .map(k => `${k}=${Array.isArray(rest[k]) ? rest[k].join(',') : rest[k]}`)
    .join('&');

  const digest = crypto
    .createHmac('sha256', API_SECRET)
    .update(message)
    .digest('hex');

  // Constant-time comparison to prevent timing attacks
  try {
    return crypto.timingSafeEqual(Buffer.from(digest, 'utf8'), Buffer.from(hmac, 'utf8'));
  } catch {
    return false;
  }
}

/** POST to Shopify's token endpoint and return the parsed JSON response. */
function exchangeCodeForToken(shop, code) {
  return new Promise((resolve, reject) => {
    const body = JSON.stringify({
      client_id:     API_KEY,
      client_secret: API_SECRET,
      code,
    });

    const options = {
      hostname: shop,
      path:     '/admin/oauth/access_token',
      method:   'POST',
      headers: {
        'Content-Type':   'application/json',
        'Content-Length': Buffer.byteLength(body),
        'Accept':         'application/json',
      },
    };

    const req = https.request(options, res => {
      let data = '';
      res.on('data', chunk => (data += chunk));
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (parsed.access_token) {
            resolve(parsed);
          } else {
            reject(new Error(`Unexpected response (HTTP ${res.statusCode}): ${data}`));
          }
        } catch (e) {
          reject(new Error(`Failed to parse response: ${data}`));
        }
      });
    });

    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

function saveToken(tokenData) {
  const payload = { shop: SHOP, ...tokenData, saved_at: new Date().toISOString() };
  fs.writeFileSync(TOKEN_FILE, JSON.stringify(payload, null, 2), { mode: 0o600 });
  console.log(`\nToken saved to: ${TOKEN_FILE}`);
}

/** Try to open the URL in the default browser (best-effort). */
function openBrowser(url) {
  const opener =
    process.platform === 'darwin' ? 'open' :
    process.platform === 'win32'  ? 'start' :
    'xdg-open';
  exec(`${opener} "${url}"`, () => {});
}

// ── OAuth flow ────────────────────────────────────────────────────────────────

async function main() {
  if (!API_KEY || !API_SECRET) {
    console.error(
      'Error: SHOPIFY_API_KEY and SHOPIFY_API_SECRET environment variables must be set.\n' +
      '  SHOPIFY_API_KEY=xxx SHOPIFY_API_SECRET=yyy node token.cjs'
    );
    process.exit(1);
  }

  const nonce = generateNonce();

  // Build the authorization URL
  const authUrl = new URL(`https://${SHOP}/admin/oauth/authorize`);
  authUrl.searchParams.set('client_id',     API_KEY);
  authUrl.searchParams.set('scope',         SCOPES);
  authUrl.searchParams.set('redirect_uri',  REDIRECT_URI);
  authUrl.searchParams.set('state',         nonce);

  console.log('\nShopify OAuth  –  inhaus-coffee.myshopify.com');
  console.log('─'.repeat(55));
  console.log('\nOpen this URL in your browser to authorise the app:\n');
  console.log(' ', authUrl.toString());
  console.log(`\nWaiting for callback on ${REDIRECT_URI} …\n`);

  openBrowser(authUrl.toString());

  // Spin up a one-shot local server to receive the OAuth callback
  const server = http.createServer(async (req, res) => {
    const reqUrl = new URL(req.url, `http://localhost:${PORT}`);

    if (reqUrl.pathname !== '/callback') {
      res.writeHead(404).end('Not found');
      return;
    }

    const params = Object.fromEntries(reqUrl.searchParams.entries());

    // --- State validation (CSRF guard) ---
    if (params.state !== nonce) {
      console.error('State mismatch – possible CSRF. Aborting.');
      res.writeHead(400, { 'Content-Type': 'text/plain' }).end('Invalid state.');
      server.close();
      process.exit(1);
    }

    // --- HMAC validation ---
    if (!validateHmac(params)) {
      console.error('HMAC validation failed. Aborting.');
      res.writeHead(400, { 'Content-Type': 'text/plain' }).end('HMAC mismatch.');
      server.close();
      process.exit(1);
    }

    // --- Exchange code for token ---
    try {
      console.log('Callback received. Exchanging code for access token…');
      const tokenData = await exchangeCodeForToken(SHOP, params.code);

      console.log('\n✅  Success!');
      console.log('   Access token :', tokenData.access_token);
      if (tokenData.scope) {
        console.log('   Scopes       :', tokenData.scope);
      }

      saveToken(tokenData);

      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Shopify OAuth – Success</title>
  <style>
    body { font-family: -apple-system, sans-serif; max-width: 520px;
           margin: 80px auto; padding: 0 1rem; }
    code { background: #f4f4f4; padding: 2px 6px; border-radius: 4px; }
    h2   { color: #1a8a1a; }
  </style>
</head>
<body>
  <h2>&#10003; Authorisation successful</h2>
  <p>Your Shopify access token has been saved to <code>${TOKEN_FILE}</code>.</p>
  <p>You can close this tab.</p>
</body>
</html>`);
    } catch (err) {
      console.error('\nToken exchange failed:', err.message);
      res.writeHead(500, { 'Content-Type': 'text/plain' }).end(`Error: ${err.message}`);
    } finally {
      server.close();
    }
  });

  server.listen(PORT, () => {
    // listening – already printed the URL above
  });

  server.on('close', () => {
    console.log('\nDone.');
    process.exit(0);
  });

  // Graceful shutdown on Ctrl-C
  process.on('SIGINT', () => {
    console.log('\nAborted.');
    server.close();
    process.exit(130);
  });
}

main().catch(err => {
  console.error('Fatal error:', err);
  process.exit(1);
});
