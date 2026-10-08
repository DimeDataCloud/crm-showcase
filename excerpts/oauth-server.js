// Excerpt from a private codebase: Dime Data CRM, crm/oauth.js at 3529c8b.
// Shown for reading. Not licensed for reuse; see ../LICENSE.
//
// One edit: the example URL in the constructor comment named the production host.

// The CRM as an OAuth 2.1 authorization server, so connecting it to an agent is a
// sign-in, not a paste.
//
// What HubSpot, Notion, Linear and the rest do for their agent connectors, at
// the size we need: an agent host (HALO Agent, Claude, ChatGPT) POSTs /mcp, gets
// a 401 that names our metadata, discovers these endpoints, registers itself
// (RFC 7591) or presents a Client ID Metadata Document URL, sends the person to
// /oauth/authorize, and the person — already signed in to the CRM, or signing in
// on the way — sees WHO wants access and WHAT they may do, and clicks Allow. The
// token that comes back is a per-user API token (api-tokens.js): it acts as that
// person, with that person's role, limited to the scopes they ticked.
//
// Rules, each one an attack this closes rather than a nicety:
//   · PKCE S256 required (public clients; no secret exists to leak).
//   · redirect_uri must match a registered one byte-for-byte.
//   · `resource` (RFC 8707), when sent, must be our MCP URL — a token minted here
//     is for here, not replayable at another server.
//   · `iss` is returned on every redirect (RFC 9207) so the client can refuse a
//     response from the wrong issuer.
//   · Codes are single-use, five minutes, bound to client + redirect + challenge.
//   · Refresh tokens rotate; a reused one is dead.
//   · Consent POST is same-origin only — the CRM's CSRF rule applies.
//
// Client and code state live in memory (one process, one box). A restart
// forgets in-flight sign-ins, which fail cleanly at the token step and the
// person signs in again; registered clients persist in app_config `oauth_clients`.
'use strict';

const crypto = require('crypto');
const { normaliseScopes, SCOPES } = require('./api-tokens');

const CODE_TTL_MS = 5 * 60 * 1000;
const CLIENTS_ROW = 'oauth_clients';
const CIMD_CACHE_MS = 10 * 60 * 1000;
const SCOPE_TEXT = {
  'crm:read': 'Read leads, clients, tasks, call history and stats',
  'crm:write': 'Add and update leads, log calls, create and change tasks and clients',
};

const b64u = (buf) => Buffer.from(buf).toString('base64url');
const esc = (s) => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

class OAuthError extends Error {
  constructor(error, description, status = 400) { super(description || error); this.error = error; this.description = description || error; this.status = status; }
}

/** Loopback http is the one non-https redirect OAuth 2.1 allows (native/local clients). */
function redirectUriAllowed(uri) {
  let u; try { u = new URL(uri); } catch { return false; }
  if (u.protocol === 'https:') return true;
  return u.protocol === 'http:' && (u.hostname === '127.0.0.1' || u.hostname === 'localhost' || u.hostname === '[::1]');
}

class OAuthServer {
  /**
   * @param publicUrl   e.g. https://crm.example.com (no trailing slash)
   * @param tokens      the TokenStore
   * @param sb          Supabase helper (for the clients row)
   * @param assertPublicUrl  SSRF guard for fetching Client ID Metadata Documents
   */
  constructor({ publicUrl, tokens, sb, assertPublicUrl, fetchImpl = fetch, now = Date.now, embedUrl = '' }) {
    this.publicUrl = String(publicUrl).replace(/\/+$/, '');
    // Where an agent host may load the CRM in a frame (a same-site hostname it
    // serves, e.g. crm.haloagent.tech). Absent → nothing offers to embed it.
    this.embedUrl = String(embedUrl || '').replace(/\/+$/, '');
    this.tokens = tokens;
    this.sb = sb;
    this.assertPublicUrl = assertPublicUrl || (async () => {});
    this.fetch = fetchImpl;
    this.now = now;
    this.codes = new Map();      // code → grant
    this.cimd = new Map();       // client_id url → { doc, at }
    this.clientsCache = null;    // { map, at }
  }

  get resource() { return this.publicUrl + '/mcp'; }

  // ── discovery documents ───────────────────────────────────────────────────
  protectedResourceMetadata() {
    return {
      resource: this.resource,
      authorization_servers: [this.publicUrl],
      scopes_supported: SCOPES,
      bearer_methods_supported: ['header'],
      resource_name: 'Dime Data CRM',
      resource_documentation: this.publicUrl + '/oauth/about',
      // Not an OAuth field: HALO Agent reads it to offer a native CRM page that
      // frames this URL. Hosts that do not know the key ignore it.
      ...(this.embedUrl ? { embed_url: this.embedUrl } : {}),
    };
  }
  authServerMetadata() {
    return {
      issuer: this.publicUrl,
      authorization_endpoint: this.publicUrl + '/oauth/authorize',
      token_endpoint: this.publicUrl + '/oauth/token',
      registration_endpoint: this.publicUrl + '/oauth/register',
      revocation_endpoint: this.publicUrl + '/oauth/revoke',
      scopes_supported: SCOPES,
      response_types_supported: ['code'],
      response_modes_supported: ['query'],
      grant_types_supported: ['authorization_code', 'refresh_token'],
      code_challenge_methods_supported: ['S256'],
      token_endpoint_auth_methods_supported: ['none'],
      revocation_endpoint_auth_methods_supported: ['none'],
      authorization_response_iss_parameter_supported: true,
      client_id_metadata_document_supported: true,
    };
  }
  /** The header on a 401 that starts discovery (RFC 9728 §5.1). */
  challengeHeader(opts = {}) {
    const parts = ['Bearer realm="Dime Data CRM"', `resource_metadata="${this.publicUrl}/.well-known/oauth-protected-resource"`];
    if (opts.error) parts.push(`error="${opts.error}"`);
    if (opts.scope) parts.push(`scope="${opts.scope}"`);
    return parts.join(', ');
  }

  // ── clients ───────────────────────────────────────────────────────────────
  async loadClients(force = false) {
    if (!force && this.clientsCache && this.now() - this.clientsCache.at < 60_000) return this.clientsCache.map;
    const rows = await this.sb('app_config?key=eq.' + CLIENTS_ROW + '&select=value').catch(() => null);
    let map = {};
    const raw = rows && rows[0] && rows[0].value;
    if (raw) { try { map = JSON.parse(raw) || {}; } catch { map = {}; } }
    this.clientsCache = { map, at: this.now() };
    return map;
  }
  async saveClients(map) {
    await this.sb('app_config', {
      method: 'POST', prefer: 'resolution=merge-duplicates,return=minimal',
      body: { key: CLIENTS_ROW, value: JSON.stringify(map), updated_at: new Date(this.now()).toISOString() },
    });
    this.clientsCache = { map, at: this.now() };
  }

  /** RFC 7591 dynamic registration. Public clients only; no secret is ever issued. */
  async register(body) {
    const uris = Array.isArray(body && body.redirect_uris) ? body.redirect_uris.map(String) : [];
    if (!uris.length) throw new OAuthError('invalid_redirect_uri', 'redirect_uris is required');
    for (const u of uris) if (!redirectUriAllowed(u)) throw new OAuthError('invalid_redirect_uri', 'redirect URIs must be https, or http on loopback: ' + u);
    if (body.token_endpoint_auth_method && body.token_endpoint_auth_method !== 'none') {
      throw new OAuthError('invalid_client_metadata', 'only public clients (token_endpoint_auth_method "none") are issued here');
    }
    const client = {
      client_id: 'dcr_' + crypto.randomBytes(16).toString('base64url'),
      client_name: String((body && body.client_name) || 'Unnamed client').slice(0, 80),
      client_uri: typeof body.client_uri === 'string' ? body.client_uri.slice(0, 200) : null,
      redirect_uris: uris,
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
      token_endpoint_auth_method: 'none',
      client_id_issued_at: Math.floor(this.now() / 1000),
    };
    const map = await this.loadClients(true);
    map[client.client_id] = client;
    await this.saveClients(map);
    return client;
  }

  /**
   * Who is asking. A registered id, or a Client ID Metadata Document: the id IS
   * an https URL, fetched (through the SSRF guard) to learn the name and the
   * redirect URIs it claims. Cached ten minutes.
   */
  async resolveClient(clientId) {
    if (!clientId) throw new OAuthError('invalid_client', 'client_id is required', 401);
    const map = await this.loadClients();
    if (map[clientId]) return map[clientId];
    if (/^https:\/\//.test(clientId)) {
      const cached = this.cimd.get(clientId);
      if (cached && this.now() - cached.at < CIMD_CACHE_MS) return cached.doc;
      await this.assertPublicUrl(clientId);
      let doc;
      try {
        const r = await this.fetch(clientId, { headers: { accept: 'application/json' }, signal: AbortSignal.timeout(8000), redirect: 'error' });
        if (!r.ok) throw new Error('HTTP ' + r.status);
        doc = await r.json();
      } catch (e) {
        throw new OAuthError('invalid_client', 'could not read client metadata at ' + clientId + ': ' + (e && e.message), 401);
      }
      if (!doc || doc.client_id !== clientId) throw new OAuthError('invalid_client', 'client metadata document does not name itself as client_id', 401);
      const uris = Array.isArray(doc.redirect_uris) ? doc.redirect_uris.map(String) : [];
      if (!uris.length || !uris.every(redirectUriAllowed)) throw new OAuthError('invalid_client', 'client metadata document lists no acceptable redirect_uris', 401);
      const client = { client_id: clientId, client_name: String(doc.client_name || new URL(clientId).host).slice(0, 80), client_uri: doc.client_uri || new URL(clientId).origin, redirect_uris: uris, token_endpoint_auth_method: 'none' };
      this.cimd.set(clientId, { doc: client, at: this.now() });
      return client;
    }
    throw new OAuthError('invalid_client', 'unknown client_id', 401);
  }

  // ── authorize ─────────────────────────────────────────────────────────────
  /**
   * Validate an authorization request. Errors about the CLIENT or REDIRECT are
   * shown to the person here (never redirected — that is how open redirectors are
   * born); everything else is returned to the client at its redirect_uri.
   */
  async validateAuthorize(q) {
    const get = (k) => (q[k] == null ? '' : String(q[k]));
    const client = await this.resolveClient(get('client_id'));
    const redirectUri = get('redirect_uri');
    if (!redirectUri || !client.redirect_uris.includes(redirectUri)) {
      throw new OAuthError('invalid_request', 'redirect_uri is not registered for this client');
    }
    const redirectable = (error, description) => Object.assign(new OAuthError(error, description), { redirectTo: this.errorRedirect(redirectUri, get('state'), error, description) });
    if (get('response_type') !== 'code') throw redirectable('unsupported_response_type', 'only response_type=code is supported');
    if (get('code_challenge_method') !== 'S256' || !/^[A-Za-z0-9_-]{43,128}$/.test(get('code_challenge'))) {
      throw redirectable('invalid_request', 'PKCE with code_challenge_method=S256 is required');
    }
    const resource = get('resource');
    if (resource && resource !== this.resource) throw redirectable('invalid_target', 'resource must be ' + this.resource);
    const scopes = normaliseScopes(get('scope') || SCOPES);
    return { client, redirectUri, state: get('state'), challenge: get('code_challenge'), resource: resource || this.resource, scopes };
  }

  errorRedirect(redirectUri, state, error, description) {
    const u = new URL(redirectUri);
    u.searchParams.set('error', error);
    if (description) u.searchParams.set('error_description', description);
    if (state) u.searchParams.set('state', state);
    u.searchParams.set('iss', this.publicUrl);
    return u.toString();
  }

  /** The person said yes: mint a code and build the redirect. */
  issueCode({ user, client, redirectUri, state, challenge, resource, scopes }) {
    const code = crypto.randomBytes(32).toString('base64url');
    this.sweepCodes();
    this.codes.set(code, { user, clientId: client.client_id, clientName: client.client_name, redirectUri, challenge, resource, scopes, exp: this.now() + CODE_TTL_MS });
    const u = new URL(redirectUri);
    u.searchParams.set('code', code);
    if (state) u.searchParams.set('state', state);
    u.searchParams.set('iss', this.publicUrl);
    return u.toString();
  }
  sweepCodes() { for (const [c, g] of this.codes) if (g.exp < this.now()) this.codes.delete(c); }

  /** The consent screen. Plain HTML, server-rendered, same look as the login page. */
  consentPage({ user, client, scopes, params, csrfHidden }) {
    const hidden = Object.entries(params).map(([k, v]) => `<input type="hidden" name="${esc(k)}" value="${esc(v)}">`).join('');
    const scopeRows = SCOPES.map((s) => {
      const on = scopes.includes(s);
      const locked = s === 'crm:read';
      return `<label class="sc"><input type="checkbox" name="scope" value="${s}" ${on ? 'checked' : ''} ${locked ? 'disabled' : ''}>${locked ? `<input type="hidden" name="scope" value="${s}">` : ''}<span><b>${esc(s)}</b><small>${esc(SCOPE_TEXT[s])}</small></span></label>`;
    }).join('');
    const origin = (() => { try { return new URL(client.client_uri || client.redirect_uris[0]).host; } catch { return ''; } })();
    return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Allow access · Dime Data CRM</title>
<link href="https://fonts.googleapis.com/css2?family=Manrope:wght@400;600;700;800&display=swap" rel="stylesheet">
<style>
*{box-sizing:border-box;margin:0;padding:0}body{font-family:Manrope,system-ui,sans-serif;background:#050038;color:#11142e;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px}
.card{background:#fff;border-radius:18px;padding:28px;max-width:460px;width:100%;box-shadow:0 30px 80px rgba(0,0,0,.35)}
.eyebrow{font-size:11px;letter-spacing:.14em;text-transform:uppercase;color:#8a8da0;font-weight:800;margin-bottom:10px}
h1{font-size:20px;font-weight:800;line-height:1.3;margin-bottom:6px}h1 b{color:#050038}.who{font-size:13px;color:#5a6080;margin-bottom:18px}.who b{color:#11142e}
.sc{display:flex;gap:12px;align-items:flex-start;padding:12px;border:1px solid rgba(20,24,58,.12);border-radius:12px;margin-bottom:8px;cursor:pointer;background:#f7f8fc}.sc input{margin-top:3px;accent-color:#050038}.sc span{display:flex;flex-direction:column;gap:2px;font-size:13px}.sc small{color:#5a6080;font-size:12px}
.row{display:flex;gap:10px;margin-top:18px}.row button{flex:1;border:none;border-radius:10px;padding:12px;font-weight:800;font-size:14px;cursor:pointer;font-family:inherit}
.allow{background:#ffd02f;color:#0a0a0f}.deny{background:transparent;color:#5a6080;border:1px solid rgba(20,24,58,.15)!important}
.fine{font-size:11px;color:#8a8da0;margin-top:14px;line-height:1.5}
</style></head><body><form class="card" method="POST" action="/oauth/authorize">${hidden}${csrfHidden || ''}
<div class="eyebrow">Dime Data CRM</div>
<h1><b>${esc(client.client_name)}</b> wants to use the CRM as you</h1>
<div class="who">Signed in as <b>${esc(user.name)}</b> (${esc(user.email || user.role)}). ${origin ? 'Request from <b>' + esc(origin) + '</b>.' : ''} Anything it does will be done as you, with your role and your leads.</div>
${scopeRows}
<div class="row"><button class="deny" type="submit" name="decision" value="deny">Cancel</button><button class="allow" type="submit" name="decision" value="allow">Allow</button></div>
<div class="fine">You can revoke this any time from the Team tab (Revoke tokens). Access expires after 24 hours of no use and renews itself while the connection is active; unused connections lapse after 90 days.</div>
</form></body></html>`;
  }

  // ── token ─────────────────────────────────────────────────────────────────
  async token(form) {
    const get = (k) => (form[k] == null ? '' : String(form[k]));
    const grant = get('grant_type');
    if (grant === 'authorization_code') {
      this.sweepCodes();
      const g = this.codes.get(get('code'));
      this.codes.delete(get('code')); // single use, success or not
      if (!g) throw new OAuthError('invalid_grant', 'authorization code is unknown, used or expired');
      if (g.clientId !== get('client_id')) throw new OAuthError('invalid_grant', 'code was issued to a different client');
      if (g.redirectUri !== get('redirect_uri')) throw new OAuthError('invalid_grant', 'redirect_uri does not match the authorization request');
      const verifier = get('code_verifier');
      if (!verifier || b64u(crypto.createHash('sha256').update(verifier).digest()) !== g.challenge) throw new OAuthError('invalid_grant', 'PKCE verification failed');
      const resource = get('resource');
      if (resource && resource !== g.resource) throw new OAuthError('invalid_target', 'resource must match the authorization request');
      return this.tokens.issueOAuth(g.user.id, { clientId: g.clientId, clientName: g.clientName, scopes: g.scopes });
    }
    if (grant === 'refresh_token') {
      const out = await this.tokens.refresh(get('refresh_token'), get('client_id'));
      if (!out) throw new OAuthError('invalid_grant', 'refresh token is unknown, rotated, expired, or belongs to another client');
      return out;
    }
    throw new OAuthError('unsupported_grant_type', 'grant_type must be authorization_code or refresh_token');
  }

  /** RFC 7009: always 200 for a well-formed request, whether or not the token existed. */
  async revoke(form) {
    const t = form && form.token ? String(form.token) : '';
    if (t) await this.tokens.revokeToken(t).catch(() => false);
    return { ok: true };
  }

  /** A short page for the metadata's documentation link and for humans who land here. */
  aboutPage() {
    return `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>Connecting agents · Dime Data CRM</title><style>body{font-family:system-ui,sans-serif;max-width:640px;margin:48px auto;padding:0 20px;color:#11142e;line-height:1.55}code{background:#f0f1f6;padding:2px 6px;border-radius:4px}</style></head><body>
<h1>Connecting an agent to this CRM</h1>
<p>This CRM is an MCP server at <code>${esc(this.resource)}</code>. Point HALO Agent (Settings → Connections → Any MCP server), Claude, or any MCP client at that URL and choose <b>Sign in</b>. You will be asked to sign in to the CRM and to allow the connection; the agent then acts as you, with your role and your leads only.</p>
<p>Scopes: <code>crm:read</code> (always) and <code>crm:write</code> (optional — add and update leads, log calls, tasks, clients). Nothing can delete records through this connection.</p>
<p>Revoke from the Team tab at any time. Metadata: <code>/.well-known/oauth-authorization-server</code>, <code>/.well-known/oauth-protected-resource</code>.</p>
</body></html>`;
  }
}

/** Parse an x-www-form-urlencoded body into a plain object; repeated keys become arrays. */
function parseForm(text) {
  const out = {};
  for (const [k, v] of new URLSearchParams(String(text || ''))) {
    if (k in out) out[k] = [].concat(out[k], v); else out[k] = v;
  }
  return out;
}

module.exports = { OAuthServer, OAuthError, parseForm, redirectUriAllowed, SCOPE_TEXT, CODE_TTL_MS };
