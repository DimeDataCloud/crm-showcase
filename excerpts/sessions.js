// Excerpt from a private codebase: Dime Data CRM, crm/server.js (lines 716-796) at 3529c8b.
// Shown for reading. Not licensed for reuse; see ../LICENSE.
//
// The session section of the server, whole. It reads CFG (the env-backed config) and
// isEmbedHost(req) from elsewhere in the file; neither changes what's shown here.

// ── Sessions ────────────────────────────────────────────────────────────────
// Stateless signed tokens, not a server-side Map. server.js is COPY'd into the
// image, so every deploy swaps the container — an in-memory session store logged
// the whole team out on each one. The token carries its own claims and a HMAC, so
// it survives restarts. Trade-off: logout revocation IS in memory (REVOKED below)
// and is lost on restart, so a token explicitly logged out could be replayed until
// its own 24h expiry if the container restarts in between. Bounded and acceptable;
// a DB-backed denylist is the fix if that ever matters.
const COOKIE_NAME  = 'crm_sess';
const SESSION_TTL  = 24 * 3600 * 1000; // 24h absolute; re-issued when under 12h left
// Derived from secrets the container already has, so it is stable across restarts
// without a new env var. Rotating DASH_PASS or the Supabase key invalidates
// every outstanding session, which is the correct behaviour.
const SESSION_KEY = process.env.SESSION_SECRET
  ? Buffer.from(process.env.SESSION_SECRET)
  : crypto.createHash('sha256').update('crm-sess:' + CFG.pass + ':' + CFG.sbKey).digest();
const REVOKED = new Map(); // jti -> exp (cleared on restart; see note above)
// user id -> instant their credentials last changed. Any session minted before
// it is refused, which is how a password change ends the sessions on every
// OTHER device. It has to work this way round because the tokens are stateless:
// there is no server-side row to delete, and REVOKED is keyed by jti, which
// only the holder of a token ever sees. Cleared on restart like REVOKED — a
// container swap in the minute after a password change leaves the old sessions
// alive until their own 24h expiry. Bounded, and the same trade-off already
// documented above; a column on crm_users is the fix if it ever matters.
const CRED_EPOCH = new Map();
function b64u(buf) { return Buffer.from(buf).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); }
function b64uDec(s) { return Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64'); }
function signSession(user) {
  const jti = crypto.randomBytes(12).toString('hex');
  const payload = b64u(JSON.stringify({ id: user.id, email: user.email, name: user.name, role: user.role, jti, exp: Date.now() + SESSION_TTL }));
  const mac = b64u(crypto.createHmac('sha256', SESSION_KEY).update(payload).digest());
  return payload + '.' + mac;
}
function verifySession(token) {
  const i = String(token).indexOf('.');
  if (i < 1) return null;
  const payload = token.slice(0, i), mac = token.slice(i + 1);
  const want = crypto.createHmac('sha256', SESSION_KEY).update(payload).digest();
  let got; try { got = b64uDec(mac); } catch { return null; }
  if (got.length !== want.length || !crypto.timingSafeEqual(got, want)) return null;
  let s; try { s = JSON.parse(b64uDec(payload).toString('utf8')); } catch { return null; }
  if (!s || !s.exp || Date.now() > s.exp) return null;
  if (s.jti && REVOKED.has(s.jti)) return null;
  // Issued before this user last changed their password? Then it belongs to a
  // device they were trying to sign out. `exp - SESSION_TTL` is the issue time.
  const since = s.id && CRED_EPOCH.get(s.id);
  if (since && (s.exp - SESSION_TTL) < since) return null;
  return s;
}
function revokeSession(token) {
  const s = verifySession(token);
  if (s && s.jti) REVOKED.set(s.jti, s.exp);
}
function sessionCookie(token, maxAgeSec, req) {
  // SameSite=Lax by default: a page the user visits cannot ride this session.
  // On an embed host (HALO Agent's frame) the cookie must travel cross-site or
  // the frame forgets the sign-in on every load; there it is None, and the
  // originOk() check on every state change carries the CSRF protection instead.
  const sameSite = req && isEmbedHost(req) ? 'None' : 'Lax';
  return `${COOKIE_NAME}=${token}; Path=/; HttpOnly; SameSite=${sameSite}; Secure; Max-Age=${maxAgeSec}`;
}
// Per-IP login throttle: 8 failures / 15 min. Note: behind Caddy the client IP
// comes from X-Forwarded-For, so a Caddy-level rate limit is the robust backstop.
// Also resets on restart — same reason, same backstop.
const LOGIN_ATTEMPTS = new Map(); // ip -> { n, exp }
function loginClientIp(req){ return String(req.headers['x-forwarded-for'] || '').split(',')[0].trim() || (req.socket && req.socket.remoteAddress) || 'unknown'; }
function loginThrottled(ip){ const e = LOGIN_ATTEMPTS.get(ip); return !!(e && Date.now() < e.exp && e.n >= 8); }
function loginFail(ip){ const now = Date.now(); const e = LOGIN_ATTEMPTS.get(ip); if (!e || now > e.exp) LOGIN_ATTEMPTS.set(ip, { n: 1, exp: now + 15 * 60 * 1000 }); else e.n++; }
function loginOk(ip){ LOGIN_ATTEMPTS.delete(ip); }
// Both maps are unbounded without this — pruning used to run only on successful login.
setInterval(() => {
  const now = Date.now();
  for (const [k, e] of LOGIN_ATTEMPTS) if (now > e.exp) LOGIN_ATTEMPTS.delete(k);
  for (const [k, exp] of REVOKED) if (now > exp) REVOKED.delete(k);
  // Once a full TTL has passed, every session that epoch could refuse has
  // expired on its own. Keeping it would grow the map for the life of the
  // container.
  for (const [k, at] of CRED_EPOCH) if (now - at > SESSION_TTL) CRED_EPOCH.delete(k);
}, 10 * 60 * 1000).unref?.();
