// Excerpt from a private codebase: Dime Data CRM, crm/mcp.js at 3529c8b.
// Shown for reading. Not licensed for reuse; see ../LICENSE.

// The CRM as an MCP server — streamable HTTP, stateless, JSON answers.
//
// Why this exists: HALO Agent mounts any MCP server a user pastes into
// Settings → Connections ("Any MCP server"), on every engine it drives. So the
// cheapest way to hand an agent this CRM is to speak MCP here, once, rather than
// teaching each agent product a REST surface. Nothing in this file touches the
// database: every tool is a call back into the CRM's own HTTP API on loopback,
// carrying the caller's own Authorization header. That keeps one set of rules —
// rep scoping, field allow-lists, the CSRF gate — and an agent can do exactly
// what the identity behind its token could do in the browser, no more.
//
// Auth is the caller's problem, deliberately. server.js authenticates the request
// before it reaches `handleMcp`, so an unauthenticated POST /mcp is a 401 with the
// same body every other route gives. The service token is accepted as a bearer
// as well as Basic because MCP clients send `Authorization: Bearer`.
//
// No delete tool. Deleting a lead or a client is the one action an agent should
// not be able to take from a sentence; a person does that in the dashboard.
'use strict';

const PROTOCOL_VERSIONS = ['2025-06-18', '2025-03-26', '2024-11-05'];
const SERVER_INFO = { name: 'dimedata-crm', version: '3.1.0' };

const LEAD_FIELDS = ['company', 'name', 'email', 'phone', 'metro', 'website', 'status', 'notes', 'owner_phone', 'facebook', 'instagram'];
const TASK_FIELDS = ['title', 'description', 'due_date', 'due_time', 'type', 'priority', 'notes', 'lead_id', 'status'];
const CLIENT_FIELDS = ['company', 'contact', 'email', 'phone', 'project_type', 'value', 'mrr', 'stage', 'notes', 'start_date', 'website', 'city', 'state', 'zip', 'industry', 'description'];
const DISPOSITIONS = ['no_answer', 'voicemail', 'callback_scheduled', 'interested', 'not_interested', 'text_sent', 'email_sent'];
/** What the Starter Lead Generator can source for — the catalogue keys leadgen/server.js labels. */
const SWEEP_OPTIONS = ['website-booking', 'ai-receptionist', 'website-addon', 'seo-audit'];

/** Keep only the allow-listed keys that were actually supplied. */
function pick(obj, keys) {
  const out = {};
  for (const k of keys) if (obj && obj[k] !== undefined) out[k] = obj[k];
  return out;
}

/** A lead row the model can read in a list without its 30 KB of enrichment meta. */
function compactLead(l) {
  return {
    id: l.id, company: l.company, name: l.name, status: l.status, metro: l.metro,
    phone: l.phone, email: l.email, website: l.website, assigned_to: l.assigned_to,
    updated_at: l.updated_at,
  };
}

function intArg(v, what) {
  const n = Number(v);
  if (!Number.isInteger(n) || n <= 0) throw new Error(what + ' must be a positive integer');
  return n;
}

function str(v, what, max = 200) {
  if (typeof v !== 'string' || !v.trim()) throw new Error(what + ' is required');
  return v.trim().slice(0, max);
}

const obj = (properties, required = []) => ({ type: 'object', properties, required, additionalProperties: false });
const READ = { readOnlyHint: true, destructiveHint: false, openWorldHint: false };
const WRITE = { readOnlyHint: false, destructiveHint: false, idempotentHint: false, openWorldHint: false };
const WRITE_IDEMPOTENT = { readOnlyHint: false, destructiveHint: false, idempotentHint: true, openWorldHint: false };

/**
 * Opaque cursor over an in-memory list: the CRM's list routes return the whole
 * scoped set (≤2000 rows), so paging is a slice here. Base64 of the offset, so a
 * client treats it as a token and we can change the encoding later.
 */
function page(rows, { cursor, limit, fallback = 50, max = 200 }) {
  const list = Array.isArray(rows) ? rows : [];
  let offset = 0;
  if (cursor) {
    try { offset = Math.max(0, parseInt(Buffer.from(String(cursor), 'base64url').toString('utf8'), 10) || 0); } catch { offset = 0; }
  }
  const n = Math.min(Math.max(1, limit ? intArg(limit, 'limit') : fallback), max);
  const slice = list.slice(offset, offset + n);
  const next = offset + n < list.length ? Buffer.from(String(offset + n)).toString('base64url') : null;
  return { total: list.length, returned: slice.length, next_cursor: next, items: slice };
}
const S = (description) => ({ type: 'string', description });
const I = (description) => ({ type: 'integer', description });

/**
 * The tool table. Each row is data plus one `run(api, args)`; the dispatcher
 * below is the only code that knows how a tool becomes an HTTP call. `api` is
 * `(method, path, body?) => Promise<json>` against this same CRM, as the caller.
 */
const TOOLS = [
  {
    name: 'list_campaigns',
    description: 'The pipelines in the CRM (slug, name). Every lead belongs to one campaign; use the slug with list_leads and add_lead.',
    inputSchema: obj({}),
    annotations: READ,
    run: (api) => api('GET', '/api/campaigns'),
  },
  {
    name: 'list_leads',
    description: 'Leads in one campaign, newest activity first, compact rows. Filter by status or rep. Default 50 rows, max 200; pass next_cursor back as cursor for the next page. Use get_lead for the full record.',
    inputSchema: obj({
      campaign: S('Campaign slug from list_campaigns, e.g. "dimedata-website".'),
      status: S('Only this pipeline status, e.g. "new", "contacted", "booked".'),
      rep: S('Only leads assigned to this user id, or "unassigned".'),
      limit: I('Rows to return, 1–200. Default 50.'),
      cursor: S('next_cursor from the previous page.'),
    }, ['campaign']),
    annotations: READ,
    run: async (api, a) => {
      const q = new URLSearchParams({ campaign: str(a.campaign, 'campaign') });
      if (a.rep) q.set('rep', str(a.rep, 'rep'));
      const rows = await api('GET', '/api/leads?' + q);
      const kept = (Array.isArray(rows) ? rows : []).filter((l) => !a.status || l.status === a.status);
      const p = page(kept, { cursor: a.cursor, limit: a.limit });
      return { total: p.total, returned: p.returned, next_cursor: p.next_cursor, leads: p.items.map(compactLead) };
    },
  },
  {
    name: 'search_leads',
    description: 'Find leads by company or contact name across all campaigns. Up to 25 matches.',
    inputSchema: obj({ q: S('Part of the company or contact name.') }, ['q']),
    annotations: READ,
    run: (api, a) => api('GET', '/api/leads/search?q=' + encodeURIComponent(str(a.q, 'q', 80))),
  },
  {
    name: 'get_lead',
    description: 'One lead in full: contact details, status, notes, enrichment profile, and the outreach that has gone out.',
    inputSchema: obj({ id: I('Lead id.') }, ['id']),
    annotations: READ,
    run: (api, a) => api('GET', '/api/leads/' + intArg(a.id, 'id')),
  },
  {
    name: 'add_lead',
    description: 'Create a lead in a campaign. Company is required; status defaults to "new".',
    inputSchema: obj({
      campaign: S('Campaign slug from list_campaigns.'),
      company: S('Business name.'),
      name: S('Contact name.'), email: S('Email.'), phone: S('Phone.'),
      metro: S('City or metro.'), website: S('Website URL.'),
      status: S('Pipeline status; default "new".'), notes: S('Free-text notes.'),
    }, ['campaign', 'company']),
    annotations: WRITE,
    run: async (api, a) => {
      const slug = str(a.campaign, 'campaign');
      const camps = await api('GET', '/api/campaigns');
      const camp = (Array.isArray(camps) ? camps : []).find((c) => c.slug === slug);
      if (!camp) throw new Error('no campaign with slug "' + slug + '" — call list_campaigns');
      const body = { campaign_id: camp.id, status: 'new', ...pick(a, LEAD_FIELDS) };
      body.company = str(a.company, 'company');
      return api('POST', '/api/leads', body);
    },
  },
  {
    name: 'update_lead',
    description: 'Change a lead: move its pipeline status, append notes, or correct contact details. Only the fields you pass change.',
    inputSchema: obj({
      id: I('Lead id.'),
      status: S('New pipeline status.'), notes: S('Replacement notes text.'),
      company: S('Business name.'), name: S('Contact name.'), email: S('Email.'), phone: S('Phone.'),
      metro: S('City or metro.'), website: S('Website URL.'),
    }, ['id']),
    annotations: WRITE_IDEMPOTENT,
    run: async (api, a) => {
      const id = intArg(a.id, 'id');
      const body = pick(a, LEAD_FIELDS);
      if (!Object.keys(body).length) throw new Error('nothing to change — pass at least one field besides id');
      await api('PATCH', '/api/leads/' + id, body);
      return { ok: true, id, changed: Object.keys(body) };
    },
  },
  {
    name: 'log_call',
    description: 'Record a call outcome against a lead. Disposition is one of: ' + DISPOSITIONS.join(', ') + '.',
    inputSchema: obj({
      lead_id: I('Lead id.'),
      disposition: { type: 'string', enum: DISPOSITIONS, description: 'How the call ended.' },
      notes: S('What was said.'),
      duration_seconds: I('Call length in seconds.'),
    }, ['lead_id', 'disposition']),
    annotations: WRITE,
    run: (api, a) => {
      if (!DISPOSITIONS.includes(a.disposition)) throw new Error('disposition must be one of: ' + DISPOSITIONS.join(', '));
      return api('POST', '/api/leads/' + intArg(a.lead_id, 'lead_id') + '/disposition',
        { disposition: a.disposition, ...pick(a, ['notes', 'duration_seconds']) });
    },
  },
  {
    name: 'lead_activity',
    description: 'The call log for one lead, newest first.',
    inputSchema: obj({ lead_id: I('Lead id.') }, ['lead_id']),
    annotations: READ,
    run: (api, a) => api('GET', '/api/leads/' + intArg(a.lead_id, 'lead_id') + '/activity'),
  },
  {
    name: 'pipeline_funnel',
    description: 'Lead counts by status for every campaign, in one call.',
    inputSchema: obj({}),
    annotations: READ,
    run: (api) => api('GET', '/api/stats/funnel'),
  },
  {
    name: 'rep_stats',
    description: 'Per-rep activity: dials, contacts, interested, callbacks, assigned and booked leads. Optionally since a date.',
    inputSchema: obj({ since: S('ISO date, e.g. "2026-09-01". Counts calls from then on.') }),
    annotations: READ,
    run: (api, a) => api('GET', '/api/stats/reps' + (a.since ? '?since=' + encodeURIComponent(str(a.since, 'since', 40)) : '')),
  },
  {
    name: 'revenue',
    description: 'Revenue as the CRM reports it: total, the tracked subset on client records, and the gap between them.',
    inputSchema: obj({}),
    annotations: READ,
    run: (api) => api('GET', '/api/stats/revenue'),
  },
  {
    name: 'list_tasks',
    description: 'Tasks, soonest due first, including callbacks scheduled from calls. Default 50, max 200; pass next_cursor back as cursor.',
    inputSchema: obj({ status: S('Only tasks with this status, e.g. "open" or "done".'), limit: I('Rows, 1–200. Default 50.'), cursor: S('next_cursor from the previous page.') }),
    annotations: READ,
    run: async (api, a) => {
      const rows = await api('GET', '/api/tasks');
      const list = (Array.isArray(rows) ? rows : []).filter((t) => !a.status || t.status === a.status);
      const p = page(list, { cursor: a.cursor, limit: a.limit });
      return { total: p.total, returned: p.returned, next_cursor: p.next_cursor, tasks: p.items };
    },
  },
  {
    name: 'create_task',
    description: 'Add a task or callback. Give it a title and a due date; attach a lead_id so it shows on that lead.',
    inputSchema: obj({
      title: S('What to do.'), due_date: S('YYYY-MM-DD.'), due_time: S('HH:MM, 24-hour, America/Chicago.'),
      type: S('"callback", "task", or "meeting".'), priority: S('"low", "normal", or "high".'),
      notes: S('Details.'), lead_id: I('Lead this is about.'),
    }, ['title', 'due_date']),
    annotations: WRITE,
    run: (api, a) => api('POST', '/api/tasks', { ...pick(a, TASK_FIELDS), title: str(a.title, 'title'), due_date: str(a.due_date, 'due_date', 10) }),
  },
  {
    name: 'update_task',
    description: 'Change a task, or mark it done with status "done".',
    inputSchema: obj({
      id: I('Task id.'), status: S('"open" or "done".'), title: S('New title.'),
      due_date: S('YYYY-MM-DD.'), due_time: S('HH:MM.'), notes: S('Details.'), priority: S('"low", "normal", or "high".'),
    }, ['id']),
    annotations: WRITE_IDEMPOTENT,
    run: async (api, a) => {
      const id = intArg(a.id, 'id');
      const body = pick(a, TASK_FIELDS);
      if (!Object.keys(body).length) throw new Error('nothing to change — pass at least one field besides id');
      await api('PATCH', '/api/tasks/' + id, body);
      return { ok: true, id, changed: Object.keys(body) };
    },
  },
  {
    name: 'list_clients',
    description: 'Active clients with their onboarding stage, project type, value and monthly recurring amount. Default 50, max 200; pass next_cursor back as cursor.',
    inputSchema: obj({ rep: S('Only clients assigned to this user id, or "unassigned".'), limit: I('Rows, 1–200. Default 50.'), cursor: S('next_cursor from the previous page.') }),
    annotations: READ,
    run: async (api, a) => {
      const rows = await api('GET', '/api/clients' + (a.rep ? '?rep=' + encodeURIComponent(str(a.rep, 'rep')) : ''));
      const p = page(rows, { cursor: a.cursor, limit: a.limit });
      return { total: p.total, returned: p.returned, next_cursor: p.next_cursor, clients: p.items };
    },
  },
  {
    name: 'update_client',
    description: 'Change a client record: stage, contact details, value, or description. Only the fields you pass change.',
    inputSchema: obj({
      id: S('Client id (UUID).'),
      stage: S('Onboarding stage.'), contact: S('Contact name.'), email: S('Email.'), phone: S('Phone.'),
      project_type: S('What we are building.'), value: I('Contract value, dollars.'), mrr: I('Monthly recurring, dollars.'),
      description: S('Notes about the business.'), website: S('Website URL.'),
    }, ['id']),
    annotations: WRITE_IDEMPOTENT,
    run: async (api, a) => {
      const id = str(a.id, 'id', 36);
      if (!/^[0-9a-fA-F-]{36}$/.test(id)) throw new Error('id must be the client UUID from list_clients');
      const body = pick(a, CLIENT_FIELDS);
      if (!Object.keys(body).length) throw new Error('nothing to change — pass at least one field besides id');
      await api('PATCH', '/api/clients/' + id, body);
      return { ok: true, id, changed: Object.keys(body) };
    },
  },
];

// ── Lead generator ───────────────────────────────────────────────────────────
// The CRM fronts the leadgen container (`/api/tools/lg/*`, admin only — the CRM
// answers 403 for a rep, which surfaces here as a tool error). A sweep discovers
// businesses in a city, writes them into the website campaign as leads with a
// recommended service, and since 2026-09-10 chains phone enrichment when done.
// Nothing here touches outreach. The bot was removed from the CRM entirely on
// 2026-09-11, routes and all, so there is nothing to expose; before that its
// controls were deliberately left off this table anyway, because an agent
// starting an email campaign from a sentence is the floor halo-agent applies
// to "send".
//
// The enterprise and AI-consulting generators are GATED in the CRM and have no
// tools here either: a tool whose every call answers 409 is a worse answer than
// no tool.
TOOLS.push(
  {
    name: 'start_lead_sweep',
    description: 'Start the Starter Lead Generator for one city: finds local businesses, writes them into the "dimedata-website" campaign as leads with a recommended service, then enriches phone numbers. Admin only. One sweep at a time; check sweep_status. Options: ' + SWEEP_OPTIONS.join(', ') + '.',
    inputSchema: obj({
      city: S('City to sweep, e.g. "Franklin".'),
      state: S('Two-letter state, e.g. "TN".'),
      county: S('County, when the city alone is ambiguous.'),
      options: { type: 'array', items: { type: 'string', enum: SWEEP_OPTIONS }, description: 'Which services to source for. Default: all.' },
      local: { type: 'boolean', description: 'Restrict to businesses that read as local and independent. Default false.' },
      auto_enrich: { type: 'boolean', description: 'Run phone enrichment on the new leads when the sweep finishes. Default true.' },
    }, ['city', 'state']),
    annotations: WRITE,
    run: async (api, a) => {
      // Validate BEFORE trimming to length: slicing first turned "Tennessee"
      // into "TE" and swept the wrong place without complaining (caught by the
      // test that asserts the refusal, 2026-09-10).
      const state = str(a.state, 'state', 40).toUpperCase();
      if (!/^[A-Z]{2}$/.test(state)) throw new Error('state must be a two-letter code, e.g. "TN" — got "' + a.state + '"');
      const options = Array.isArray(a.options) ? a.options.filter((o) => SWEEP_OPTIONS.includes(o)) : [];
      const body = { city: str(a.city, 'city', 80), state, options, local: a.local === true, autoEnrich: a.auto_enrich !== false };
      if (a.county) body.county = str(a.county, 'county', 80);
      const r = await api('POST', '/api/tools/lg/scrape', body);
      if (r && r.error) throw new Error(r.error === 'busy' ? 'a sweep is already running — check sweep_status' : String(r.error));
      return { started: Boolean(r && r.started), city: body.city, state, options: options.length ? options : SWEEP_OPTIONS, auto_enrich: Boolean(r && r.autoEnrich) };
    },
  },
  {
    name: 'sweep_status',
    description: 'Progress of the current or last lead sweep (scanned, created, skipped, by service option, log tail) and of phone enrichment. Poll this after start_lead_sweep. Admin only.',
    inputSchema: obj({ log_lines: I('How many log lines to include, 0–50. Default 10.') }),
    annotations: READ,
    run: async (api, a) => {
      const [sweep, phones] = await Promise.all([api('GET', '/api/tools/lg/status'), api('GET', '/api/tools/phones/status').catch(() => null)]);
      const n = Math.min(Math.max(0, a.log_lines == null ? 10 : Number(a.log_lines) || 0), 50);
      const s = sweep || {};
      return {
        sweep: {
          running: Boolean(s.running), done: Boolean(s.done), error: s.error || null,
          scanned: s.scanned || 0, discovered: s.discovered || 0, created: s.created || 0, skipped: s.skipped || 0,
          no_need: (s.noNeed || 0) + (s.offPackage || 0), no_contact: s.noContact || 0, not_business: s.notBusiness || 0,
          by_option: s.byOption || {}, by_tier: s.byTier || {},
          log: Array.isArray(s.log) ? s.log.slice(-n) : [],
        },
        phone_enrichment: phones ? { running: Boolean(phones.running), pending: Boolean(phones.pending), auto: Boolean(phones.auto), done: phones.done || 0, found: phones.found || 0, total: phones.total || 0 } : null,
      };
    },
  },
);

const TOOL_BY_NAME = new Map(TOOLS.map((t) => [t.name, t]));

/** The tools/list payload: the table without its `run`. */
function publicTools() {
  return TOOLS.map(({ run, ...t }) => t);
}

/**
 * Build the `api` a tool runs with: loopback to this same process, as the caller.
 * The Authorization header is forwarded untouched, so scoping is whatever the
 * CRM decides for that identity — this module never learns the token.
 */
function loopbackApi({ port, authorization, fetchImpl = fetch }) {
  return async (method, path, body) => {
    const res = await fetchImpl('http://127.0.0.1:' + port + path, {
      method,
      headers: {
        authorization: authorization || '',
        accept: 'application/json',
        ...(body !== undefined ? { 'content-type': 'application/json' } : {}),
      },
      body: body !== undefined ? JSON.stringify(body) : undefined,
    });
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch { data = { raw: text.slice(0, 500) }; }
    if (!res.ok) {
      const msg = (data && data.error) || ('HTTP ' + res.status);
      throw new Error(method + ' ' + path.split('?')[0] + ' → ' + msg);
    }
    return data;
  };
}

const rpcError = (id, code, message) => ({ jsonrpc: '2.0', id, error: { code, message } });
const rpcResult = (id, result) => ({ jsonrpc: '2.0', id, result });

/** Tools the caller's scopes allow: read tools always, write tools only with crm:write. */
function allowedTools(scopes) {
  const canWrite = !scopes || scopes.includes('crm:write');
  return TOOLS.filter((t) => canWrite || (t.annotations && t.annotations.readOnlyHint));
}

/** Answer one JSON-RPC message. Returns null for notifications (no reply owed). */
async function dispatch(msg, api, scopes) {
  if (!msg || typeof msg !== 'object' || msg.jsonrpc !== '2.0' || typeof msg.method !== 'string') {
    return rpcError(msg && msg.id !== undefined ? msg.id : null, -32600, 'invalid request');
  }
  const { id, method, params = {} } = msg;
  const isNotification = id === undefined || id === null;
  if (isNotification) return null;

  switch (method) {
    case 'initialize': {
      const asked = params && params.protocolVersion;
      const protocolVersion = PROTOCOL_VERSIONS.includes(asked) ? asked : PROTOCOL_VERSIONS[0];
      return rpcResult(id, { protocolVersion, capabilities: { tools: { listChanged: false } }, serverInfo: SERVER_INFO });
    }
    case 'ping':
      return rpcResult(id, {});
    case 'tools/list':
      // Filtered by scope, the way Close filters its tool list by tier: a read-only
      // connection never sees a write tool it would be refused.
      return rpcResult(id, { tools: allowedTools(scopes).map(({ run, ...t }) => t) });
    case 'tools/call': {
      const tool = TOOL_BY_NAME.get(params && params.name);
      if (!tool) return rpcError(id, -32602, 'unknown tool: ' + String(params && params.name));
      if (!allowedTools(scopes).includes(tool)) {
        return rpcResult(id, { content: [{ type: 'text', text: 'This connection is read-only: ' + tool.name + ' needs the crm:write scope. Reconnect the CRM and allow "Add and update" to use it.' }], isError: true });
      }
      const args = (params && params.arguments) || {};
      try {
        const out = await tool.run(api, args);
        return rpcResult(id, { content: [{ type: 'text', text: JSON.stringify(out === undefined ? { ok: true } : out) }], isError: false });
      } catch (e) {
        return rpcResult(id, { content: [{ type: 'text', text: String((e && e.message) || e) }], isError: true });
      }
    }
    case 'resources/list':
      return rpcResult(id, { resources: [] });
    case 'prompts/list':
      return rpcResult(id, { prompts: [] });
    default:
      return rpcError(id, -32601, 'method not found: ' + method);
  }
}

/**
 * Serve POST /mcp. The caller has already been authenticated by server.js.
 *
 *   GET    → 405: no server-initiated stream here, every answer is one JSON body.
 *   DELETE → 200: sessions are stateless, so ending one is a no-op.
 *   POST   → one message or a batch; notifications alone answer 202 with no body.
 */
async function handleMcp(req, res, { api, readBody, scopes }) {
  const method = String(req.method || 'GET').toUpperCase();
  const send = (status, body) => {
    const headers = { 'Cache-Control': 'no-store' };
    if (body !== undefined) headers['Content-Type'] = 'application/json';
    res.writeHead(status, headers);
    res.end(body === undefined ? undefined : JSON.stringify(body));
  };
  if (method === 'DELETE') return send(200, { ok: true });
  if (method !== 'POST') {
    res.setHeader('Allow', 'POST, DELETE');
    return send(405, { error: 'MCP over HTTP here is POST only' });
  }
  let parsed;
  try {
    parsed = JSON.parse((await readBody(req)) || '');
  } catch {
    return send(400, rpcError(null, -32700, 'parse error'));
  }
  const batch = Array.isArray(parsed);
  const messages = batch ? parsed : [parsed];
  if (!messages.length) return send(400, rpcError(null, -32600, 'empty batch'));
  const replies = (await Promise.all(messages.map((m) => dispatch(m, api, scopes)))).filter(Boolean);
  if (!replies.length) return send(202);
  return send(200, batch ? replies : replies[0]);
}

module.exports = { TOOLS, publicTools, allowedTools, handleMcp, dispatch, loopbackApi, page, PROTOCOL_VERSIONS, SERVER_INFO, DISPOSITIONS };
