# Excerpts

Three files from the private Dime Data CRM source at commit 3529c8b, copied unchanged apart from a
header (and, in `oauth-server.js`, one example URL that named the production host). Each one reads
on its own.

| File | Why it's here |
|---|---|
| [`mcp-server.js`](mcp-server.js) | The CRM as an MCP server, whole. Stateless streamable HTTP. It never touches the database: every tool calls the CRM's own HTTP API on loopback with the caller's own token, so an agent gets exactly the scoping and field allow-lists its person would. Write tools send only allow-listed fields, bad arguments come back as tool errors rather than RPC faults, and there is no delete tool. |
| [`oauth-server.js`](oauth-server.js) | The OAuth 2.1 authorization server that lets an agent host connect with a sign-in instead of a pasted key: dynamic registration or a client metadata URL, PKCE S256 required, exact redirect matching, resource binding, single-use five-minute codes and rotating refresh tokens. The header lists each rule next to the attack it closes. |
| [`sessions.js`](sessions.js) | Signed stateless sessions that survive container swaps, a revocation list for logout, and a per-user credentials epoch: a stateless token can't be deleted, so a password change instead refuses every session issued before it. The comments record the trade-offs, including what a restart forgets. |

These files aren't licensed for reuse. They're here to show how the product is built.
