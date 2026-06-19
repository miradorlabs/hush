# hush demo — MCP secrets gateway

Exercises `hush mcp` end-to-end: instead of your AI tool reading `.env`, it
requests secrets through an MCP server, and every request runs the full hush
check path plus a Touch ID prompt that names the caller and the key. This folder
shows the least-privilege policy and the reference-handle path (`http_request`),
and a non-interactive script for the parts that need no prompt.

## Files

- `.env.example` — fake demo secrets; copy to `.env`.
- `.hushmcp.json` — the least-privilege policy (below).
- `mcp-config.json` — paste this into your AI tool's MCP config (set the absolute `--project` path).
- `test.sh` — non-interactive walkthrough of the pre-decryption refusals.

## The policy

```json
{
  "allow": ["DATABASE_URL", "API_KEY", "STRIPE_*"],
  "deny":  ["STRIPE_SECRET_KEY"],
  "http_allow_hosts": ["api.github.com"]
}
```

With these demo secrets that means:

| Key | Servable? | Why |
|---|---|---|
| `DATABASE_URL`, `API_KEY` | ✅ | on the allowlist |
| `STRIPE_PUBLISHABLE_KEY` | ✅ | matches `STRIPE_*` |
| `STRIPE_SECRET_KEY` | ❌ | `deny` wins over the `STRIPE_*` allow |
| `AWS_SECRET_ACCESS_KEY` | ❌ | not on the allowlist |

`http_request` may only send to `api.github.com`; any other host is refused
before a secret is ever decrypted.

## Run the non-interactive demo (no Touch ID)

```sh
cd examples/mcp-gateway
./test.sh
```

It drives the gateway over stdio and shows the refusals that happen *before* any
decryption: a denied key and a non-allowlisted host are rejected with no prompt,
and each is written to the access log (`hush log`).

## The auth-gated flow (by hand — needs Touch ID)

```sh
cp .env.example .env
hush lock --rm --bind-config          # seal; also bind the AI-tool config
```

Then point your AI tool at the gateway. Copy the `mcpServers` entry from
`mcp-config.json` into your tool's config (Claude Code: `.mcp.json`; Cursor:
`~/.cursor/mcp.json`) and set `--project` to this folder's absolute path. Now in
the tool:

- `get_secret("DATABASE_URL")` → Touch ID prompt naming the key → returns the value.
- `get_secret("STRIPE_SECRET_KEY")` → refused by policy, no prompt.
- `http_request` to `api.github.com` with `Authorization: Bearer {{secret:API_KEY}}`
  → hush substitutes the real key **server-side**, makes the call, and returns
  the response — the value never enters the model's context.

Review everything with `hush log`.

## The point — and the honest limit

The gateway gives you **consent you can see** (the Touch ID prompt names the
key), a **full audit trail**, **least-privilege** so a compromised agent can't
grab the whole set, and the `http_request` path that keeps a secret out of the
model context and off any host you didn't approve.

It does not make exfiltration impossible: once `get_secret` returns a value, the
assistant holds it and could leak it. That residual risk is why you also wire the
fake values to canary tokens (`hush decoy`) and bind the AI-tool config
(`hush lock --bind-config`) so the instruction telling the agent to use the
gateway can't be quietly rewritten.

## Notes

- `.env` and any `.hush` you create here are gitignored by the repo root; the
  `.env.example`, `.hushmcp.json`, and `mcp-config.json` are committable.
- Steer your assistant from `CLAUDE.md` to use these tools and never read `.env`
  directly — see the gateway section in the repo root README.
