# hush demo — web app

A tiny zero-dependency Node web app that reads its secrets from the environment,
for exercising hush end-to-end. It demonstrates the original use case: the app
needs `.env` values, but they stay encrypted until you approve a prompt.

## Setup

```sh
cd examples/web-app
cp .env.example .env          # put real or fake values here
hush lock --rm                # prompt to sign → .env becomes .hush, plaintext shredded
```

## The point: secrets only flow with approval

```sh
node server.js                # secrets MISSING — the app sees no .env
hush run -- node server.js    # prompt to decrypt → secrets injected → app works
```

Open http://localhost:3000 — with `hush run` the app reports the secrets are
loaded (masked); plain `node server.js` shows them missing. `cat .hush` is just
ciphertext.

## Exercise the extra protections

```sh
# Least-privilege: hand the app only one secret
hush run --only API_KEY -- node server.js     # DATABASE_URL shows missing

# Exposure tripwire: catch a secret leaking into output
hush run --watch -- node server.js            # then: curl localhost:3000/leak
#   the /leak route prints the full API_KEY to stdout;
#   hush detects it, logs an EXPOSURE event, and alerts.
hush run --redact -- node server.js           # same, but the value is masked in-stream

# Supply-chain guard (refused by default)
hush run -- npm install                       # BLOCKED

# Honeytoken decoy: leave canary bait where .env was
hush lock --decoy                             # a fake .env an agent/scanner would grab

# Review what happened
hush log
hush doctor                                   # should be all-clear here
```

## Notes

- The real `.env` and the `.hush` you create are gitignored by the repo root
  `.gitignore`; `.env.example` is committable.
- `node server.js` is resolved to its absolute path before any secret is
  injected (hush's MITM-on-delivery guard).
