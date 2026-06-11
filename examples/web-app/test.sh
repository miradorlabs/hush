#!/usr/bin/env bash
# Non-interactive walkthrough of hush against the demo app. The auth-gated steps
# (lock/run) need Touch ID and can't be scripted — they're printed at the end to
# run by hand. Everything here runs without a prompt.
set -uo pipefail
cd "$(dirname "$0")"
indent() { sed 's/^/   /'; }

if ! command -v hush >/dev/null; then
  echo "hush not on PATH — run 'make install' first"; exit 1
fi

echo "▶ 1) the app WITHOUT hush — secrets missing"
node server.js >/tmp/hush_demo.$$.log 2>&1 &
pid=$!
for _ in $(seq 1 40); do curl -s -o /dev/null localhost:3000/ && break; sleep 0.25; done
curl -s localhost:3000/ | indent
kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; rm -f /tmp/hush_demo.$$.log

echo
echo "▶ 2) honeytoken decoy — a fake .env an agent/scanner would grab"
hush decoy -o .env.decoy >/dev/null
grep -E 'hush-decoy|AWS_ACCESS_KEY_ID|DATABASE_URL' .env.decoy | indent
rm -f .env.decoy

echo
echo "▶ 3) package-manager guard — refused (no prompt)"
hush run -- npm install 2>&1 | head -1 | indent

echo
echo "▶ 4) MITM-on-delivery guard — relative command refused"
hush run -- ./evil 2>&1 | head -1 | indent

echo
echo "▶ 5) doctor — should be clean here (.env.example is not flagged)"
hush doctor | indent

echo
echo "✔ non-interactive demo complete."
echo "  Auth-gated flow (needs Touch ID), try by hand:"
echo "     cp .env.example .env && hush lock --rm"
echo "     hush run -- node server.js              # http://localhost:3000"
echo "     hush run --watch -- node server.js      # then: curl localhost:3000/leak"
