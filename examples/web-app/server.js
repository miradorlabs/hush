// Zero-dependency demo web app for exercising hush end-to-end.
// It reads its secrets from the environment exactly like a real app — so
// `hush run -- node server.js` injects them, and `node server.js` alone gets
// nothing. No npm install needed (which also keeps clear of hush's pkg guard).
const http = require('http');

const PORT = process.env.PORT || 3000;
const API_KEY = process.env.API_KEY;
const DATABASE_URL = process.env.DATABASE_URL;

// Show that a secret is present without printing it: first 3 chars + length.
function masked(v) {
  if (!v) return '(missing — did you start with `hush run`?)';
  return `${v.slice(0, 3)}***  (len ${v.length})`;
}

const server = http.createServer((req, res) => {
  if (req.url === '/leak') {
    // Deliberately leak a secret to stdout to demo `hush run --watch`.
    // In watch mode hush detects this line and alerts (and --redact masks it).
    console.log(`[debug] full API_KEY = ${API_KEY}`);
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('Leaked the full API_KEY to stdout. If you ran with --watch, hush just alerted.\n');
    return;
  }
  res.writeHead(200, { 'content-type': 'text/plain' });
  res.end(
    `hush demo app\n\n` +
    `API_KEY:      ${masked(API_KEY)}\n` +
    `DATABASE_URL: ${masked(DATABASE_URL)}\n\n` +
    `try GET /leak to trigger an intentional secret leak (see hush --watch)\n`
  );
});

server.listen(PORT, () => {
  console.log(`hush demo app listening on http://localhost:${PORT}`);
  console.log(`secrets loaded: API_KEY=${API_KEY ? 'yes' : 'NO'}, DATABASE_URL=${DATABASE_URL ? 'yes' : 'NO'}`);
});
