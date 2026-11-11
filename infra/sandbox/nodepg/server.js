// A deliberately vulnerable Node + Postgres app: a bundled practice target that proves the
// range can stand up a real app image backed by a real datastore. It is the Node+Postgres
// analogue of the stdlib practice targets (vulnweb.py, noteapp.py). NOT production code; the
// SQL below is string-concatenated on purpose so the harness confirms a Postgres-backed SQLi
// end to end against a genuine app image, not a stdlib stand-in.
//
// Routes:
//   GET /              -> an HTML index linking to the notes endpoint, so a black-box crawl finds
//                         /notes and its `tag` parameter (a real app has an entry page to follow)
//   GET /healthz        -> 200 "ok", the readiness probe the harness polls before proofs/recon
//   GET /notes?tag=...  -> notes whose tag matches; the `tag` value is inlined into the query,
//                          so `' OR '1'='1` returns every row including the seeded secret.
"use strict";

const http = require("http");
const { URL } = require("url");
const { Pool } = require("pg");

const PORT = parseInt(process.env.PORT || "3000", 10);
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

async function connectWithRetry(attempts = 30) {
  // Provisioning waits on pg_isready before starting us, but a short retry keeps the app robust
  // if the socket is accepting before the server finishes its own startup.
  for (let i = 1; i <= attempts; i++) {
    try {
      const c = await pool.connect();
      c.release();
      return;
    } catch (err) {
      if (i === attempts) throw err;
      await new Promise((r) => setTimeout(r, 1000));
    }
  }
}

function send(res, status, body, type = "text/plain") {
  res.writeHead(status, { "content-type": type });
  res.end(body);
}

const server = http.createServer(async (req, res) => {
  let url;
  try {
    url = new URL(req.url, `http://localhost:${PORT}`);
  } catch {
    return send(res, 400, "bad request");
  }

  if (url.pathname === "/healthz") return send(res, 200, "ok");

  if (url.pathname === "/") {
    const html =
      "<!doctype html><html><head><title>Notes</title></head><body>" +
      "<h1>Notes</h1><ul>" +
      '<li><a href="/notes?tag=public">public notes</a></li>' +
      '<li><a href="/notes?tag=todo">todo notes</a></li>' +
      "</ul></body></html>";
    return send(res, 200, html, "text/html");
  }

  if (url.pathname === "/notes") {
    const tag = url.searchParams.get("tag") || "";
    // INTENTIONALLY VULNERABLE: the tag is concatenated straight into the statement.
    const sql = `SELECT id, tag, body FROM notes WHERE tag = '${tag}' ORDER BY id`;
    try {
      const { rows } = await pool.query(sql);
      return send(res, 200, JSON.stringify(rows), "application/json");
    } catch (err) {
      // Echoing the driver error back is itself a realistic weakness (error-based SQLi aid).
      return send(res, 500, String(err && err.message ? err.message : err));
    }
  }

  return send(res, 404, "not found");
});

connectWithRetry()
  .then(() => server.listen(PORT, () => console.log(`nodepg practice target on :${PORT}`)))
  .catch((err) => {
    console.error("could not reach the database:", err.message);
    process.exit(1);
  });
