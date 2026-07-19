// selftest.mjs — run after any scaffold edit, before every push.
// Catches the two failure modes that matter most: a file silently truncated
// or null-padded by a sync hazard, and a JS file that doesn't actually parse.
// This does NOT hit any live provider API — it only checks the files on disk.

import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import path from "node:path";
import { execFileSync } from "node:child_process";

const root = path.dirname(fileURLToPath(import.meta.url));
let failures = 0;

function fail(msg) {
  console.error(`FAIL: ${msg}`);
  failures++;
}
function ok(msg) {
  console.log(`ok:   ${msg}`);
}

function checkNotEmptyOrPadded(relPath, minBytes) {
  const p = path.join(root, relPath);
  if (!existsSync(p)) return fail(`${relPath} is missing`);
  const buf = readFileSync(p);
  if (buf.length < minBytes) return fail(`${relPath} is only ${buf.length} bytes (expected at least ${minBytes}) — looks truncated`);
  if (buf.includes(0)) return fail(`${relPath} contains null bytes — looks null-padded (sync hazard, not a content bug: rebuild it via the shell)`);
  const text = buf.toString("utf8");
  const trimmed = text.trimEnd();
  if (!trimmed.length) return fail(`${relPath} is empty`);
  ok(`${relPath}: ${buf.length} bytes, no null padding`);
  return text;
}

// --- wrangler.toml ---
{
  const text = checkNotEmptyOrPadded("wrangler.toml", 50);
  if (text) {
    for (const key of ["name", "main", "compatibility_date", "[[kv_namespaces]]", "binding = \"TOKENS\"", "[assets]"]) {
      if (!text.includes(key)) fail(`wrangler.toml missing expected "${key}"`);
    }
    if (text.includes("REPLACE_AFTER_FIRST_DEPLOY")) {
      console.log("note: wrangler.toml KV id is still the placeholder — expected until after the first Cloudflare deploy, then it must be pinned.");
    }
  }
}

// --- package.json ---
{
  const text = checkNotEmptyOrPadded("package.json", 30);
  if (text) {
    try {
      const pkg = JSON.parse(text);
      if (!pkg.scripts?.deploy) fail("package.json missing scripts.deploy");
    } catch (e) {
      fail(`package.json does not parse as JSON: ${e.message}`);
    }
  }
}

// --- worker.js ---
{
  const text = checkNotEmptyOrPadded("worker.js", 2000);
  if (text) {
    if (!text.trimEnd().endsWith("};") && !text.trimEnd().endsWith("}")) {
      fail("worker.js doesn't end on a closing brace — likely truncated mid-file");
    }
    try {
      execFileSync(process.execPath, ["--check", path.join(root, "worker.js")], { stdio: "pipe" });
      ok("worker.js parses as valid JS");
    } catch (e) {
      fail(`worker.js failed to parse: ${e.stderr?.toString() || e.message}`);
    }
    for (const marker of ["export default", "async fetch(req, env)", "/api/metrics", "/api/setup", "/api/connect/xero/callback"]) {
      if (!text.includes(marker)) fail(`worker.js missing expected marker: ${marker}`);
    }
  }
}

// --- public/dashboard.html ---
{
  const text = checkNotEmptyOrPadded("public/dashboard.html", 3000);
  if (text) {
    const trimmed = text.trimEnd();
    if (!trimmed.endsWith("</html>")) fail("public/dashboard.html doesn't end with </html> — likely truncated");
    if (!text.includes("<script>") || !text.includes("</script>")) fail("public/dashboard.html missing a complete <script> block");
    const openTags = (text.match(/<script>/g) || []).length;
    const closeTags = (text.match(/<\/script>/g) || []).length;
    if (openTags !== closeTags) fail(`public/dashboard.html has ${openTags} <script> but ${closeTags} </script> — unbalanced`);
    for (const marker of ["doSetup", "doLogin", "loadBoard", "renderBoard", "confirmMetric"]) {
      if (!text.includes(marker)) fail(`public/dashboard.html missing expected function: ${marker}`);
    }
  }
}

console.log("");
if (failures > 0) {
  console.error(`selftest FAILED: ${failures} problem(s). Do not push — rebuild the flagged file(s) and re-run.`);
  process.exit(1);
} else {
  console.log("selftest passed. Safe to push.");
}
