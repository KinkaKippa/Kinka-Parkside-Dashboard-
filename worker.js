// Kinka Parkside KPI dashboard — Cloudflare Worker
//
// Everything here follows the locked metric definitions in kpi-spec.md and the
// rules in CLAUDE.md: every money figure comes from Xero (ex-GST), Square
// supplies only the transaction count, read-only everywhere, "not configured"
// instead of a misleading number, and nothing is trusted until reconciled.
//
// Storage:
//  - env.TOKENS (KV)  -> auth password hash, session signing key, settings,
//                        rotating Xero OAuth tokens, ingest cache, last-synced
//                        timestamps, per-metric verified flags.
//  - env.XERO_CLIENT_ID / XERO_CLIENT_SECRET  -> Cloudflare secrets (static app
//                        credentials, set once via Variables and Secrets).
//  - env.SQUARE_API_TOKEN                  -> Cloudflare secret (Square
//                        production personal access token, pasted once).
//  - env.INGEST_TOKEN                         -> Cloudflare secret, the
//                        owner's "upload code" for guided upload / scheduled
//                        pull ingestion.

const METRIC_KEYS = ["revenue", "transactions", "acs", "cogs", "wagePct", "overheads", "profit"];

const DEFAULT_SETTINGS = {
  venueName: "",
  timezone: "Australia/Brisbane",
  weekStartDay: 1, // 0=Sunday .. 6=Saturday. 1=Monday is the AU default.
  tradingDayRolloverHour: 0, // 0 = midnight, no rollover.
  defaultPeriod: "this_month",
  accentColor: "#2563eb",
  targets: {
    wagePct: null,
    cogsPct: null,
    overheadsPct: null,
    profitPct: null,
  },
  // Wage/super account matching (kpi-spec.md #5). Auto-detected accounts are
  // proposed; nothing is trusted for Wage % / Overheads until the owner has
  // confirmed the exact list during reconciliation.
  confirmedWageAccounts: null, // null = not yet confirmed; else string[] of exact Xero account names.
  verified: { revenue: false, transactions: false, cogs: false, wagePct: false, overheads: false, profit: false },
};

const WAGE_KEYWORD_RE = /wages|salaries|superannuation|super|payroll|annual leave|long service|workcover/i;

// Owner-confirmed wage/super accounts (confirmed 2026-07-21 during Milestone 4
// reconciliation). Wage % = rostered venue staff labour only: "Wages and
// Salaries (In Venue)" + "Superannuation (In Venue)". The owner explicitly
// decided "Wages and Salaries (Overhead)" (admin/management salaries, not
// tied to trading volume) should NOT count toward Wage % and instead falls
// into the Overheads bucket, same as any other non-wage operating expense.
// Used as the fallback when settings.confirmedWageAccounts hasn't been set
// via the (not-yet-built) Settings UI — see summarizeXeroPnl's caller below.
const CONFIRMED_WAGE_ACCOUNTS = ["Wages and Salaries (In Venue)", "Superannuation (In Venue)"];

// ---------- small helpers ----------

function json(data, init = {}) {
  return new Response(JSON.stringify(data), {
    ...init,
    headers: { "content-type": "application/json; charset=utf-8", ...(init.headers || {}) },
  });
}

function badRequest(msg) {
  return json({ error: msg }, { status: 400 });
}

function unauthorized(msg = "Not signed in") {
  return json({ error: msg }, { status: 401 });
}

function b64urlEncode(bytes) {
  let bin = "";
  for (const b of new Uint8Array(bytes)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64urlDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  const bin = atob(str);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

function randomBytes(n) {
  const arr = new Uint8Array(n);
  crypto.getRandomValues(arr);
  return arr;
}

// Cloudflare Workers' PBKDF2 implementation caps iteration count (this
// runtime rejects anything above 10,000 with a NotSupportedError) — kept
// well under that ceiling rather than the higher counts you'd use outside
// this platform.
async function pbkdf2Hash(password, saltBytes, iterations = 10000) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt: saltBytes, iterations, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return new Uint8Array(bits);
}

async function hmacSign(keyBytes, message) {
  const key = await crypto.subtle.importKey("raw", keyBytes, { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return new Uint8Array(sig);
}

function timingSafeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

// ---------- KV-backed state ----------

async function getSettings(env) {
  const raw = await env.TOKENS.get("settings", "json");
  if (!raw) return { ...DEFAULT_SETTINGS };
  return { ...DEFAULT_SETTINGS, ...raw, targets: { ...DEFAULT_SETTINGS.targets, ...(raw.targets || {}) }, verified: { ...DEFAULT_SETTINGS.verified, ...(raw.verified || {}) } };
}

async function saveSettings(env, settings) {
  await env.TOKENS.put("settings", JSON.stringify(settings));
}

async function getSessionKey(env) {
  let raw = await env.TOKENS.get("auth:sessionKey");
  if (raw) return b64urlDecode(raw);
  const key = randomBytes(32);
  await env.TOKENS.put("auth:sessionKey", b64urlEncode(key));
  return key;
}

async function isSetupComplete(env) {
  return !!(await env.TOKENS.get("auth:password"));
}

async function setPassword(env, password) {
  const salt = randomBytes(16);
  const hash = await pbkdf2Hash(password, salt);
  await env.TOKENS.put("auth:password", JSON.stringify({ salt: b64urlEncode(salt), hash: b64urlEncode(hash), iterations: 10000 }));
}

async function checkPassword(env, password) {
  const raw = await env.TOKENS.get("auth:password", "json");
  if (!raw) return false;
  const salt = b64urlDecode(raw.salt);
  const hash = await pbkdf2Hash(password, salt, raw.iterations || 10000);
  return timingSafeEqual(hash, b64urlDecode(raw.hash));
}

async function makeSessionCookie(env) {
  const key = await getSessionKey(env);
  const payload = { iat: Date.now(), exp: Date.now() + 1000 * 60 * 60 * 24 * 30 };
  const payloadStr = b64urlEncode(new TextEncoder().encode(JSON.stringify(payload)));
  const sig = await hmacSign(key, payloadStr);
  const token = `${payloadStr}.${b64urlEncode(sig)}`;
  return `session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=2592000`;
}

function clearSessionCookie() {
  return `session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0`;
}

function readCookie(req, name) {
  const header = req.headers.get("cookie") || "";
  for (const part of header.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return null;
}

async function isAuthenticated(req, env) {
  const token = readCookie(req, "session");
  if (!token) return false;
  const [payloadStr, sigStr] = token.split(".");
  if (!payloadStr || !sigStr) return false;
  const key = await getSessionKey(env);
  const expected = await hmacSign(key, payloadStr);
  if (!timingSafeEqual(expected, b64urlDecode(sigStr))) return false;
  try {
    const payload = JSON.parse(new TextDecoder().decode(b64urlDecode(payloadStr)));
    return payload.exp > Date.now();
  } catch {
    return false;
  }
}

// ---------- date / period math (venue-timezone aware, date-only) ----------

function partsInTz(date, timeZone) {
  const fmt = new Intl.DateTimeFormat("en-CA", {
    timeZone,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    hour12: false,
  });
  const parts = Object.fromEntries(fmt.formatToParts(date).map((p) => [p.type, p.value]));
  return { y: Number(parts.year), m: Number(parts.month), d: Number(parts.day), h: Number(parts.hour === "24" ? "0" : parts.hour) };
}

function ymd(y, m, d) {
  return `${String(y).padStart(4, "0")}-${String(m).padStart(2, "0")}-${String(d).padStart(2, "0")}`;
}

function dateFromYmd(s) {
  const [y, m, d] = s.split("-").map(Number);
  // Use noon UTC as a stable anchor so day-math never slips a day via DST.
  return new Date(Date.UTC(y, m - 1, d, 12));
}

function addDays(s, n) {
  const dt = dateFromYmd(s);
  dt.setUTCDate(dt.getUTCDate() + n);
  return ymd(dt.getUTCFullYear(), dt.getUTCMonth() + 1, dt.getUTCDate());
}

function addMonths(s, n) {
  const [y, m, d] = s.split("-").map(Number);
  const dt = new Date(Date.UTC(y, m - 1 + n, 1, 12));
  const lastDay = new Date(Date.UTC(dt.getUTCFullYear(), dt.getUTCMonth() + 1, 0, 12)).getUTCDate();
  return ymd(dt.getUTCFullYear(), dt.getUTCMonth() + 1, Math.min(d, lastDay));
}

function startOfMonth(s) {
  const [y, m] = s.split("-").map(Number);
  return ymd(y, m, 1);
}

function endOfMonth(s) {
  const [y, m] = s.split("-").map(Number);
  const last = new Date(Date.UTC(y, m, 0, 12)).getUTCDate();
  return ymd(y, m, last);
}

function todayInVenue(settings) {
  const { y, m, d, h } = partsInTz(new Date(), settings.timezone);
  if (h < (settings.tradingDayRolloverHour || 0)) {
    return addDays(ymd(y, m, d), -1);
  }
  return ymd(y, m, d);
}

function startOfWeek(dateStr, weekStartDay) {
  const dow = dateFromYmd(dateStr).getUTCDay(); // 0=Sun..6=Sat
  const diff = (dow - weekStartDay + 7) % 7;
  return addDays(dateStr, -diff);
}

// How far ahead of UTC a given IANA timezone is, in minutes, at a given
// instant (handles DST automatically for zones that observe it; Brisbane/
// Queensland doesn't, but this keeps it correct if the venue's timezone
// setting is ever changed to one that does).
function tzOffsetMinutes(utcMs, timeZone) {
  const dtf = new Intl.DateTimeFormat("en-US", {
    timeZone,
    hourCycle: "h23",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
  });
  const parts = Object.fromEntries(dtf.formatToParts(new Date(utcMs)).map((p) => [p.type, p.value]));
  const asIfUtc = Date.UTC(+parts.year, +parts.month - 1, +parts.day, +parts.hour === 24 ? 0 : +parts.hour, +parts.minute, +parts.second);
  return (asIfUtc - utcMs) / 60000;
}

// Converts a venue-local calendar date + time-of-day (e.g. midnight) into the
// correct UTC instant, given the venue's IANA timezone. This is what
// squareTransactionCount needs so that "today" for Square's search matches
// the same real-world midnight-to-midnight window the owner sees on her own
// Square dashboard — a naive `${dateStr}T00:00:00Z` treats the date as if it
// were already UTC, which for Queensland (UTC+10) shifts every window ~10
// hours late and mis-attributes early-morning trade to the wrong day.
function zonedMidnightToUtcIso(dateStr, timeZone, hour = 0) {
  const [y, m, d] = dateStr.split("-").map(Number);
  let guessMs = Date.UTC(y, m - 1, d, hour, 0, 0);
  // Two passes handles the (rare) case where the initial guess lands on the
  // wrong side of a DST transition.
  for (let i = 0; i < 2; i++) {
    const offsetMin = tzOffsetMinutes(guessMs, timeZone);
    guessMs = Date.UTC(y, m - 1, d, hour, 0, 0) - offsetMin * 60000;
  }
  return new Date(guessMs).toISOString();
}

function financialYearStart(dateStr) {
  const [y, m] = dateStr.split("-").map(Number);
  const fyStartYear = m >= 7 ? y : y - 1;
  return ymd(fyStartYear, 7, 1);
}

// Returns { start, end } for the named period, plus its two comparisons.
// "this_*" periods are to-date (fair comparison across in-progress periods);
// "last_*" periods are the complete prior period. This mirrors how a manager
// actually reads a Monday-morning board and is a deliberate build choice
// (kpi-spec.md lists the period names but not to-date vs complete; documented
// here and in build-progress.md).
function resolvePeriod(kind, settings, customStart, customEnd) {
  const today = todayInVenue(settings);
  const wsd = settings.weekStartDay ?? 1;

  let start, end, label;

  if (kind === "this_week") {
    start = startOfWeek(today, wsd);
    end = today;
    label = "This week";
  } else if (kind === "last_week") {
    const thisStart = startOfWeek(today, wsd);
    start = addDays(thisStart, -7);
    end = addDays(thisStart, -1);
    label = "Last week";
  } else if (kind === "this_month") {
    start = startOfMonth(today);
    end = today;
    label = "This month";
  } else if (kind === "last_month") {
    const prevMonthAnyDay = addMonths(today, -1);
    start = startOfMonth(prevMonthAnyDay);
    end = endOfMonth(prevMonthAnyDay);
    label = "Last month";
  } else if (kind === "this_fy") {
    start = financialYearStart(today);
    end = today;
    label = "This financial year";
  } else if (kind === "last_fy") {
    const thisFyStart = financialYearStart(today);
    const lastFyStart = addMonths(thisFyStart, -12);
    start = lastFyStart;
    end = addDays(thisFyStart, -1);
    label = "Last financial year";
  } else if (kind === "custom") {
    if (!customStart || !customEnd) throw new Error("custom period needs start and end");
    start = customStart;
    end = customEnd;
    label = "Custom range";
  } else {
    throw new Error(`Unknown period: ${kind}`);
  }

  const spanDays = Math.round((dateFromYmd(end) - dateFromYmd(start)) / 86400000) + 1;
  const previousPeriod = { start: addDays(start, -spanDays), end: addDays(start, -1) };
  const sameLastYear = { start: addMonths(start, -12), end: addMonths(end, -12) };

  return { kind, label, start, end, previousPeriod, sameLastYear };
}

// ---------- Xero adapter ----------

const XERO_AUTHORIZE_URL = "https://login.xero.com/identity/connect/authorize";
const XERO_TOKEN_URL = "https://identity.xero.com/connect/token";
const XERO_CONNECTIONS_URL = "https://api.xero.com/connections";
const XERO_SCOPES = "offline_access accounting.reports.profitandloss.read";

async function xeroTokenRequest(env, body) {
  const basic = btoa(`${env.XERO_CLIENT_ID}:${env.XERO_CLIENT_SECRET}`);
  const res = await fetch(XERO_TOKEN_URL, {
    method: "POST",
    headers: {
      "content-type": "application/x-www-form-urlencoded",
      authorization: `Basic ${basic}`,
    },
    body: new URLSearchParams(body).toString(),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Xero token request failed (${res.status}): ${text}`);
  }
  return res.json();
}

async function xeroExchangeCode(env, code, redirectUri) {
  const tokens = await xeroTokenRequest(env, { grant_type: "authorization_code", code, redirect_uri: redirectUri });
  return tokens;
}

async function xeroRefresh(env, refreshToken) {
  return xeroTokenRequest(env, { grant_type: "refresh_token", refresh_token: refreshToken });
}

async function getXeroConnection(env) {
  const raw = await env.TOKENS.get("provider:xero", "json");
  return raw || null;
}

async function saveXeroConnection(env, conn) {
  await env.TOKENS.put("provider:xero", JSON.stringify(conn));
}

// Ensures a valid (non-expired) access token, refreshing and persisting the
// rotated refresh token if needed. Xero refresh tokens are single-use.
async function ensureXeroAccessToken(env) {
  const conn = await getXeroConnection(env);
  if (!conn) return null;
  if (conn.expiresAt && conn.expiresAt > Date.now() + 60000) return conn;
  const refreshed = await xeroRefresh(env, conn.refreshToken);
  const updated = {
    ...conn,
    accessToken: refreshed.access_token,
    refreshToken: refreshed.refresh_token,
    expiresAt: Date.now() + refreshed.expires_in * 1000,
  };
  await saveXeroConnection(env, updated);
  return updated;
}

async function fetchXeroProfitAndLoss(env, fromDate, toDate) {
  const conn = await ensureXeroAccessToken(env);
  if (!conn) return null;
  const url = new URL("https://api.xero.com/api.xro/2.0/Reports/ProfitAndLoss");
  url.searchParams.set("fromDate", fromDate);
  url.searchParams.set("toDate", toDate);
  const res = await fetch(url.toString(), {
    headers: {
      authorization: `Bearer ${conn.accessToken}`,
      "xero-tenant-id": conn.tenantId,
      accept: "application/json",
    },
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Xero P&L request failed (${res.status}): ${text}`);
  }
  return res.json();
}

// Walks the P&L Rows tree and returns { revenue, cogs, operatingExpensesTotal,
// wageLines: [{label, amount}], overheadLines: [{label, amount}] } for a
// single-period report (one amount column).
function summarizeXeroPnl(report, confirmedWageAccounts) {
  const rows = report?.Reports?.[0]?.Rows || [];
  let revenue = 0;
  let cogs = 0;
  let operatingExpensesTotal = 0;
  const wageLines = [];
  const overheadLines = [];

  function amountOf(cells) {
    const v = cells?.[1]?.Value;
    const n = parseFloat(v);
    return Number.isFinite(n) ? n : 0;
  }

  function isWageAccount(label) {
    if (confirmedWageAccounts && confirmedWageAccounts.length) {
      return confirmedWageAccounts.some((a) => a.toLowerCase() === label.toLowerCase());
    }
    return WAGE_KEYWORD_RE.test(label);
  }

  for (const section of rows) {
    if (section.RowType !== "Section") continue;
    const title = (section.Title || "").toLowerCase();
    const sectionRows = section.Rows || [];

    if (title.includes("income") || title.includes("revenue")) {
      if (title.includes("other income")) continue; // trading income only
      const summary = sectionRows.find((r) => r.RowType === "SummaryRow");
      revenue += summary ? amountOf(summary.Cells) : sectionRows.filter((r) => r.RowType === "Row").reduce((s, r) => s + amountOf(r.Cells), 0);
    } else if (title.includes("cost of sales") || title.includes("cost of goods")) {
      const summary = sectionRows.find((r) => r.RowType === "SummaryRow");
      cogs += summary ? amountOf(summary.Cells) : sectionRows.filter((r) => r.RowType === "Row").reduce((s, r) => s + amountOf(r.Cells), 0);
    } else if (title.includes("operating expenses") || title.includes("expenses")) {
      const summary = sectionRows.find((r) => r.RowType === "SummaryRow");
      operatingExpensesTotal += summary ? amountOf(summary.Cells) : 0;
      for (const row of sectionRows) {
        if (row.RowType !== "Row") continue;
        const label = row.Cells?.[0]?.Value || "";
        const amount = amountOf(row.Cells);
        if (isWageAccount(label)) wageLines.push({ label, amount });
        else overheadLines.push({ label, amount });
      }
    }
  }

  const wagesTotal = wageLines.reduce((s, l) => s + l.amount, 0);
  const overheadsTotal = operatingExpensesTotal - wagesTotal;

  return { revenue, cogs, wagesTotal, overheadsTotal, wageLines, overheadLines, wageAutoDetected: !(confirmedWageAccounts && confirmedWageAccounts.length) };
}

// ---------- Square adapter ----------

async function squareTransactionCount(env, locationIds, fromDate, toDate, timeZone, debugOut) {
  if (!env.SQUARE_API_TOKEN) return null;
  // Square's Orders Search API, filtered to COMPLETED state within the date
  // range (venue timezone), for the resolved location(s) — see
  // resolveSquareLocationIds below for how the location list is picked.
  if (!locationIds || !locationIds.length) return null;

  // fromDate/toDate are venue-local calendar dates (e.g. "2026-07-21" means
  // that whole trading day in the venue's own timezone) — convert their
  // local midnight boundaries to the correct UTC instants rather than
  // treating the date strings as if they were already UTC (see
  // zonedMidnightToUtcIso for why that distinction matters).
  const tz = timeZone || "Australia/Brisbane";
  const startIso = zonedMidnightToUtcIso(fromDate, tz);
  const endIso = zonedMidnightToUtcIso(addDays(toDate, 1), tz);
  if (debugOut) {
    debugOut.fromDate = fromDate;
    debugOut.toDate = toDate;
    debugOut.tz = tz;
    debugOut.startIso = startIso;
    debugOut.endIso = endIso;
    debugOut.locationIds = locationIds;
  }

  const res = await fetch("https://connect.squareup.com/v2/orders/search", {
    method: "POST",
    headers: {
      authorization: `Bearer ${env.SQUARE_API_TOKEN}`,
      "content-type": "application/json",
      "Square-Version": "2026-06-18",
    },
    body: JSON.stringify({
      location_ids: locationIds,
      query: {
        filter: {
          state_filter: { states: ["COMPLETED"] },
          date_time_filter: { closed_at: { start_at: startIso, end_at: endIso } },
        },
      },
      limit: 500,
    }),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Square orders search failed (${res.status}): ${text}`);
  }

  let count = 0;
  let cursor;
  let data = await res.json();
  count += (data.orders || []).length;
  cursor = data.cursor;
  // Paginate if needed.
  let guard = 0;
  while (cursor && guard < 50) {
    guard++;
    const pageRes = await fetch("https://connect.squareup.com/v2/orders/search", {
      method: "POST",
      headers: {
        authorization: `Bearer ${env.SQUARE_API_TOKEN}`,
        "content-type": "application/json",
        "Square-Version": "2026-06-18",
      },
      body: JSON.stringify({
        location_ids: locationIds,
        cursor,
        query: {
          filter: {
            state_filter: { states: ["COMPLETED"] },
            date_time_filter: { closed_at: { start_at: startIso, end_at: endIso } },
          },
        },
        limit: 500,
      }),
    });
    if (!pageRes.ok) break;
    data = await pageRes.json();
    count += (data.orders || []).length;
    cursor = data.cursor;
  }
  return count;
}

async function squareBusinessInfo(env) {
  if (!env.SQUARE_API_TOKEN) return null;
  const res = await fetch("https://connect.squareup.com/v2/locations", {
    headers: { authorization: `Bearer ${env.SQUARE_API_TOKEN}`, "Square-Version": "2026-06-18" },
  });
  if (!res.ok) return { error: `Square locations request failed (${res.status})` };
  const data = await res.json();
  return { locations: (data.locations || []).map((l) => ({ id: l.id, name: l.name, status: l.status })) };
}

// Which Square location(s) count toward the transaction number. The owner
// confirmed (2026-07-21) that ALL locations under this Square account should
// be added together — rather than hardcode a specific list of location ids
// (which would silently go stale if a location is renamed, added, or
// removed), this pulls the live location list every time and includes every
// ACTIVE one. settings.squareLocationIds still acts as an override/pin if a
// future Settings UI lets the owner narrow this down.
async function resolveSquareLocationIds(env, settings) {
  if (settings.squareLocationIds && settings.squareLocationIds.length) return settings.squareLocationIds;
  const info = await squareBusinessInfo(env);
  if (!info || info.error || !info.locations) return null;
  return info.locations.filter((l) => l.status === "ACTIVE").map((l) => l.id);
}

// ---------- metric computation ----------

async function computeMetricsForRange(env, settings, start, end) {
  const [xeroConn, ] = [await getXeroConnection(env)];
  let pnl = null;
  let pnlError = null;
  if (xeroConn) {
    try {
      pnl = await fetchXeroProfitAndLoss(env, start, end);
    } catch (e) {
      pnlError = String(e.message || e);
    }
  }

  let txCount = null;
  let squareError = null;
  let squareLocationIds = null;
  const squareDebug = {};
  if (env.SQUARE_API_TOKEN) {
    try {
      squareLocationIds = await resolveSquareLocationIds(env, settings);
      if (squareLocationIds && squareLocationIds.length) {
        txCount = await squareTransactionCount(env, squareLocationIds, start, end, settings.timezone, squareDebug);
      }
    } catch (e) {
      squareError = String(e.message || e);
    }
  }

  let summary = null;
  const wageAccountsToUse =
    settings.confirmedWageAccounts && settings.confirmedWageAccounts.length
      ? settings.confirmedWageAccounts
      : CONFIRMED_WAGE_ACCOUNTS;
  if (pnl) summary = summarizeXeroPnl(pnl, wageAccountsToUse);

  return {
    summary,
    txCount,
    pnlError,
    squareError,
    squareDebug,
    xeroConfigured: !!xeroConn,
    squareConfigured: !!(env.SQUARE_API_TOKEN && squareLocationIds && squareLocationIds.length),
  };
}

function pctOrNull(part, whole) {
  if (whole === null || whole === undefined || whole === 0) return null;
  return (part / whole) * 100;
}

function buildMetricSet(range, settings) {
  const { summary, txCount, xeroConfigured, squareConfigured } = range;

  const revenue = xeroConfigured && summary ? summary.revenue : null;
  const cogs = xeroConfigured && summary ? summary.cogs : null;
  const wagesTotal = xeroConfigured && summary ? summary.wagesTotal : null;
  const overheads = xeroConfigured && summary ? summary.overheadsTotal : null;
  const transactions = squareConfigured ? txCount : null;

  const acs = revenue !== null && transactions !== null ? (transactions === 0 ? "—" : revenue / transactions) : null;

  const profit =
    revenue !== null && cogs !== null && wagesTotal !== null && overheads !== null
      ? revenue - cogs - wagesTotal - overheads
      : null;

  return {
    revenue: { value: revenue, configured: xeroConfigured, verified: !!settings.verified.revenue },
    transactions: { value: transactions, configured: squareConfigured, verified: !!settings.verified.transactions },
    acs: { value: acs, configured: revenue !== null && transactions !== null, verified: !!settings.verified.revenue && !!settings.verified.transactions },
    cogs: { value: cogs, pct: pctOrNull(cogs, revenue), configured: xeroConfigured, verified: !!settings.verified.cogs },
    wagePct: {
      value: wagesTotal,
      pct: pctOrNull(wagesTotal, revenue),
      configured: xeroConfigured,
      verified: !!settings.verified.wagePct,
      wageAutoDetected: summary?.wageAutoDetected ?? null,
      wageLines: summary?.wageLines ?? null,
    },
    overheads: { value: overheads, pct: pctOrNull(overheads, revenue), configured: xeroConfigured, verified: !!settings.verified.overheads },
    profit: {
      value: profit,
      pct: pctOrNull(profit, revenue),
      configured: revenue !== null && cogs !== null && wagesTotal !== null && overheads !== null,
      verified: !!settings.verified.profit,
    },
  };
}

function pctChange(curr, prev) {
  if (curr === null || prev === null || prev === undefined) return null;
  if (typeof curr !== "number" || typeof prev !== "number") return null;
  if (prev === 0) return null;
  return ((curr - prev) / Math.abs(prev)) * 100;
}

function withComparison(current, compareA, compareB) {
  const out = {};
  for (const key of METRIC_KEYS) {
    const c = current[key];
    const a = compareA?.[key];
    const b = compareB?.[key];
    out[key] = {
      ...c,
      change: {
        previousPeriod: a ? pctChange(typeof c.value === "number" ? c.value : null, typeof a.value === "number" ? a.value : null) : null,
        sameLastYear: b ? pctChange(typeof c.value === "number" ? c.value : null, typeof b.value === "number" ? b.value : null) : null,
      },
    };
  }
  return out;
}

// Builds a short trend series of past buckets of the same kind as `period`
// (weekly buckets for week-shaped periods, monthly for month/FY-shaped ones),
// ending at the period just before the current one, oldest first.
async function computeTrend(env, settings, period, bucketCount = 8) {
  const isWeekly = period.kind === "this_week" || period.kind === "last_week";
  const stepDays = isWeekly ? 7 : null;

  const buckets = [];
  let cursorEnd = addDays(period.start, -1);
  for (let i = 0; i < bucketCount; i++) {
    let bStart, bEnd;
    if (isWeekly) {
      bEnd = cursorEnd;
      bStart = addDays(bEnd, -6);
    } else {
      bEnd = endOfMonth(cursorEnd);
      bStart = startOfMonth(cursorEnd);
    }
    buckets.unshift({ start: bStart, end: bEnd });
    cursorEnd = addDays(bStart, -1);
  }

  const results = await Promise.all(buckets.map((b) => computeMetricsForRange(env, settings, b.start, b.end)));
  return buckets.map((b, i) => ({ start: b.start, end: b.end, metrics: buildMetricSet(results[i], settings) }));
}

// ---------- router ----------

async function handleApi(req, env, url) {
  const path = url.pathname;

  if (path === "/api/status" && req.method === "GET") {
    return json({ setupComplete: await isSetupComplete(env), authenticated: await isAuthenticated(req, env) });
  }

  if (path === "/api/setup" && req.method === "POST") {
    if (await isSetupComplete(env)) return badRequest("Already set up");
    const { password } = await req.json().catch(() => ({}));
    if (!password || password.length < 8) return badRequest("Password must be at least 8 characters");
    await setPassword(env, password);
    const cookie = await makeSessionCookie(env);
    return json({ ok: true }, { headers: { "set-cookie": cookie } });
  }

  if (path === "/api/login" && req.method === "POST") {
    const { password } = await req.json().catch(() => ({}));
    if (!password) return badRequest("Password required");
    const ok = await checkPassword(env, password);
    if (!ok) return unauthorized("Wrong password");
    const cookie = await makeSessionCookie(env);
    return json({ ok: true }, { headers: { "set-cookie": cookie } });
  }

  if (path === "/api/logout" && req.method === "POST") {
    return json({ ok: true }, { headers: { "set-cookie": clearSessionCookie() } });
  }

  // Ingest is authenticated with the owner's upload code, not the session cookie.
  if (path === "/api/ingest" && req.method === "POST") {
    const auth = req.headers.get("authorization") || "";
    const token = auth.replace(/^Bearer\s+/i, "");
    if (!env.INGEST_TOKEN || token !== env.INGEST_TOKEN) return unauthorized("Invalid upload code");
    const body = await req.json().catch(() => null);
    if (!body || !body.source || !body.periodStart || !body.periodEnd || !body.rows) {
      return badRequest("Expected { source, periodStart, periodEnd, rows }");
    }
    const key = `ingest:${body.source}:${body.periodStart}:${body.periodEnd}`;
    await env.TOKENS.put(key, JSON.stringify({ ...body, receivedAt: Date.now() }));
    await env.TOKENS.put(`lastSynced:${body.source}`, String(Date.now()));
    return json({ ok: true });
  }

  // Everything below requires a signed-in session.
  if (!(await isAuthenticated(req, env))) return unauthorized();

  if (path === "/api/settings" && req.method === "GET") {
    return json(await getSettings(env));
  }

  if (path === "/api/settings" && req.method === "POST") {
    const patch = await req.json().catch(() => ({}));
    const current = await getSettings(env);
    const next = { ...current, ...patch, targets: { ...current.targets, ...(patch.targets || {}) } };
    await saveSettings(env, next);
    return json(next);
  }

  if (path === "/api/verify" && req.method === "POST") {
    const { metric } = await req.json().catch(() => ({}));
    if (!METRIC_KEYS.includes(metric)) return badRequest("Unknown metric");
    const settings = await getSettings(env);
    settings.verified[metric] = true;
    await saveSettings(env, settings);
    return json(settings);
  }

  if (path === "/api/connections" && req.method === "GET") {
    const xeroConn = await getXeroConnection(env);
    const squareInfo = env.SQUARE_API_TOKEN ? await squareBusinessInfo(env).catch((e) => ({ error: String(e) })) : null;
    return json({
      xero: xeroConn ? { configured: true, tenantName: xeroConn.tenantName, connectedAt: xeroConn.connectedAt } : { configured: false },
      square: env.SQUARE_API_TOKEN ? { configured: true, ...squareInfo } : { configured: false },
      urhere: { configured: false, fallback: "Xero timesheet export covers actual Wage %; projected Wage % is not configured." },
    });
  }

  if (path === "/api/connect/xero/start" && req.method === "GET") {
    if (!env.XERO_CLIENT_ID) return badRequest("Xero is not set up yet");
    const redirectUri = `${url.origin}/api/connect/xero/callback`;
    const state = b64urlEncode(randomBytes(16));
    await env.TOKENS.put(`xero:state:${state}`, "1", { expirationTtl: 600 });
    const authUrl = new URL(XERO_AUTHORIZE_URL);
    authUrl.searchParams.set("response_type", "code");
    authUrl.searchParams.set("client_id", env.XERO_CLIENT_ID);
    authUrl.searchParams.set("redirect_uri", redirectUri);
    authUrl.searchParams.set("scope", XERO_SCOPES);
    authUrl.searchParams.set("state", state);
    return json({ authUrl: authUrl.toString() });
  }

  if (path === "/api/connect/xero/callback" && req.method === "GET") {
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state");
    if (!code || !state) return badRequest("Missing code or state");
    const seen = await env.TOKENS.get(`xero:state:${state}`);
    if (!seen) return badRequest("This connection link expired — try connecting again.");
    await env.TOKENS.delete(`xero:state:${state}`);

    const redirectUri = `${url.origin}/api/connect/xero/callback`;
    const tokens = await xeroExchangeCode(env, code, redirectUri);

    const connRes = await fetch(XERO_CONNECTIONS_URL, { headers: { authorization: `Bearer ${tokens.access_token}` } });
    const connections = await connRes.json();
    const tenant = connections?.[0];

    await saveXeroConnection(env, {
      accessToken: tokens.access_token,
      refreshToken: tokens.refresh_token,
      expiresAt: Date.now() + tokens.expires_in * 1000,
      tenantId: tenant?.tenantId,
      tenantName: tenant?.tenantName,
      connectedAt: Date.now(),
    });
    await env.TOKENS.put("lastSynced:xero", String(Date.now()));

    return Response.redirect(`${url.origin}/#connections`, 302);
  }

  if (path === "/api/metrics" && req.method === "GET") {
    const settings = await getSettings(env);
    let period;
    try {
      period = resolvePeriod(url.searchParams.get("period") || settings.defaultPeriod, settings, url.searchParams.get("start"), url.searchParams.get("end"));
    } catch (e) {
      return badRequest(String(e.message || e));
    }

    const [current, prev, lastYear] = await Promise.all([
      computeMetricsForRange(env, settings, period.start, period.end),
      computeMetricsForRange(env, settings, period.previousPeriod.start, period.previousPeriod.end),
      computeMetricsForRange(env, settings, period.sameLastYear.start, period.sameLastYear.end),
    ]);

    const metrics = withComparison(buildMetricSet(current, settings), buildMetricSet(prev, settings), buildMetricSet(lastYear, settings));

    const lastSyncedXero = await env.TOKENS.get("lastSynced:xero");
    const lastSyncedSquare = await env.TOKENS.get("lastSynced:square");

    const anyConnected = current.xeroConfigured || current.squareConfigured;
    const unverified = anyConnected && METRIC_KEYS.some((k) => metrics[k].configured && !metrics[k].verified);

    return json({
      period,
      metrics,
      unverified,
      lastSynced: { xero: lastSyncedXero ? Number(lastSyncedXero) : null, square: lastSyncedSquare ? Number(lastSyncedSquare) : null },
      errors: { pnl: current.pnlError || null, square: current.squareError || null },
      _buildTag: "tzfix-2026-07-22-b",
      _debugSquare: { ...current.squareDebug, settingsTimezone: settings.timezone },
    });
  }

  if (path === "/api/trend" && req.method === "GET") {
    const settings = await getSettings(env);
    let period;
    try {
      period = resolvePeriod(url.searchParams.get("period") || settings.defaultPeriod, settings, url.searchParams.get("start"), url.searchParams.get("end"));
    } catch (e) {
      return badRequest(String(e.message || e));
    }
    const trend = await computeTrend(env, settings, period);
    return json({ period, trend });
  }

  return json({ error: "Not found" }, { status: 404 });
}

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (url.pathname.startsWith("/api/")) {
      try {
        return await handleApi(req, env, url);
      } catch (e) {
        return json({ error: String(e.message || e) }, { status: 500 });
      }
    }
    // Static frontend (public/dashboard.html and friends) via Workers Assets.
    return env.ASSETS.fetch(req);
  },
};
