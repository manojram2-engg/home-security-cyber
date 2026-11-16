#!/usr/bin/env node
"use strict";
// Home Lab Attack Surface Snapshot: real backend. Zero dependencies (Node >= 18).
// Runs nmap + searchsploit on PRIVATE ranges only, streams progress over SSE, stores history in ./data.
const http = require("http"), fs = require("fs"), path = require("path"), crypto = require("crypto");
const { spawn, execFile } = require("child_process");
const PORT = +process.env.PORT || 3000, HOST = process.env.HOST || "127.0.0.1";
const DATA = path.join(__dirname, "data"), PUB = path.join(__dirname, "public");
fs.mkdirSync(DATA, { recursive: true });
const live = new Map(); let active = null;
const PROFILES = { quick: ["-F", "-sV", "--version-light", "-T4"], standard: ["-sV", "-T4"], discovery: ["-sn", "-T4"] };

// ---------- safety: only private IPv4 targets, max /22, fixed argument lists, no shell ----------
function parseTarget(t) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})(?:\/(\d{1,2}))?$/.exec(String(t || "").trim());
  if (!m) return null;
  const o = m.slice(1, 5).map(Number), bits = m[5] === undefined ? 32 : +m[5];
  if (o.some(n => n > 255) || bits > 32 || bits < 22) return null;
  const priv = o[0] === 10 || (o[0] === 172 && o[1] >= 16 && o[1] <= 31) || (o[0] === 192 && o[1] === 168) || o[0] === 127;
  return priv ? String(t).trim() : null;
}
// ---------- tool helpers ----------
function probe(cmd, args) {
  return new Promise(res => execFile(cmd, args, { timeout: 5000 }, (err, out) => {
    if (err && err.code === "ENOENT") return res(null);
    res((String(out || "").split("\n")[0] || "installed").trim().slice(0, 60));
  }));
}
function run(cmd, args, onLine, timeoutMs) {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"], shell: false });
    let out = "", buf = "";
    const t = setTimeout(() => { p.kill("SIGKILL"); reject(new Error(cmd + " timed out")); }, timeoutMs);
    p.stdout.on("data", d => { if (out.length < 5e6) out += d; if (onLine) { buf += d; let i; while ((i = buf.indexOf("\n")) > -1) { const l = buf.slice(0, i).trim(); buf = buf.slice(i + 1); if (l) onLine(l); } } });
    p.on("error", e => { clearTimeout(t); reject(e.code === "ENOENT" ? new Error(cmd + " is not installed") : e); });
    p.on("close", code => { clearTimeout(t); code === 0 || out ? resolve(out) : reject(new Error(cmd + " exited with code " + code)); });
  });
}
const unesc = s => String(s).replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, "&");
function parseNmap(xml) {
  const hosts = [], svcs = [];
  for (const hm of xml.matchAll(/<host\b[\s\S]*?<\/host>/g)) {
    const h = hm[0]; if (/<status[^>]*state="down"/.test(h)) continue;
    const ip = (/<address addr="([^"]+)" addrtype="ipv4"/.exec(h) || [])[1]; if (!ip) continue;
    const name = unesc((/<hostname name="([^"]*)"/.exec(h) || [])[1] || ip); let open = 0;
    for (const pm of h.matchAll(/<port\b[^>]*portid="(\d+)"[^>]*>([\s\S]*?)<\/port>/g)) {
      if (!/<state state="open"/.test(pm[2])) continue; open++;
      const sv = (/<service\b([^>]*?)\/?>/.exec(pm[2]) || [, ""])[1], g = k => { const r = new RegExp("(?:^|\\s)" + k + '="([^"]*)"').exec(sv); return r ? unesc(r[1]) : ""; };
      svcs.push({ ip, port: pm[1], name: g("name"), product: g("product"), version: g("version") });
    }
    hosts.push({ id: "h" + hosts.length, ip, name, open });
  }
  return { hosts, svcs };
}
// ---------- vulnerability mapping ----------
const DEMO_DB = { "vsftpd 2.3.4": ["vsftpd 2.3.4 - Backdoor Command Execution"], "samba smbd 3.0.20": ["Samba 3.0.20 - 'Username' map script Command Execution"], "openssh 4.7p1": ["OpenSSH < 7.7 - User Enumeration"], "openssh 7.2p2": ["OpenSSH < 7.7 - User Enumeration"], "apache httpd 2.2.8": ["Apache 2.2.x - Denial of Service", "Apache 2.2.8 - Information Disclosure"], "apache httpd 2.4.18": ["Apache 2.4.x - Local Privilege Escalation"] };
async function search(q, demo) {
  if (demo) return (DEMO_DB[q.toLowerCase()] || []).map(t => ({ title: "[demo] " + t, id: "demo" }));
  const out = await run("searchsploit", ["--json", q], null, 30000);
  try { return (JSON.parse(out).RESULTS_EXPLOIT || []).map(e => ({ title: e.Title, id: e["EDB-ID"] })); } catch (e) { return []; }
}
function grade(title) {
  if (/remote code|command exec|backdoor|\brce\b|overflow/i.test(title)) return ["Critical", "CIA"];
  if (/privilege|escalation|traversal|injection|bypass/i.test(title)) return ["High", "CI"];
  if (/denial|\bdos\b/i.test(title)) return ["High", "A"];
  return ["Medium", "C"];
}
const RK = { Critical: 3, High: 2, Medium: 1 };
async function analyse(parsed, demo, say) {
  const F = [], groups = new Map();
  for (const s of parsed.svcs) {
    const base = (s.product || s.name) + (s.version ? " " + s.version : "");
    const k = s.ip + "|" + base; if (!groups.has(k)) groups.set(k, { ip: s.ip, base, q: s.product && s.version ? base : "", name: s.name, ports: [] });
    groups.get(k).ports.push(s.port);
  }
  const idOf = {}; parsed.hosts.forEach(h => idOf[h.ip] = h.id);
  const cache = new Map(); let i = 0;
  for (const g of groups.values()) {
    say("phase", "Matching " + g.base + " (" + (++i) + "/" + groups.size + ")");
    const svc = g.base + " (" + g.ports.join("/") + ")";
    if (g.q) {
      if (!cache.has(g.q)) cache.set(g.q, await search(g.q, demo));
      const hits = cache.get(g.q);
      if (hits.length) {
        const best = hits.map(h => ({ h, r: grade(h.title) })).sort((a, b) => RK[b.r[0]] - RK[a.r[0]])[0];
        F.push({ h: idOf[g.ip], ip: g.ip, svc, sev: best.r[0], cia: best.r[1], issue: best.h.title + (hits.length > 1 ? " (+" + (hits.length - 1) + " more public exploits)" : ""), ref: best.h.id === "demo" ? "dummy data" : "EDB-ID " + best.h.id, fix: "Upgrade " + (g.base.split(" ")[0]) + " to a supported, patched release and restrict access with a firewall." });
      }
    }
    if (g.name === "telnet") F.push({ h: idOf[g.ip], ip: g.ip, svc, sev: "High", cia: "C", issue: "Telnet sends credentials in cleartext", ref: "Cleartext protocol", fix: "Disable telnet and use SSH." });
    if (g.name === "ftp") F.push({ h: idOf[g.ip], ip: g.ip, svc, sev: "Medium", cia: "C", issue: "FTP sends credentials in cleartext", ref: "Cleartext protocol", fix: "Replace FTP with SFTP or FTPS." });
  }
  F.sort((a, b) => RK[b.sev] - RK[a.sev] || (a.ip < b.ip ? -1 : 1));
  return { hosts: parsed.hosts, F };
}
// ---------- scan lifecycle ----------
const wait = ms => new Promise(r => setTimeout(r, ms));
function emit(s, m) { s.log.push(m); for (const r of s.subs) r.write("data: " + JSON.stringify(m) + "\n\n"); }
const save = s => fs.writeFileSync(path.join(DATA, s.meta.id + ".json"), JSON.stringify(s.meta));
async function execute(s) {
  const say = (type, text) => emit(s, { type, text });
  try {
    let xml;
    if (s.meta.demo) { say("phase", "Demo mode: using dummy data, nothing is scanned"); await wait(300); xml = fs.readFileSync(path.join(__dirname, "sample-scan.xml"), "utf8"); say("log", "Loaded dummy scan"); }
    else {
      const xmlPath = path.join(DATA, s.meta.id + ".xml");
      say("phase", "Scanning " + s.meta.target + " with nmap (" + s.meta.profile + ")");
      await run("nmap", [...PROFILES[s.meta.profile], "--stats-every", "3s", "-oX", xmlPath, s.meta.target], l => say("log", l), 15 * 60 * 1000);
      xml = fs.readFileSync(xmlPath, "utf8");
    }
    const parsed = parseNmap(xml);
    if (!parsed.hosts.length) throw new Error("No live hosts were found on that target.");
    s.meta.result = await analyse(parsed, s.meta.demo, say);
    s.meta.status = "done"; save(s); say("done", "Complete");
  } catch (e) { s.meta.status = "error"; s.meta.error = e.message; save(s); say("error", e.message); }
  active = null; for (const r of s.subs) r.end(); s.subs.clear(); setTimeout(() => live.delete(s.meta.id), 600000);
}
// ---------- http ----------
const TYPES = { ".html": "text/html; charset=utf-8", ".js": "text/javascript", ".css": "text/css", ".xml": "application/xml", ".svg": "image/svg+xml" };
const CSP = "default-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; worker-src blob:; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'";
function send(res, code, obj) { res.writeHead(code, { "Content-Type": "application/json", "Cache-Control": "no-store" }); res.end(JSON.stringify(obj)); }
function body(req) { return new Promise((ok, no) => { let b = ""; req.on("data", d => { b += d; if (b.length > 4096) { no(new Error("Body too large")); req.destroy(); } }); req.on("end", () => { try { ok(JSON.parse(b || "{}")); } catch (e) { no(new Error("Invalid JSON")); } }); }); }
const readMeta = id => { try { return JSON.parse(fs.readFileSync(path.join(DATA, id + ".json"), "utf8")); } catch (e) { return null; } };
const server = http.createServer(async (req, res) => {
  res.setHeader("X-Content-Type-Options", "nosniff"); res.setHeader("Content-Security-Policy", CSP); res.setHeader("Referrer-Policy", "no-referrer");
  const url = new URL(req.url, "http://x"), p = url.pathname;
  try {
    if (p.startsWith("/api/")) {
      if (req.method !== "GET") {
        if (req.headers["x-requested-with"] !== "ass") return send(res, 403, { error: "Missing X-Requested-With header." });
        if (req.headers.origin && req.headers.origin !== "http://" + req.headers.host) return send(res, 403, { error: "Cross-origin request blocked." });
      }
      if (p === "/api/status") return send(res, 200, { nmap: await probe("nmap", ["--version"]), searchsploit: await probe("searchsploit", ["-h"]), busy: !!active, profiles: Object.keys(PROFILES) });
      if (p === "/api/scans" && req.method === "GET") return send(res, 200, fs.readdirSync(DATA).filter(f => /^[a-f0-9]{12}\.json$/.test(f)).map(f => readMeta(f.slice(0, -5))).filter(Boolean).map(m => ({ id: m.id, target: m.target, profile: m.profile, demo: m.demo, created: m.created, status: m.status, findings: m.result ? m.result.F.length : 0 })).sort((a, b) => b.created - a.created).slice(0, 20));
      if (p === "/api/scans" && req.method === "POST") {
        const b = await body(req);
        if (b.authorized !== true) return send(res, 400, { error: "Confirm you own this network or have written permission." });
        if (active) return send(res, 409, { error: "A scan is already running." });
        const demo = b.demo === true, profile = PROFILES[b.profile] ? b.profile : "quick";
        const target = demo ? "demo" : parseTarget(b.target);
        if (!target) return send(res, 400, { error: "Target must be a private IPv4 address or CIDR (10.x, 172.16-31.x, 192.168.x, 127.x), no larger than /22." });
        if (!demo && !(await probe("nmap", ["--version"]))) return send(res, 400, { error: "nmap is not installed on the server. Install it, or use demo mode." });
        if (!demo && profile !== "discovery" && !(await probe("searchsploit", ["-h"]))) return send(res, 400, { error: "searchsploit is not installed (sudo apt install exploitdb). Use the discovery profile or demo mode." });
        const s = { meta: { id: crypto.randomBytes(6).toString("hex"), target, profile, demo, created: Date.now(), status: "running" }, log: [], subs: new Set() };
        live.set(s.meta.id, s); active = s; save(s); execute(s);
        return send(res, 202, { id: s.meta.id });
      }
      let m = /^\/api\/scans\/([a-f0-9]{12})(\/events)?$/.exec(p);
      if (m) {
        const id = m[1], s = live.get(id);
        if (m[2]) {
          res.writeHead(200, { "Content-Type": "text/event-stream", "Cache-Control": "no-store", Connection: "keep-alive" });
          if (s) { s.log.forEach(e => res.write("data: " + JSON.stringify(e) + "\n\n")); if (s.meta.status === "running") { s.subs.add(res); req.on("close", () => s.subs.delete(res)); return; } return res.end(); }
          const d = readMeta(id); res.write("data: " + JSON.stringify(d && d.status === "done" ? { type: "done", text: "Complete" } : { type: "error", text: d ? d.error || "Scan failed" : "Not found" }) + "\n\n"); return res.end();
        }
        if (req.method === "DELETE") { if (s && s.meta.status === "running") return send(res, 409, { error: "Scan still running." }); for (const e of [".json", ".xml"]) try { fs.unlinkSync(path.join(DATA, id + e)); } catch (x) {} live.delete(id); return send(res, 200, { ok: true }); }
        const d = readMeta(id); return d ? send(res, 200, d) : send(res, 404, { error: "Scan not found." });
      }
      return send(res, 404, { error: "Unknown endpoint." });
    }
    // static files, confined to ./public
    const f = path.normalize(path.join(PUB, p === "/" ? "index.html" : p));
    if (!f.startsWith(PUB + path.sep) || !fs.existsSync(f) || !fs.statSync(f).isFile()) { res.writeHead(404); return res.end("Not found"); }
    res.writeHead(200, { "Content-Type": TYPES[path.extname(f)] || "application/octet-stream" }); fs.createReadStream(f).pipe(res);
  } catch (e) { send(res, 400, { error: e.message }); }
});
if (require.main === module) server.listen(PORT, HOST, () => console.log("Attack Surface Snapshot running at http://" + HOST + ":" + PORT));
module.exports = { server, parseTarget, parseNmap };
