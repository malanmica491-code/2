// Backend for "กระดานสนทนา นศท." — Netlify Function + Netlify Blobs (no extra database needed)
import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

export const config = { path: "/api/*" };

const DAY = 86400000;
const forum = () => getStore({ name: "forum2", consistency: "strong" });
const creds = () => getStore({ name: "creds2", consistency: "strong" });
const media = () => getStore({ name: "media", consistency: "strong" });

const CORS = { 
  "access-control-allow-origin": "*", 
  "access-control-allow-headers": "authorization, content-type", 
  "access-control-allow-methods": "GET, POST, OPTIONS" 
};

const json = (obj, status = 200) =>
  new Response(JSON.stringify(obj), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...CORS } });
const err = (status, code, message) => json({ error: code, message }, status);

const uid = () => Date.now().toString(36) + crypto.randomBytes(4).toString("hex").slice(0, 5);

/* ---------- state ---------- */
const emptyState = () => ({ users: [], posts: [], reposts: [], reports: [], events: [], notifs: [], trash: [], chats: {}, broadcasts: [], mart: null, site: { maint: null } });
const fillState = (st) => { const e = emptyState(); for (const k of Object.keys(e)) if (st[k] === undefined) st[k] = e[k]; return st; };
const maintActive = (st) => { const m = st.site && st.site.maint; return !!(m && m.on && (!m.reopenAt || m.reopenAt > Date.now())); };

async function readState() {
  const r = await forum().getWithMetadata("state", { type: "json", consistency: "strong" });
  if (!r || !r.data) return { state: emptyState(), etag: null };
  return { state: fillState(r.data), etag: r.etag };
}

async function writeState(state, etag) {
  try {
    const opts = etag ? { onlyIfMatch: etag } : {};
    const res = await forum().setJSON("state", state, opts);
    if (res && res.modified === false) return null;
    if (res && res.etag) return res.etag;
    const meta = await forum().getMetadata("state", { consistency: "strong" });
    return (meta && meta.etag) || "unknown";
  } catch (e) {
    const resBackup = await forum().setJSON("state", state);
    return (resBackup && resBackup.etag) || "unknown";
  }
}

/* ---------- passwords / sessions ---------- */
function hashPw(pw, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(pw, salt, 64).toString("hex");
  return { salt, hash };
}
function checkPw(pw, rec) {
  if (!rec) return false;
  const a = Buffer.from(crypto.scryptSync(pw, rec.salt, 64).toString("hex"));
  const b = Buffer.from(rec.hash);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
async function newSession(userId) {
  const token = crypto.randomBytes(32).toString("hex");
  await creds().setJSON("s/" + token, { uid: userId, at: Date.now() });
  return token;
}
async function authUser(req, state) {
  const h = req.headers.get("authorization") || "";
  const token = h.startsWith("Bearer ") ? h.slice(7) : "";
  if (!/^[0-9a-f]{64}$/.test(token)) return null;
  const s = await creds().get("s/" + token, { type: "json" });
  if (!s) return null;
  const u = state.users.find((x) => x.id === s.uid);
  return u ? { user: u, token } : null;
}

/* ---------- media ---------- */
async function externalizeMedia(val) {
  if (typeof val === "string") {
    const m = /^data:((?:image|video|audio)\/[\w.+-]+);base64,/.exec(val);
    if (m && val.length > 1500) {
      const id = uid() + crypto.randomBytes(3).toString("hex");
      const buf = Buffer.from(val.slice(m[0].length), "base64");
      await media().set(id, buf, { metadata: { type: m[1] } });
      return "/api/media/" + id;
    }
    return val;
  }
  if (Array.isArray(val)) {
    for (let i = 0; i < val.length; i++) val[i] = await externalizeMedia(val[i]);
    return val;
  }
  if (val && typeof val === "object") {
    for (const k of Object.keys(val)) val[k] = await externalizeMedia(val[k]);
  }
  return val;
}

/* ---------- path helpers ---------- */
const isIdObj = (x) => x && typeof x === "object" && !Array.isArray(x) && typeof x.id === "string";
function child(container, seg) {
  if (Array.isArray(container)) return container.find((x) => isIdObj(x) && x.id === seg);
  if (container && typeof container === "object") return Object.prototype.hasOwnProperty.call(container, seg) ? container[seg] : undefined;
  return undefined;
}
const BAD = new Set(["__proto__", "constructor", "prototype"]);

function applyOp(root, op) {
  const p = op.p;
  if (!Array.isArray(p) || !p.length || p.some((s) => typeof s !== "string" || BAD.has(s))) return false;
  let cur = root;
  for (let i = 0; i < p.length - 1; i++) {
    cur = child(cur, p[i]);
    if (cur === undefined || cur === null || typeof cur !== "object") return false;
  }
  const last = p[p.length - 1];
  if (Array.isArray(cur)) {
    const idx = cur.findIndex((x) => isIdObj(x) && x.id === last);
    if (op.x) { if (idx >= 0) cur.splice(idx, 1); return true; }
    if (op.inc !== undefined) return false;
    if (!isIdObj(op.v) || op.v.id !== last) return false;
    if (idx >= 0) cur[idx] = op.v; else cur.push(op.v);
    return true;
  }
  if (op.x) { delete cur[last]; return true; }
  if (op.inc !== undefined) {
    const n = Number(op.inc);
    if (!Number.isFinite(n)) return false;
    const base = typeof cur[last] === "number" ? cur[last] : 0;
    let v = base + n;
    if (last === "stock" && v < 0) v = 0;
    cur[last] = v;
    return true;
  }
  cur[last] = op.v;
  return true;
}

/* ---------- permissions ---------- */
const USER_LOCKED_SELF = new Set(["id", "username", "first", "last", "gender", "year", "birth", "company", "platoon", "role", "banned", "suspendedUntil", "postBlockUntil", "tags", "password", "email", "emailKey", "emailAt"]);
const POST_ADMIN_ONLY = new Set(["announce", "commentsOpen", "allowedReacts"]);

function allowed(op, me, st) {
  const admin = me.role === "admin";
  const p = op.p;
  if (!p || p.length === 0) return false;
  const [a, b, c, ...r] = p;
  if (admin) return a !== "users" || !(p.length === 3 && (c === "id" || c === "password"));
  const blocked = me.postBlockUntil > Date.now();
  const byId = (arr, id) => (arr || []).find((x) => x.id === id);

  const commentRule = (item, rest) => {
    if (!rest.length) return false;
    const cm = byId(item.comments, rest[0]);
    if (rest.length === 1) {
      if (op.x) return !!cm && (cm.userId === me.id || item.userId === me.id);
      if (!cm) return !blocked && op.v && op.v.userId === me.id;
      return cm.userId === me.id;
    }
    if (!cm) return false;
    if (rest[1] === "reacts") return rest.length === 3 && rest[2] === me.id;
    return cm.userId === me.id;
  };

  switch (a) {
    case "users": {
      if (b === me.id) {
        if (!c) return false;
        return !USER_LOCKED_SELF.has(c);
      }
      return c === "reportCount" && r.length === 0 && (op.inc !== undefined || typeof op.v === "number");
    }
    case "posts":
    case "reposts": {
      const item = byId(st[a], b);
      if (!c) {
        if (op.x) return !!item && item.userId === me.id;
        if (!item) {
          if (blocked || !op.v || op.v.userId !== me.id) return false;
          if (a === "posts" && (op.v.announce || op.v.allowedReacts || op.v.commentsOpen === false)) return false;
          return true;
        }
        return item.userId === me.id && !(a === "posts" && op.v && op.v.announce && !item.announce);
      }
      if (!item) return false;
      if (c === "comments") return commentRule(item, r);
      if (c === "reacts") return r.length === 1 && r[0] === me.id;
      if (a === "posts" && POST_ADMIN_ONLY.has(c)) return false;
      return item.userId === me.id;
    }
    case "reports": {
      const item = byId(st.reports, b);
      if (c) return false;
      return !item && !op.x && op.v && op.v.by === me.id;
    }
    case "notifs": {
      const item = byId(st.notifs, b);
      if (c) return !!item && item.userId === me.id;
      if (!item) return !op.x && op.v && st.users.some((u) => u.id === op.v.userId);
      return !!item && item.userId === me.id;
    }
    case "chats": {
      if (!b || !c) return false;
      const room = st.chats[b];
      if (!room) return !op.x && op.v && op.v.senderId === me.id && b.split("-").includes(me.id);
      const msg = room.find(x => x.id === c);
      if (!msg) return !op.x && op.v && op.v.senderId === me.id;
      return msg.senderId === me.id;
    }
    default: return false;
  }
}

/* ---------- MAIN ROUTER ---------- */
export default async (req) => {
  if (req.method === "OPTIONS") return new Response("", { status: 204, headers: CORS });
  
  const url = new URL(req.url);
  const path = url.pathname.replace(/\/$/, "");

  // Media server endpoint
  if (req.method === "GET" && path.startsWith("/api/media/")) {
    const id = path.slice(11);
    const item = await media().get(id, { type: "stream" });
    if (!item) return err(404, "NOT_FOUND", "Media not found");
    const meta = await media().getMetadata(id);
    return new Response(item, { headers: { "content-type": (meta && meta.metadata && meta.metadata.type) || "application/octet-stream", "cache-control": "public, max-age=31536000", ...CORS } });
  }

  // API core logic
  try {
    const { state, etag } = await readState();

    // 1. REGISTER / SIGN UP
    if (req.method === "POST" && path === "/api/register") {
      const { username, password, first, last, gender, year, birth, company, platoon } = await req.json();
      
      if (!username || !password || !first || !last) return err(400, "BAD_REQUEST", "ข้อมูลไม่ครบถ้วน");
      if (state.users.some(u => u.username.toLowerCase() === username.toLowerCase())) {
        return err(400, "USER_EXISTS", "ชื่อผู้ใช้นี้ถูกใช้ไปแล้ว");
      }

      const isFirstUser = state.users.length === 0;
      const myRole = isFirstUser ? "admin" : "user";
      const uId = uid();
      const pwdData = hashPw(password);

const newUser = {
id: uId,
username,
first,
last,
gender: gender || "",
year: year || "",
birth: birth || "",
company: company || "",
platoon: platoon || "",
role: myRole,
banned: false,
suspendedUntil: 0,
postBlockUntil: 0,
reportCount: 0,
tags: isFirstUser ? ["แอดมินระบบ"] : []
};
state.users.push(newUser);
// บันทึกรหัสผ่านลงคลัง creds2
await creds().setJSON("p/" + uId, pwdData);
// บันทึกสถานะหลักกลับไป
const newEtag = await writeState(state, etag);
if (!newEtag) return err(409, "CONFLICT", "ระบบไม่สามารถลงทะเบียนได้ในขณะนี้ กรุณาลองใหม่อีกครั้ง");
const token = await newSession(uId);
return json({ token, user: newUser });
}
// 2. LOGIN
if (req.method === "POST" && path === "/api/login") {
const { username, password } = await req.json();
const u = state.users.find(x => x.username.toLowerCase() === username.toLowerCase());
if (!u) return err(401, "AUTH_FAILED", "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง");
const rec = await creds().get("p/" + u.id, { type: "json" });
if (!rec || !checkPw(password, rec)) return err(401, "AUTH_FAILED", "ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง");
if (u.banned) return err(403, "BANNED", "บัญชีของคุณถูกระงับการใช้งานอย่างถาวร");
const token = await newSession(u.id);
return json({ token, user: u });
}
// 3. GET STATE
if (req.method === "GET" && path === "/api/state") {
const auth = await authUser(req, state);
if (!auth) return err(401, "UNAUTHORIZED", "กรุณาเข้าสู่ระบบ");
if (maintActive(state) && auth.user.role !== "admin") {
return json({ site: state.site, users: state.users.map(x => ({ id: x.id, username: x.username, role: x.role })) });
}
return json({ state, me: auth.user });
}
// 4. MUTATE / UPDATE STATE
if (req.method === "POST" && path === "/api/mutate") {
const auth = await authUser(req, state);
if (!auth) return err(401, "UNAUTHORIZED", "กรุณาเข้าสู่ระบบ");
if (auth.user.banned || auth.user.suspendedUntil > Date.now()) return err(403, "FORBIDDEN", "คุณถูกระงับการใช้งานชั่วคราว");
if (maintActive(state) && auth.user.role !== "admin") return err(503, "MAINTENANCE", "ระบบกำลังปิดปรับปรุง");
let { ops } = await req.json();
if (!Array.isArray(ops)) return err(400, "BAD_REQUEST", "รูปแบบคำสั่งไม่ถูกต้อง");
ops = await externalizeMedia(ops);
for (const op of ops) {
if (!allowed(op, auth.user, state)) return err(403, "UNAUTHORIZED_OP", "คุณไม่มีสิทธิ์ทำรายการนี้");
const ok = applyOp(state, op);
if (!ok) return err(400, "BAD_OP", "คำสั่งทำงานไม่สำเร็จ");
}
const newEtag = await writeState(state, etag);
if (!newEtag) return err(409, "CONFLICT", "ข้อมูลมีการเปลี่ยนแปลงจากที่อื่น กรุณาดึงข้อมูลใหม่");
return json({ state, etag: newEtag });
}
return err(404, "NOT_FOUND", "ไม่พบหน้า API ที่เรียก");
} catch (e) {
return err(500, "SERVER_ERROR", e.message || "เกิดข้อผิดพลาดภายในระบบหลังบ้าน");
}
};
