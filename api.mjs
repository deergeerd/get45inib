import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

// ---------- storage ----------
const store = (name) => getStore({ name, consistency: "strong" });
const users = () => store("users"); //  u/<username>
const chats = () => store("chats"); //  c/<chatId>
const index = () => store("chat-index"); //  idx/<username>/<chatId>
const msgs = () => store("messages"); //  msg/<chatId>/<ts>-<rand>

// ---------- helpers ----------
const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
const fail = (status, error) => json({ error }, status);

const USERNAME_RE = /^[a-z0-9_]{3,20}$/;
const SESSION_DAYS = 30;

function secret() {
  const s = process.env.SESSION_SECRET;
  if (!s) throw new Error("SESSION_SECRET env var is not set");
  return s;
}

function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString("base64url");
  const mac = crypto.createHmac("sha256", secret()).update(body).digest("base64url");
  return `${body}.${mac}`;
}

function verify(token) {
  if (!token) return null;
  const [body, mac] = token.split(".");
  if (!body || !mac) return null;
  const expected = crypto.createHmac("sha256", secret()).update(body).digest("base64url");
  const a = Buffer.from(mac);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  try {
    const p = JSON.parse(Buffer.from(body, "base64url").toString());
    return p.exp > Date.now() ? p : null;
  } catch {
    return null;
  }
}

function getCookie(req, name) {
  const header = req.headers.get("cookie") || "";
  for (const part of header.split(";")) {
    const [k, ...v] = part.trim().split("=");
    if (k === name) return v.join("=");
  }
  return null;
}

function sessionCookie(username) {
  const exp = Date.now() + SESSION_DAYS * 86400_000;
  const token = sign({ u: username, exp });
  return `session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${SESSION_DAYS * 86400}`;
}

const clearCookie = "session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto.scryptSync(password, salt, 64).toString("hex");
  return { salt, hash };
}

function checkPassword(password, user) {
  const { hash } = hashPassword(password, user.salt);
  const a = Buffer.from(hash);
  const b = Buffer.from(user.hash);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

const rand = (n = 4) => crypto.randomBytes(n).toString("hex");

async function readBody(req) {
  try {
    return await req.json();
  } catch {
    return {};
  }
}

async function loadChatFor(id, username) {
  const chat = await chats().get(`c/${id}`, { type: "json" });
  if (!chat || !chat.members.includes(username)) return null;
  return chat;
}

async function touchIndex(chat, last, preview) {
  await Promise.all(
    chat.members.map((m) =>
      index().setJSON(`idx/${m}/${chat.id}`, { chatId: chat.id, last, preview })
    )
  );
}

// ---------- routes ----------
async function signup(req) {
  const { username, password } = await readBody(req);
  const name = String(username || "").toLowerCase();
  if (!USERNAME_RE.test(name)) return fail(400, "Username: 3-20 chars, a-z, 0-9, underscore.");
  if (typeof password !== "string" || password.length < 8) return fail(400, "Password must be at least 8 characters.");
  if (await users().get(`u/${name}`)) return fail(409, "That username is taken.");
  const { salt, hash } = hashPassword(password);
  await users().setJSON(`u/${name}`, { username: name, salt, hash, created: Date.now() });
  return json({ username: name }, 200, { "Set-Cookie": sessionCookie(name) });
}

async function login(req) {
  const { username, password } = await readBody(req);
  const name = String(username || "").toLowerCase();
  const user = await users().get(`u/${name}`, { type: "json" });
  if (!user || typeof password !== "string" || !checkPassword(password, user)) {
    return fail(401, "Wrong username or password.");
  }
  return json({ username: name }, 200, { "Set-Cookie": sessionCookie(name) });
}

async function searchUsers(me, url) {
  const q = (url.searchParams.get("q") || "").toLowerCase().replace(/[^a-z0-9_]/g, "");
  if (!q) return json({ users: [] });
  const { blobs } = await users().list({ prefix: `u/${q}` });
  const found = blobs.map((b) => b.key.slice(2)).filter((u) => u !== me).slice(0, 10);
  return json({ users: found });
}

async function listChats(me) {
  const { blobs } = await index().list({ prefix: `idx/${me}/` });
  const rows = await Promise.all(
    blobs.map(async (b) => {
      const idx = await index().get(b.key, { type: "json" });
      const chat = idx && (await chats().get(`c/${idx.chatId}`, { type: "json" }));
      return chat ? { ...chat, last: idx.last, preview: idx.preview } : null;
    })
  );
  const list = rows.filter(Boolean).sort((a, b) => (b.last || 0) - (a.last || 0));
  return json({ chats: list });
}

async function createChat(me, req) {
  const body = await readBody(req);

  if (body.type === "dm") {
    const other = String(body.with || "").toLowerCase();
    if (other === me) return fail(400, "You can't DM yourself.");
    if (!(await users().get(`u/${other}`))) return fail(404, "User not found.");
    const [a, b] = [me, other].sort();
    const id = `dm_${a}__${b}`; // deterministic, so creating twice is harmless
    let chat = await chats().get(`c/${id}`, { type: "json" });
    if (!chat) {
      chat = { id, type: "dm", name: null, members: [a, b], created: Date.now() };
      await chats().setJSON(`c/${id}`, chat);
      await touchIndex(chat, chat.created, "");
    }
    return json({ chat });
  }

  if (body.type === "group") {
    const name = String(body.name || "").trim().slice(0, 50);
    if (!name) return fail(400, "Group needs a name.");
    const wanted = [...new Set((body.members || []).map((m) => String(m).toLowerCase()))].filter((m) => m !== me);
    if (wanted.length < 1) return fail(400, "Add at least one other member.");
    if (wanted.length > 49) return fail(400, "Groups are limited to 50 members.");
    const checks = await Promise.all(wanted.map((m) => users().get(`u/${m}`)));
    const missing = wanted.filter((_, i) => !checks[i]);
    if (missing.length) return fail(404, `Unknown user(s): ${missing.join(", ")}`);
    const id = `g_${rand(8)}`;
    const chat = { id, type: "group", name, members: [me, ...wanted], owner: me, created: Date.now() };
    await chats().setJSON(`c/${id}`, chat);
    await touchIndex(chat, chat.created, "");
    return json({ chat });
  }

  return fail(400, "Unknown chat type.");
}

async function getMessages(me, id, url) {
  const chat = await loadChatFor(id, me);
  if (!chat) return fail(404, "Chat not found.");
  const after = url.searchParams.get("after");
  const { blobs } = await msgs().list({ prefix: `msg/${id}/` });
  let keys = blobs.map((b) => b.key).sort();
  keys = after ? keys.filter((k) => k > after) : keys.slice(-50);
  const rows = await Promise.all(keys.map((k) => msgs().get(k, { type: "json" })));
  const messages = rows.map((m, i) => (m ? { key: keys[i], ...m } : null)).filter(Boolean);
  return json({ messages });
}

async function sendMessage(me, id, req) {
  const chat = await loadChatFor(id, me);
  if (!chat) return fail(404, "Chat not found.");
  const { text } = await readBody(req);
  const clean = String(text || "").trim();
  if (!clean) return fail(400, "Empty message.");
  if (clean.length > 2000) return fail(400, "Message too long (2000 max).");
  const ts = Date.now();
  const key = `msg/${id}/${String(ts).padStart(13, "0")}-${rand(3)}`;
  await msgs().setJSON(key, { from: me, text: clean, ts });
  await touchIndex(chat, ts, `${me}: ${clean.slice(0, 60)}`);
  return json({ ok: true, key });
}

// ---------- entry ----------
export default async (req) => {
  try {
    const url = new URL(req.url);
    const path = url.pathname.replace(/^\/api/, "") || "/";
    const method = req.method;

    if (method === "POST" && path === "/signup") return await signup(req);
    if (method === "POST" && path === "/login") return await login(req);
    if (method === "POST" && path === "/logout") return json({ ok: true }, 200, { "Set-Cookie": clearCookie });

    const session = verify(getCookie(req, "session"));
    if (!session) return fail(401, "Not signed in.");
    const me = session.u;

    if (method === "GET" && path === "/me") return json({ username: me });
    if (method === "GET" && path === "/users") return await searchUsers(me, url);
    if (method === "GET" && path === "/chats") return await listChats(me);
    if (method === "POST" && path === "/chats") return await createChat(me, req);

    const m = path.match(/^\/chats\/([\w-]+)\/messages$/);
    if (m && method === "GET") return await getMessages(me, m[1], url);
    if (m && method === "POST") return await sendMessage(me, m[1], req);

    return fail(404, "Not found.");
  } catch (err) {
    console.error(err);
    return fail(500, err.message || "Server error.");
  }
};

export const config = { path: "/api/*" };
