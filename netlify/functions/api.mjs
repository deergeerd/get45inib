import { getStore } from "@netlify/blobs";
import crypto from "node:crypto";

// ---------- storage ----------
const store = (name) => getStore({ name, consistency: "strong" });
const users = () => store("users"); //  u/<username>
const chats = () => store("chats"); //  c/<chatId>
const index = () => store("chat-index"); //  idx/<username>/<chatId>
const msgs = () => store("messages"); //  msg/<chatId>/<ts>-<rand>
const rl = () => store("ratelimit"); //  login/u/<hash>, login/ip/<hash>, signup/ip/<hash>
const typingStore = () => store("typing"); //  t/<chatId> -> { username: lastPingMs }
const TYPING_TTL = 6000; // a typer is shown for this long after their last ping (clients ping every ~2.5s)

// ---------- helpers ----------
const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "Content-Type": "application/json", "Cache-Control": "no-store", ...headers },
  });
const fail = (status, error) => json({ error }, status);

const USERNAME_RE = /^[a-z0-9_]{3,20}$/;
const SESSION_DAYS = 30;

// ---------- rate limiting ----------
const MIN = 60_000;
const LOGIN_USER_MAX = 5; //  failed logins per username before it locks
const LOGIN_IP_MAX = 20; //   failed logins per IP before it locks (covers guessing across many usernames)
const LOGIN_WINDOW = 15 * MIN; // failures older than this are forgotten; also the lock duration
const SIGNUP_IP_MAX = 10; //  signups per IP per hour
const SIGNUP_WINDOW = 60 * MIN;

const sha = (s) => crypto.createHash("sha256").update(s).digest("hex").slice(0, 32);

// Hashed so we never store raw IPs. Returns null when the IP is unknown (e.g. local dev).
function clientKey(req, kind) {
  const ip =
    req.headers.get("x-nf-client-connection-ip") ||
    (req.headers.get("x-forwarded-for") || "").split(",")[0].trim();
  return ip ? `${kind}/ip/${sha(ip)}` : null;
}

// Seconds left on the lock for this key (0 = not locked).
async function lockedFor(key) {
  const rec = await rl().get(key, { type: "json" });
  return rec && rec.lockedUntil > Date.now() ? Math.ceil((rec.lockedUntil - Date.now()) / 1000) : 0;
}

// Record one event. If `max` events happen within `window`, lock the key for `lockMs`.
// Returns true if the key is locked afterwards.
async function recordHit(key, max, window, lockMs) {
  const now = Date.now();
  const rec = (await rl().get(key, { type: "json" })) || { hits: [], lockedUntil: 0 };
  rec.hits = rec.hits.filter((t) => now - t < window);
  rec.hits.push(now);
  if (rec.hits.length >= max) {
    rec.lockedUntil = now + lockMs;
    rec.hits = [];
  }
  await rl().setJSON(key, rec);
  return rec.lockedUntil > now;
}

function tooMany(seconds) {
  const mins = Math.max(1, Math.ceil(seconds / 60));
  return json(
    { error: `Too many attempts. Try again in ${mins} minute${mins === 1 ? "" : "s"}.` },
    429,
    { "Retry-After": String(seconds) }
  );
}

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

// Each member has one index entry per chat: { chatId, last, preview, unread, readTs }.
// `fn(member, current)` returns the member's new entry. Version is bumped after the writes.
async function updateIndex(chat, fn) {
  await Promise.all(
    chat.members.map(async (m) => {
      const key = `idx/${m}/${chat.id}`;
      const cur = (await index().get(key, { type: "json" })) || { chatId: chat.id, last: 0, preview: "", unread: 0, readTs: 0 };
      await index().setJSON(key, fn(m, cur));
    })
  );
  await bumpVersion(chat.members);
}

// New activity in a chat. If `from` is set, everyone except the sender gets +1 unread.
// The sender's own count is deliberately left alone: a message from someone else may have
// landed just before they hit send, and only the client knows what was actually displayed.
// The sender's client clears it via /read right after its next sync.
async function touchIndex(chat, last, preview, from = null) {
  await updateIndex(chat, (m, cur) => {
    if (!from || m === from) return { ...cur, last, preview };
    return { ...cur, last, preview, unread: (cur.unread || 0) + 1 };
  });
}

// Bump each member's version only AFTER the data is written, so a client that
// sees the new version is guaranteed to find the new data.
async function bumpVersion(members) {
  const v = `${Date.now()}-${rand(2)}`; // unique per change; clients only compare for equality
  await Promise.all(members.map((m) => index().setJSON(`ver/${m}`, v)));
}

// ---------- routes ----------
async function signup(req) {
  const ikey = clientKey(req, "signup");
  if (ikey) {
    const wait = await lockedFor(ikey);
    if (wait) return tooMany(wait);
    await recordHit(ikey, SIGNUP_IP_MAX, SIGNUP_WINDOW, SIGNUP_WINDOW);
  }
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
  // Keyed by what was typed, whether or not the account exists, so attackers learn nothing.
  const ukey = `login/u/${sha(name)}`;
  const ikey = clientKey(req, "login");

  // Check locks BEFORE touching the password: a locked account rejects even the right password,
  // and we skip the expensive hash.
  const wait = Math.max(await lockedFor(ukey), ikey ? await lockedFor(ikey) : 0);
  if (wait) return tooMany(wait);

  const user = await users().get(`u/${name}`, { type: "json" });
  if (!user || typeof password !== "string" || !checkPassword(password, user)) {
    const userLocked = await recordHit(ukey, LOGIN_USER_MAX, LOGIN_WINDOW, LOGIN_WINDOW);
    const ipLocked = ikey ? await recordHit(ikey, LOGIN_IP_MAX, LOGIN_WINDOW, LOGIN_WINDOW) : false;
    if (userLocked || ipLocked) return tooMany(Math.ceil(LOGIN_WINDOW / 1000));
    return fail(401, "Wrong username or password.");
  }
  await rl().delete(ukey); // success clears this username's failures (the IP's count is kept on purpose)
  return json({ username: name }, 200, { "Set-Cookie": sessionCookie(name) });
}

async function searchUsers(me, url) {
  const q = (url.searchParams.get("q") || "").toLowerCase().replace(/[^a-z0-9_]/g, "");
  if (!q) return json({ users: [] });
  const { blobs } = await users().list({ prefix: `u/${q}` });
  const found = blobs.map((b) => b.key.slice(2)).filter((u) => u !== me).slice(0, 10);
  return json({ users: found });
}

async function chatsFor(me) {
  const { blobs } = await index().list({ prefix: `idx/${me}/` });
  const rows = await Promise.all(
    blobs.map(async (b) => {
      const idx = await index().get(b.key, { type: "json" });
      const chat = idx && (await chats().get(`c/${idx.chatId}`, { type: "json" }));
      // Re-check membership: a stale index entry must never expose a chat someone was removed from.
      return chat && chat.members.includes(me)
        ? { ...chat, last: idx.last, preview: idx.preview, unread: idx.unread || 0 }
        : null;
    })
  );
  return rows.filter(Boolean).sort((a, b) => (b.last || 0) - (a.last || 0));
}

async function listChats(me) {
  return json({ chats: await chatsFor(me) });
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

async function messagesFor(me, id, after) {
  const chat = await loadChatFor(id, me);
  if (!chat) return null;
  const { blobs } = await msgs().list({ prefix: `msg/${id}/` });
  let keys = blobs.map((b) => b.key).sort();
  keys = after ? keys.filter((k) => k > after) : keys.slice(-50);
  const rows = await Promise.all(keys.map((k) => msgs().get(k, { type: "json" })));
  return rows.map((m, i) => (m ? { key: keys[i], ...m } : null)).filter(Boolean);
}

async function getMessages(me, id, url) {
  const messages = await messagesFor(me, id, url.searchParams.get("after"));
  return messages ? json({ messages }) : fail(404, "Chat not found.");
}

// One cheap endpoint for the client to poll. If the user's version hasn't changed
// it answers 204 with no body, after a single blob read.
async function sync(me, url) {
  const clientV = url.searchParams.get("v") || "";
  const clientT = url.searchParams.get("t") || ""; // typers the client is currently showing
  const rawChat = url.searchParams.get("chat");
  const chatId = rawChat && /^[\w-]+$/.test(rawChat) ? rawChat : null;
  // Read the version BEFORE the data: if something changes mid-read, the next poll sees a newer version.
  const v = (await index().get(`ver/${me}`, { type: "json" })) || "0";
  // Who is typing in the open chat (null if it isn't a chat I'm in). Typing never touches versions.
  const typing = chatId ? await typersFor(me, chatId) : null;
  const sig = typing ? typing.join(",") : "";
  const versionSame = clientV && clientV === v;
  if (versionSame && sig === clientT) {
    return new Response(null, { status: 204, headers: { "Cache-Control": "no-store" } });
  }
  // Only the typing state changed: a tiny reply without the chat list or messages.
  if (versionSame) return json({ v, typing: typing || [] });
  const out = { v, chats: await chatsFor(me) };
  if (typing) out.typing = typing;
  if (chatId) {
    const messages = await messagesFor(me, chatId, url.searchParams.get("after"));
    if (messages) {
      out.messages = messages;
      const { blobs } = await msgs().list({ prefix: `del/${chatId}/` });
      out.deleted = blobs.map((b) => b.key.split("/").pop()).sort().slice(-100);
    }
  }
  return json(out);
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
  await clearTyping(me, id);
  await touchIndex(chat, ts, `${me}: ${clean.slice(0, 60)}`, me);
  return json({ ok: true, key });
}

async function deleteMessage(me, id, suffix) {
  const chat = await loadChatFor(id, me);
  if (!chat) return fail(404, "Chat not found.");
  const key = `msg/${id}/${suffix}`;
  const msg = await msgs().get(key, { type: "json" });
  if (!msg) return fail(404, "Message not found.");
  if (msg.system) return fail(403, "Notices can't be deleted.");
  if (msg.from !== me) return fail(403, "You can only delete your own messages.");
  if (!msg.deleted) {
    // Erase the text for real; keep a tombstone so message order and keys stay stable.
    await msgs().setJSON(key, { from: msg.from, ts: msg.ts, deleted: true });
    // Marker that lets clients who already showed the message learn it was deleted.
    await msgs().setJSON(`del/${id}/${suffix}`, true);
    const { blobs } = await msgs().list({ prefix: `msg/${id}/` });
    const latest = blobs.map((b) => b.key).sort().pop();
    const isLatest = latest === key;
    await updateIndex(chat, (m, cur) => {
      let unread = cur.unread || 0;
      // If this recipient hadn't read it yet, it no longer counts as unread.
      if (m !== me && msg.ts > (cur.readTs || 0) && unread > 0) unread--;
      return { ...cur, unread, ...(isLatest ? { preview: `${me} deleted a message` } : {}) };
    });
  }
  return json({ ok: true });
}

// The client reports "I have seen everything up to timestamp upTo".
async function markRead(me, id, req) {
  const chat = await loadChatFor(id, me);
  if (!chat) return fail(404, "Chat not found.");
  const t = Number((await readBody(req)).upTo);
  if (!Number.isFinite(t) || t <= 0) return fail(400, "Bad timestamp.");
  const key = `idx/${me}/${id}`;
  const cur = await index().get(key, { type: "json" });
  if (!cur) return json({ ok: true });
  const readTs = Math.max(cur.readTs || 0, t);
  // Only clear the badge if nothing newer than what the client saw has arrived meanwhile.
  const unread = t >= (cur.last || 0) ? 0 : cur.unread || 0;
  if (readTs !== (cur.readTs || 0) || unread !== (cur.unread || 0)) {
    await index().setJSON(key, { ...cur, readTs, unread });
    await bumpVersion([me]); // only my other tabs/devices need to know
  }
  return json({ ok: true });
}

// ---------- typing indicator ----------
async function typersFor(me, id) {
  const chat = await loadChatFor(id, me);
  if (!chat) return null;
  const cur = (await typingStore().get(`t/${id}`, { type: "json" })) || {};
  const now = Date.now();
  return Object.entries(cur)
    .filter(([u, t]) => u !== me && chat.members.includes(u) && now - t < TYPING_TTL)
    .map(([u]) => u)
    .sort();
}

async function setTyping(me, id, req) {
  const chat = await loadChatFor(id, me);
  if (!chat) return fail(404, "Chat not found.");
  const { typing } = await readBody(req);
  const now = Date.now();
  const cur = (await typingStore().get(`t/${id}`, { type: "json" })) || {};
  for (const [u, t] of Object.entries(cur)) if (now - t > 10_000) delete cur[u]; // tidy old entries
  if (typing === false) delete cur[me];
  else cur[me] = now;
  await typingStore().setJSON(`t/${id}`, cur);
  return json({ ok: true });
}

// Sending a message ends "typing" immediately, so the indicator vanishes together with the new message.
async function clearTyping(me, id) {
  const cur = await typingStore().get(`t/${id}`, { type: "json" });
  if (cur && cur[me]) {
    delete cur[me];
    await typingStore().setJSON(`t/${id}`, cur);
  }
}

// ---------- group membership ----------
const MAX_GROUP = 50;

// A centered notice in the conversation ("alice added dave"). Doesn't count as unread.
async function postSystem(chat, actor, text) {
  const ts = Date.now();
  const key = `msg/${chat.id}/${String(ts).padStart(13, "0")}-${rand(3)}`;
  await msgs().setJSON(key, { from: actor, text, ts, system: true });
  await touchIndex(chat, ts, text);
}

// Any member can add people.
async function addMembers(me, id, req) {
  const chat = await loadChatFor(id, me);
  if (!chat) return fail(404, "Chat not found.");
  if (chat.type !== "group") return fail(400, "Only groups can have people added.");
  const { add } = await readBody(req);
  const wanted = [...new Set((Array.isArray(add) ? add : []).map((u) => String(u).toLowerCase()))]
    .filter((u) => USERNAME_RE.test(u) && !chat.members.includes(u));
  if (!wanted.length) return fail(400, "Nobody new to add.");
  if (chat.members.length + wanted.length > MAX_GROUP) return fail(400, `Groups are limited to ${MAX_GROUP} members.`);
  const found = await Promise.all(wanted.map((u) => users().get(`u/${u}`)));
  const missing = wanted.filter((_, i) => !found[i]);
  if (missing.length) return fail(404, `Unknown user(s): ${missing.join(", ")}`);

  chat.members = [...chat.members, ...wanted];
  await chats().setJSON(`c/${id}`, chat);
  await postSystem(chat, me, `${me} added ${wanted.join(", ")}`); // also creates the new members' index entries
  return json({ chat });
}

// Leave (target === me) or, for the owner, remove someone else.
async function removeMember(me, id, target) {
  const chat = await loadChatFor(id, me);
  if (!chat) return fail(404, "Chat not found.");
  if (chat.type !== "group") return fail(400, "You can't leave a direct message.");
  if (!chat.members.includes(target)) return fail(404, "That person isn't in this group.");
  const leaving = target === me;
  if (!leaving && chat.owner !== me) return fail(403, "Only the group owner can remove people.");

  chat.members = chat.members.filter((m) => m !== target);

  if (!chat.members.length) {
    // Last person left: delete the group and its messages.
    await chats().delete(`c/${id}`);
    await typingStore().delete(`t/${id}`);
    await index().delete(`idx/${target}/${id}`);
    const keys = [
      ...(await msgs().list({ prefix: `msg/${id}/` })).blobs,
      ...(await msgs().list({ prefix: `del/${id}/` })).blobs,
    ].map((b) => b.key);
    for (let i = 0; i < keys.length; i += 25) await Promise.all(keys.slice(i, i + 25).map((k) => msgs().delete(k)));
    await bumpVersion([target]);
    return json({ ok: true, gone: true });
  }

  if (chat.owner === target) chat.owner = chat.members[0]; // oldest remaining member
  await chats().setJSON(`c/${id}`, chat); // access is revoked from this write on
  await index().delete(`idx/${target}/${id}`);
  await bumpVersion([target]); // so their client notices straight away
  await postSystem(chat, me, leaving ? `${me} left` : `${me} removed ${target}`);
  return json({ ok: true, chat });
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

    if (method === "GET" && path === "/sync") return await sync(me, url);
    if (method === "GET" && path === "/me") return json({ username: me });
    if (method === "GET" && path === "/users") return await searchUsers(me, url);
    if (method === "GET" && path === "/chats") return await listChats(me);
    if (method === "POST" && path === "/chats") return await createChat(me, req);

    const m = path.match(/^\/chats\/([\w-]+)\/messages$/);
    if (m && method === "GET") return await getMessages(me, m[1], url);
    if (m && method === "POST") return await sendMessage(me, m[1], req);

    const ty = path.match(/^\/chats\/([\w-]+)\/typing$/);
    if (ty && method === "POST") return await setTyping(me, ty[1], req);

    const mb = path.match(/^\/chats\/([\w-]+)\/members$/);
    if (mb && method === "POST") return await addMembers(me, mb[1], req);
    const mr = path.match(/^\/chats\/([\w-]+)\/members\/([a-z0-9_]{3,20})$/);
    if (mr && method === "DELETE") return await removeMember(me, mr[1], mr[2]);

    const rd = path.match(/^\/chats\/([\w-]+)\/read$/);
    if (rd && method === "POST") return await markRead(me, rd[1], req);

    const d = path.match(/^\/chats\/([\w-]+)\/messages\/(\d{13}-[0-9a-f]{6})$/);
    if (d && method === "DELETE") return await deleteMessage(me, d[1], d[2]);

    return fail(404, "Not found.");
  } catch (err) {
    console.error(err);
    return fail(500, err.message || "Server error.");
  }
};

export const config = { path: "/api/*" };
