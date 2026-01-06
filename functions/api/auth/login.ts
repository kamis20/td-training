function b64u(bytes: Uint8Array) {
  return btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
}

function fromB64u(s: string) {
  s = s.replaceAll("-", "+").replaceAll("_", "/");
  while (s.length % 4) s += "=";
  const bin = atob(s);
  return new Uint8Array([...bin].map((c) => c.charCodeAt(0)));
}

async function sha256Hex(data: Uint8Array) {
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

async function hashPassword(password: string, saltBytes: Uint8Array) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt: saltBytes,
      iterations: 150000,
    },
    keyMaterial,
    256
  );

  return new Uint8Array(bits);
}

function constantTimeEqual(a: Uint8Array, b: Uint8Array) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

export const onRequestPost: PagesFunction = async ({ request, env }) => {
  const body = await request.json().catch(() => null);
  if (!body) return new Response("Bad JSON", { status: 400 });

  const { gameId, password } = body;
  if (!gameId || !password) return new Response("Missing fields", { status: 400 });

  const user = await env.DB.prepare(
    "SELECT game_id, password_salt, password_hash, is_active FROM users WHERE game_id = ?"
  ).bind(gameId).first();

  if (!user || user.is_active !== 1) return new Response("Invalid login", { status: 401 });

  const salt = fromB64u(user.password_salt as string);
  const expected = fromB64u(user.password_hash as string);
  const got = await hashPassword(password, salt);

  if (!constantTimeEqual(got, expected)) return new Response("Invalid login", { status: 401 });

  const token = crypto.getRandomValues(new Uint8Array(32));
  const tokenStr = b64u(token);
  const tokenHash = await sha256Hex(new TextEncoder().encode(tokenStr));

  const expires = new Date(Date.now() + 1000 * 60 * 60 * 24 * 14); // 14 dni
  await env.DB.prepare(
    `INSERT INTO sessions (token_hash, user_game_id, admin_mode, expires_at, last_seen_at)
     VALUES (?, ?, 0, ?, datetime('now'))`
  ).bind(tokenHash, gameId, expires.toISOString()).run();

  const cookie = `__Host-td_session=${tokenStr}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${60 * 60 * 24 * 14}`;

  return new Response(JSON.stringify({ ok: true }), {
    headers: {
      "Content-Type": "application/json",
      "Set-Cookie": cookie,
    },
  });
};
