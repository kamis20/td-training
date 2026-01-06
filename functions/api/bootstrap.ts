
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

export const onRequestPost: PagesFunction = async ({ request, env }) => {
  const body = await request.json().catch(() => null);
  if (!body) return new Response("Bad JSON", { status: 400 });

  const { bootstrapKey, gameId, fullName, password } = body;

  if (!env.BOOTSTRAP_KEY || bootstrapKey !== env.BOOTSTRAP_KEY) {
    return new Response("Forbidden", { status: 403 });
  }

  if (!gameId || !fullName || !password) {
    return new Response("Missing fields", { status: 400 });
  }

  const existingAdmin = await env.DB.prepare(
    "SELECT game_id FROM users WHERE is_admin = 1 LIMIT 1"
  ).first();

  if (existingAdmin) {
    return new Response("Admin already exists", { status: 409 });
  }

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await hashPassword(password, salt);

  const saltB64 = b64u(salt);
  const hashB64 = b64u(hash);

  await env.DB.prepare(
    `INSERT INTO users (game_id, full_name, password_salt, password_hash, is_admin, is_active)
     VALUES (?, ?, ?, ?, 1, 1)`
  ).bind(gameId, fullName, saltB64, hashB64).run();

  return Response.json({ ok: true });
};
