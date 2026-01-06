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
      iterations: 100000,
    },
    keyMaterial,
    256
  );

  return new Uint8Array(bits);
}

export const onRequestPost: PagesFunction = async ({ request, env }) => {
  try {
    const body = await request.json().catch(() => null);
    if (!body) return new Response("Bad JSON", { status: 400 });

    const { bootstrapKey, gameId, fullName, password } = body;

    if (!env.BOOTSTRAP_KEY || bootstrapKey !== env.BOOTSTRAP_KEY) {
      return new Response("Forbidden", { status: 403 });
    }

    if (!gameId || !fullName || !password) {
      return new Response("Missing fields", { status: 400 });
    }

    // 1) Jeśli admin już istnieje — koniec
    const existingAdmin = await env.DB.prepare(
      "SELECT game_id FROM users WHERE is_admin = 1 LIMIT 1"
    ).first();

    if (existingAdmin) {
      return new Response("Admin already exists", { status: 409 });
    }

    // 2) Jeśli gameId już jest w bazie (np. wcześniej dodany trener) — zwróć czytelny błąd
    const existingUser = await env.DB.prepare(
      "SELECT game_id, is_admin FROM users WHERE game_id = ? LIMIT 1"
    ).bind(gameId).first();

    if (existingUser) {
      return new Response("User with this gameId already exists", { status: 409 });
    }

    // 3) Tworzenie admina
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const hash = await hashPassword(password, salt);

    const saltB64 = b64u(salt);
    const hashB64 = b64u(hash);

    await env.DB.prepare(
      `INSERT INTO users (game_id, full_name, password_salt, password_hash, is_admin, is_active)
       VALUES (?, ?, ?, ?, 1, 1)`
    ).bind(gameId, fullName, saltB64, hashB64).run();

    return Response.json({ ok: true });
  } catch (e: any) {
    // Zamiast 1101, pokażemy błąd normalnie
    const msg = String(e?.message || e);
    console.log("BOOTSTRAP_ERROR", msg, e?.stack);
    return Response.json(
      { ok: false, error: msg, stack: e?.stack ? String(e.stack).slice(0, 1500) : null },
      { status: 500 }
    );
  }
};
