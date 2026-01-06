async function sha256Hex(data: Uint8Array) {
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function getCookie(req: Request, name: string) {
  const c = req.headers.get("Cookie") || "";
  const m = c.match(new RegExp(`(?:^|; )${name}=([^;]+)`));
  return m ? m[1] : null;
}

async function requireAdmin(request: Request, env: any) {
  const token = getCookie(request, "__Host-td_session");
  if (!token) return null;

  const tokenHash = await sha256Hex(new TextEncoder().encode(token));
  const row = await env.DB.prepare(
    `SELECT u.game_id, u.is_admin, s.admin_mode
     FROM sessions s
     JOIN users u ON u.game_id = s.user_game_id
     WHERE s.token_hash = ? AND s.expires_at > datetime('now')
     LIMIT 1`
  ).bind(tokenHash).first();

  if (!row) return null;
  if (row.is_admin !== 1 || row.admin_mode !== 1) return null;
  return row;
}

export const onRequestGet: PagesFunction = async ({ request, env }) => {
  const admin = await requireAdmin(request, env);
  if (!admin) return new Response("Forbidden", { status: 403 });

  const res = await env.DB.prepare(
    "SELECT id, code, name, cooldown_after_fail_hours, max_attempts, is_active FROM training_types ORDER BY id DESC"
  ).all();

  return Response.json({ items: res.results });
};

export const onRequestPost: PagesFunction = async ({ request, env }) => {
  const admin = await requireAdmin(request, env);
  if (!admin) return new Response("Forbidden", { status: 403 });

  const body = await request.json().catch(() => null);
  if (!body) return new Response("Bad JSON", { status: 400 });

  const { code, name, cooldownAfterFailHours = 24, maxAttempts = 3, isActive = 1 } = body;
  if (!code || !name) return new Response("Missing fields", { status: 400 });

  await env.DB.prepare(
    `INSERT INTO training_types (code, name, cooldown_after_fail_hours, max_attempts, is_active)
     VALUES (?, ?, ?, ?, ?)`
  ).bind(code, name, cooldownAfterFailHours, maxAttempts, isActive ? 1 : 0).run();

  return Response.json({ ok: true });
};
