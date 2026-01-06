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

export const onRequestPatch: PagesFunction = async ({ request, env, params }) => {
  const admin = await requireAdmin(request, env);
  if (!admin) return new Response("Forbidden", { status: 403 });

  const id = Number(params.id);
  if (!Number.isFinite(id)) return new Response("Bad id", { status: 400 });

  const body = await request.json().catch(() => null);
  if (!body) return new Response("Bad JSON", { status: 400 });

  const { name, cooldownAfterFailHours, maxAttempts, isActive } = body;

  await env.DB.prepare(
    `UPDATE training_types
     SET name = COALESCE(?, name),
         cooldown_after_fail_hours = COALESCE(?, cooldown_after_fail_hours),
         max_attempts = COALESCE(?, max_attempts),
         is_active = COALESCE(?, is_active)
     WHERE id = ?`
  ).bind(
    name ?? null,
    cooldownAfterFailHours ?? null,
    maxAttempts ?? null,
    typeof isActive === "number" ? isActive : (typeof isActive === "boolean" ? (isActive ? 1 : 0) : null),
    id
  ).run();

  return Response.json({ ok: true });
};
