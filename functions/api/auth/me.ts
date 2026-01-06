async function sha256Hex(data: Uint8Array) {
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function getCookie(req: Request, name: string) {
  const c = req.headers.get("Cookie") || "";
  const m = c.match(new RegExp(`(?:^|; )${name}=([^;]+)`));
  return m ? m[1] : null;
}

export const onRequestGet: PagesFunction = async ({ request, env }) => {
  const token = getCookie(request, "__Host-td_session");
  if (!token) return Response.json({ user: null });

  const tokenHash = await sha256Hex(new TextEncoder().encode(token));

  const row = await env.DB.prepare(
    `SELECT u.game_id, u.full_name, u.is_admin, s.admin_mode
     FROM sessions s
     JOIN users u ON u.game_id = s.user_game_id
     WHERE s.token_hash = ? AND s.expires_at > datetime('now')
     LIMIT 1`
  ).bind(tokenHash).first();

  if (!row) return Response.json({ user: null });

  return Response.json({
    user: {
      gameId: row.game_id,
      fullName: row.full_name,
      isAdmin: row.is_admin === 1,
      adminMode: row.admin_mode === 1,
    },
  });
};
