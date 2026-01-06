async function sha256Hex(data: Uint8Array) {
  const digest = await crypto.subtle.digest("SHA-256", data);
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function getCookie(req: Request, name: string) {
  const c = req.headers.get("Cookie") || "";
  const m = c.match(new RegExp(`(?:^|; )${name}=([^;]+)`));
  return m ? m[1] : null;
}

export const onRequestPost: PagesFunction = async ({ request, env }) => {
  const token = getCookie(request, "__Host-td_session");
  if (token) {
    const tokenHash = await sha256Hex(new TextEncoder().encode(token));
    await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(tokenHash).run();
  }

  const cookie = `__Host-td_session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
  return new Response(JSON.stringify({ ok: true }), {
    headers: { "Content-Type": "application/json", "Set-Cookie": cookie },
  });
};
