export const onRequestGet: PagesFunction = async ({ env }) => {
  try {
    const hasDB = !!(env as any).DB;

    if (!hasDB) {
      return Response.json(
        { ok: false, hasDB: false, hint: "Brak D1 bindingu o nazwie DB w tym środowisku (Production/Preview)." },
        { status: 500 }
      );
    }

    const res = await (env as any).DB
      .prepare("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
      .all();

    const tables = (res.results || []).map((r: any) => r.name);

    return Response.json({
      ok: true,
      hasDB: true,
      tables,
      hasBootstrapKey: !!(env as any).BOOTSTRAP_KEY
    });
  } catch (e: any) {
    return Response.json(
      { ok: false, error: String(e?.message || e), stack: e?.stack ? String(e.stack).slice(0, 800) : null },
      { status: 500 }
    );
  }
};
