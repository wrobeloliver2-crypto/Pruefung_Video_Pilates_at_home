// Prüfprogramm Pilates @home – eine Function für alles.
// Anmeldung: Portal-Token (aus #ma=…) wird beim Mitarbeiter-Dienst geprüft. Kein eigenes Passwort.
import { neon } from '@neondatabase/serverless';
import { createHmac, createHash } from 'node:crypto';

const sql = neon(process.env.DATABASE_URL);
const MA_URL = 'https://mitarbeiter-api.netlify.app/.netlify/functions/auth';
const ARTEN = ['bild_start', 'bild_ende', 'video', 'voice'];


// ── Abspiel-Links für den Prüfspeicher (S3-kompatibel, nur Lesen, 1 Stunde gültig) ──
const BUCKET = 'pruefmedien';
const REGION = 'eu-central-1';
const hmac = (k, d) => createHmac('sha256', k).update(d).digest();
const enc = (s) => encodeURIComponent(s).replace(/[!'()*]/g, (c) => '%' + c.charCodeAt(0).toString(16).toUpperCase());
function lesenUrl(key, sek = 3600) {
  const ep = process.env.S3_ENDPOINT, ak = process.env.S3_ACCESS_KEY, sk = process.env.S3_SECRET_KEY;
  if (!ep || !ak || !sk) return null;
  const host = new URL(ep).host;
  const t = new Date().toISOString().replace(/[:-]|\.\d{3}/g, '');
  const tag = t.slice(0, 8);
  const scope = `${tag}/${REGION}/s3/aws4_request`;
  const pfad = '/' + BUCKET + '/' + key.split('/').map(enc).join('/');
  const q = { 'X-Amz-Algorithm': 'AWS4-HMAC-SHA256', 'X-Amz-Credential': `${ak}/${scope}`, 'X-Amz-Date': t, 'X-Amz-Expires': String(sek), 'X-Amz-SignedHeaders': 'host' };
  const qs = Object.keys(q).sort().map((k) => `${enc(k)}=${enc(q[k])}`).join('&');
  const canon = ['GET', pfad, qs, `host:${host}\n`, 'host', 'UNSIGNED-PAYLOAD'].join('\n');
  const sts = ['AWS4-HMAC-SHA256', t, scope, createHash('sha256').update(canon).digest('hex')].join('\n');
  const kk = hmac(hmac(hmac(hmac('AWS4' + sk, tag), REGION), 's3'), 'aws4_request');
  const sig = createHmac('sha256', kk).update(sts).digest('hex');
  return `${ep.replace(/\/$/, '')}${pfad}?${qs}&X-Amz-Signature=${sig}`;
}

const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });

const cache = new Map();
async function wer(token) {
  if (!token) return null;
  const c = cache.get(token);
  if (c && c.bis > Date.now()) return c.r;
  let user = null;
  try {
    const res = await fetch(MA_URL, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ action: 'me', token, app: 'intranet' }) });
    if (res.ok) { const d = await res.json(); user = d && d.user ? d.user : null; }
  } catch { user = null; }
  if (!user) return null;
  const mid = Number(user.mitarbeiterId ?? user.mitarbeiter_id ?? user.m ?? user.id);
  let rows = await sql`SELECT id, name, rolle FROM reviewer WHERE mitarbeiter_id = ${mid}`;
  if (!rows.length && user.name) {
    const v = String(user.name).split(' ')[0];
    rows = await sql`SELECT id, name, rolle FROM reviewer WHERE name = ${v} AND mitarbeiter_id IS NOT NULL`;
  }
  const r = rows[0] || null;
  cache.set(token, { r, bis: Date.now() + 60000 });
  return r;
}

async function logError(art, reviewerId, exerciseId, details) {
  await sql`INSERT INTO error_log (art, reviewer_id, exercise_id, details) VALUES (${art}, ${reviewerId ?? null}, ${exerciseId ?? null}, ${String(details ?? '').slice(0, 500)})`;
}
const audit = (akteur, aktion, details) => sql`INSERT INTO audit_log (akteur, aktion, details) VALUES (${akteur}, ${aktion}, ${JSON.stringify(details ?? {})}::jsonb)`;

// Neueste Version je Übung und Art
const NEUESTE = `SELECT DISTINCT ON (exercise_id, art) * FROM asset ORDER BY exercise_id, art, version DESC`;

async function statusJeUebung(nurReviewer) {
  const rows = await sql.query(`
    WITH a AS (${NEUESTE}),
    voll AS (SELECT exercise_id, count(DISTINCT art) FILTER (WHERE art IN ('bild_start','bild_ende','video','voice')) AS n FROM a GROUP BY exercise_id),
    entsch AS (
      SELECT DISTINCT ON (r.asset_id) r.asset_id, r.entscheidung FROM review r ORDER BY r.asset_id, r.zeitstempel DESC)
    SELECT e.id, e.name, e.modus, e.phase, (SELECT a2.storage_key FROM a a2 WHERE a2.exercise_id = e.id AND a2.art = 'bild_start') AS start_key, b.video_status, b.voice_status, COALESCE(b.video_da,false) AS video_da, COALESCE(b.voice_da,false) AS voice_da,
      COALESCE(v.n,0) AS vorhanden,
      asg.reviewer_id, rv.name AS pruefer,
      COALESCE(count(a.id) FILTER (WHERE a.art IN ('bild_start','bild_ende','video','voice')),0) AS inhalte,
      COALESCE(array_agg(DISTINCT a.art) FILTER (WHERE a.art IN ('bild_start','bild_ende','video','voice')), ARRAY[]::text[]) AS arten,
      count(en.asset_id) FILTER (WHERE en.entscheidung='ok') AS ok,
      count(en.asset_id) FILTER (WHERE en.entscheidung='aenderung') AS aenderung
    FROM exercise e
    LEFT JOIN voll v ON v.exercise_id = e.id
    LEFT JOIN bestand b ON b.exercise_id = e.id
    LEFT JOIN assignment asg ON asg.exercise_id = e.id AND asg.aktiv
    LEFT JOIN reviewer rv ON rv.id = asg.reviewer_id
    LEFT JOIN a ON a.exercise_id = e.id
    LEFT JOIN entsch en ON en.asset_id = a.id
    ${nurReviewer ? 'WHERE asg.reviewer_id = $1' : ''}
    GROUP BY e.id, e.name, e.modus, e.phase, b.video_status, b.voice_status, b.video_da, b.voice_da, v.n, asg.reviewer_id, rv.name, e.reihenfolge
    ORDER BY e.reihenfolge NULLS LAST, e.name`, nurReviewer ? [nurReviewer] : []);
  return rows.map(({ start_key, ...r }) => ({ ...r, vorschau: start_key ? lesenUrl(start_key) : null, vorhanden: Number(r.vorhanden), inhalte: Number(r.inhalte), ok: Number(r.ok), aenderung: Number(r.aenderung), pruefbar: Number(r.vorhanden) === 4 }));
}

export default async (req) => {
  if (req.method !== 'POST') return json(405, { error: 'nur POST' });
  let b; try { b = await req.json(); } catch { return json(400, { error: 'ungueltig' }); }
  const { action, data = {}, token } = b;

  // Fehler dürfen auch ohne gültigen Token gemeldet werden (z. B. Anmeldung gescheitert).
  if (action === 'fehlerMelden') {
    const p = await wer(token).catch(() => null);
    await logError(String(data.art || 'sonstiges').slice(0, 40), p && p.id, data.exerciseId, data.details);
    return json(200, { ok: true });
  }

  const p = await wer(token);
  if (!p) { await logError('kein_zugang', null, null, 'Anmeldung nicht möglich oder keine Berechtigung').catch(() => {}); return json(401, { error: 'kein_zugang' }); }
  const admin = p.rolle === 'admin';

  try {
    switch (action) {
      case 'me': return json(200, { id: p.id, name: p.name, rolle: p.rolle });

      case 'liste': {
        if (admin) return json(403, { error: 'nur_pruefer' });
        const l = (await statusJeUebung(p.id)).filter(x => x.pruefbar);
        return json(200, { uebungen: l });
      }

      case 'uebung': {
        const eid = String(data.id || '');
        if (!admin) {
          const a = await sql`SELECT 1 FROM assignment WHERE exercise_id = ${eid} AND reviewer_id = ${p.id} AND aktiv`;
          if (!a.length) return json(403, { error: 'nicht_zugewiesen' });
        }
        const ex = (await sql`SELECT id, name, modus, phase FROM exercise WHERE id = ${eid}`)[0];
        if (!ex) return json(404, { error: 'unbekannt' });
        const assets = await sql.query(`WITH a AS (${NEUESTE}) SELECT a.id, a.art, a.version, a.dateiname, a.hinweis, a.video_mit_rueck, a.storage_key IS NOT NULL AS im_speicher, a.storage_key,
          (SELECT entscheidung FROM review r WHERE r.asset_id = a.id ORDER BY zeitstempel DESC LIMIT 1) AS entscheidung,
          (SELECT kommentar FROM review r WHERE r.asset_id = a.id ORDER BY zeitstempel DESC LIMIT 1) AS kommentar,
          EXISTS (SELECT 1 FROM asset_lock l WHERE l.asset_id = a.id) AS gesperrt
          FROM a WHERE a.exercise_id = $1`, [eid]);
        const inhalte = assets.map(({ storage_key, ...i }) => ({ ...i, url: storage_key ? lesenUrl(storage_key) : null }));
        const zaehl = {};
        for (const k of ['z1','z2','z3','z4','z5','z6','z7','z8','z9','z10','s1','s2']) zaehl[k.replace(/^z/, '')] = lesenUrl('zaehlen/' + k + '.mp3');
        return json(200, { uebung: ex, inhalte, zaehl });
      }

      case 'entscheiden': {
        if (admin) return json(403, { error: 'admin_gibt_nicht_frei' });
        const assetId = Number(data.assetId);
        const ent = data.entscheidung;
        const kom = String(data.kommentar || '').trim();
        if (!['ok', 'aenderung'].includes(ent)) return json(400, { error: 'entscheidung' });
        if (ent === 'aenderung' && !kom) return json(400, { error: 'text_noetig' });
        const a = (await sql`SELECT a.id, a.exercise_id FROM asset a WHERE a.id = ${assetId}`)[0];
        if (!a) return json(404, { error: 'unbekannt' });
        const z = await sql`SELECT 1 FROM assignment WHERE exercise_id = ${a.exercise_id} AND reviewer_id = ${p.id} AND aktiv`;
        if (!z.length) return json(403, { error: 'nicht_zugewiesen' });
        const g = await sql`SELECT 1 FROM asset_lock WHERE asset_id = ${assetId}`;
        if (g.length) return json(409, { error: 'gesperrt' });
        await sql`INSERT INTO review (asset_id, reviewer_id, entscheidung, kommentar) VALUES (${assetId}, ${p.id}, ${ent}, ${ent === 'ok' ? null : kom})`;
        if (ent === 'ok') await sql`INSERT INTO asset_lock (asset_id, gesperrt_von) VALUES (${assetId}, ${p.id}) ON CONFLICT DO NOTHING`;
        await audit(p.name, 'entscheidung', { assetId, ent });
        return json(200, { ok: true });
      }

      // ── Admin ──
      case 'adminUebersicht': {
        if (!admin) return json(403, { error: 'nur_admin' });
        const u = await statusJeUebung(null);
        const pruefer = await sql`SELECT id, name FROM reviewer WHERE rolle = 'pruefer' ORDER BY id`;
        const fehler = await sql`SELECT id, zeitpunkt, art, reviewer_id, exercise_id, details FROM error_log WHERE NOT erledigt ORDER BY zeitpunkt DESC LIMIT 50`;
        const aend = await sql`SELECT e.name AS uebung, a.art, a.version, r.kommentar, rv.name AS pruefer, r.zeitstempel
          FROM review r JOIN asset a ON a.id = r.asset_id JOIN exercise e ON e.id = a.exercise_id JOIN reviewer rv ON rv.id = r.reviewer_id
          WHERE r.entscheidung = 'aenderung' AND r.id = (SELECT max(id) FROM review r2 WHERE r2.asset_id = r.asset_id) ORDER BY r.zeitstempel DESC`;
        return json(200, { uebungen: u, pruefer, fehler, aenderungen: aend });
      }

      case 'zuweisen': {
        if (!admin) return json(403, { error: 'nur_admin' });
        const eid = String(data.exerciseId), rid = Number(data.reviewerId);
        await sql`UPDATE assignment SET aktiv = false WHERE exercise_id = ${eid} AND aktiv`;
        if (rid) await sql`INSERT INTO assignment (exercise_id, reviewer_id) VALUES (${eid}, ${rid})`;
        await audit(p.name, 'zuweisen', { eid, rid });
        return json(200, { ok: true });
      }

      case 'fehlerErledigt': {
        if (!admin) return json(403, { error: 'nur_admin' });
        await sql`UPDATE error_log SET erledigt = true WHERE id = ${Number(data.id)}`;
        return json(200, { ok: true });
      }

      default: return json(400, { error: 'unbekannte_aktion' });
    }
  } catch (e) {
    await logError('speicher_fehler', p.id, data.id || data.exerciseId, e.message).catch(() => {});
    return json(500, { error: 'serverfehler' });
  }
};
