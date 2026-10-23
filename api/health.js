import { guard, pickKey, gemini, MODELS } from '../lib/core.js';
export default async function handler(req, res) {
  if (!guard(req, res)) return;
  const key = pickKey(req), source = req.headers['x-user-key'] ? 'browser' : process.env.GEMINI_API_KEY ? 'server-env' : 'none';
  if (!req.body?.test) return res.json({ source, configured: !!key });
  if (!key) return res.json({ ok: false, source, error: 'No key found. Set GEMINI_API_KEY in Vercel or paste one in the browser.' });
  try {
    const t0 = Date.now();
    const { model } = await gemini({ key, models: [req.body.model || MODELS[0], ...MODELS], prompt: 'Reply with JSON {"ok":true}' });
    return res.json({ ok: true, source, model, ms: Date.now() - t0 });
  } catch (e) { return res.json({ ok: false, source, error: e.message }); }
}
