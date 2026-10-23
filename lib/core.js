// Shared: security gateway, deterministic static scanner, Gemini client.
export const MODELS = ['gemini-2.5-flash', 'gemini-2.0-flash', 'gemini-2.5-flash-lite'];
const HITS = new Map();
const WAF = [/ignore (all |any )?(previous|prior|above) instructions/i, /(reveal|print|show).{0,20}system prompt/i,
  /bypass (the )?(security|safety|rules)/i, /you are now (dan|jailbroken)/i, /disregard .{0,30}(rules|instructions)/i];

export function guard(req, res) {
  res.setHeader('X-Content-Type-Options', 'nosniff'); res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') { res.status(405).json({ error: 'Method Not Allowed' }); return false; }
  const ip = (req.headers['x-forwarded-for'] || 'x').split(',')[0], now = Date.now();
  const hits = (HITS.get(ip) || []).filter(t => now - t < 60000);
  if (hits.length >= 20) { res.status(429).json({ error: 'Rate limit: 20 req/min. Thoda ruk ja bhai.' }); return false; }
  hits.push(now); HITS.set(ip, hits);
  const code = req.body?.code;
  if (code !== undefined) {
    if (typeof code !== 'string' || !code.trim()) { res.status(400).json({ error: 'Code input is required' }); return false; }
    if (code.length > 8000) { res.status(413).json({ error: 'Max 8000 characters allowed' }); return false; }
    if (WAF.some(rx => rx.test(code))) {
      res.status(403).json({ error: 'WAF_BLOCKED: Prompt-injection pattern detected at the gateway. Request never reached the model.' });
      return false;
    }
  }
  return true;
}

export const pickKey = req => (req.headers['x-user-key'] || process.env.GEMINI_API_KEY || '').toString().trim();

const RULES = [
  [/(api[_-]?key|secret|token|passwd|password)\s*[:=]\s*["'][^"']{6,}["']|["']sk-[\w-]{8,}["']/i, 'CWE-798', 'Hardcoded credential in source', 'CRITICAL', 25],
  [/\beval\s*\(|\bexec\s*\(|new Function\s*\(/, 'CWE-95', 'Dynamic code execution (eval/exec)', 'CRITICAL', 30],
  [/(SELECT|INSERT|UPDATE|DELETE)\b[^\n]*(\{[^}]+\}|\$\{|["']\s*\+\s*\w|["']\s*%\s*\w|\.format\()/i, 'CWE-89', 'SQL built via string interpolation (injection)', 'CRITICAL', 28],
  [/shell\s*=\s*True|os\.system\(|child_process\.exec\(/, 'CWE-78', 'OS command injection surface', 'HIGH', 20],
  [/pickle\.loads?\(|yaml\.load\((?![^)]*Safe)/, 'CWE-502', 'Unsafe deserialization', 'HIGH', 18],
  [/verify\s*=\s*False|rejectUnauthorized\s*:\s*false/, 'CWE-295', 'TLS verification disabled', 'HIGH', 15],
  [/innerHTML\s*=|dangerouslySetInnerHTML/, 'CWE-79', 'Unescaped HTML sink (XSS)', 'MEDIUM', 10],
  [/\b(md5|sha1)\b/i, 'CWE-327', 'Weak hash algorithm', 'MEDIUM', 8],
  [/debug\s*=\s*True/, 'CWE-489', 'Debug mode enabled', 'LOW', 5],
  [/\bfor\b[^\n]*\n(?:[^\n]*\n){0,3}?[ \t]+(for\b|[^\n]*\.forEach\()/, 'PERF', 'Nested loop: likely O(N²) bottleneck', 'MEDIUM', 12],
];

export function scan(code) {
  const findings = RULES.filter(([rx]) => rx.test(code)).map(([, id, title, sev, p]) => ({ id, title, sev, penalty: p }));
  return { findings, score: Math.max(0, 100 - findings.reduce((a, f) => a + f.penalty, 0)) };
}

export async function gemini({ key, models, prompt }) {
  let lastErr;
  for (const model of models) {
    const ctl = new AbortController(), timer = setTimeout(() => ctl.abort(), 45000);
    try {
      const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent`, {
        method: 'POST', signal: ctl.signal,
        headers: { 'Content-Type': 'application/json', 'x-goog-api-key': key },
        body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }],
          generationConfig: { responseMimeType: 'application/json', temperature: 0.2 } })
      });
      const d = await r.json();
      if (!r.ok) { lastErr = new Error(d.error?.message || `HTTP ${r.status}`); if (r.status === 400 || r.status === 401 || r.status === 403) break; continue; }
      const t = d.candidates?.[0]?.content?.parts?.[0]?.text;
      if (!t) { lastErr = new Error('Empty model response'); continue; }
      return { data: JSON.parse(t.replace(/^```json\s*|```$/g, '').trim()), model };
    } catch (e) { lastErr = e.name === 'AbortError' ? new Error('Gemini timeout') : e; } finally { clearTimeout(timer); }
  }
  throw lastErr || new Error('Gemini call failed');
}
