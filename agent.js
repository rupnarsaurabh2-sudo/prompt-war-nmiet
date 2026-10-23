// api/agent.js - Vercel Serverless Function (Zero-Trust Backend)
export default async function handler(req, res) {
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method Not Allowed' });
    }

    const { code, clientApiKey } = req.body;
    // Server environment key first, fallback to client key if provided
    const apiKey = process.env.GEMINI_API_KEY || clientApiKey;

    if (!code) {
        return res.status(400).json({ error: 'Code input is required' });
    }

    // Backend Security Layer: Prompt Injection & Payload Guard
    const forbidden = [/ignore previous instructions/i, /system prompt/i, /bypass security/i];
    if (forbidden.some(rx => rx.test(code))) {
        return res.status(403).json({ error: 'SECURITY_ALERT: Adversarial Prompt Injection Blocked by Backend WAF.' });
    }

    if (!apiKey) {
        return res.status(401).json({ error: 'NO_API_KEY' });
    }

    const prompt = `You are AegisAI, an Autonomous DevSecOps & Self-Healing System.
    Perform a 4-agent autonomous workflow on the following code:
    1. Recon Agent: Find OWASP/CWE security vulnerabilities and Big-O complexity bottlenecks.
    2. Patcher Agent: Rewrite the complete code to be 100% secure and algorithmically optimal.
    3. QA Verifier Agent: Write 2 automated unit test assertions to verify the patched code works securely.

    Respond ONLY with valid JSON matching this exact structure:
    {
      "security_score_before": 25,
      "security_score_after": 96,
      "complexity_change": "O(N²) ➔ O(N)",
      "autonomous_reasoning": "Detailed multi-agent reasoning log...",
      "vulnerabilities_found": ["CWE-89: ...", "Performance: ..."],
      "patched_code": "Full fixed code...",
      "unit_tests": "Automated unit test code to verify the patch..."
    }

    Source Code:
    ${code}`;

    try {
        const response = await fetch(
            `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent?key=${apiKey}`,
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    contents: [{ parts: [{ text: prompt }] }],
                    generationConfig: { responseMimeType: "application/json" }
                })
            }
        );

        const data = await response.json();
        const resultText = data.candidates?.[0]?.content?.parts?.[0]?.text;
        
        if (!resultText) throw new Error("Invalid response from Gemini Engine");
        return res.status(200).json(JSON.parse(resultText));

    } catch (error) {
        return res.status(500).json({ error: error.message });
    }
}
