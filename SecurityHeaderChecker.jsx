import { useState, useRef, useEffect } from "react";

// ─── Header Definitions (mirrors Python tool) ────────────────────────────────
const SECURITY_HEADERS = {
  "Strict-Transport-Security": {
    severity: "HIGH",
    description: "Enforces HTTPS. Prevents protocol downgrade attacks.",
    recommendation: "max-age=31536000; includeSubDomains; preload",
  },
  "Content-Security-Policy": {
    severity: "HIGH",
    description: "Controls allowed resources. Mitigates XSS and injection.",
    recommendation: "default-src 'self'",
  },
  "X-Frame-Options": {
    severity: "MEDIUM",
    description: "Prevents clickjacking via iframe embedding.",
    recommendation: "DENY",
  },
  "X-Content-Type-Options": {
    severity: "MEDIUM",
    description: "Prevents MIME-type sniffing.",
    recommendation: "nosniff",
  },
  "Referrer-Policy": {
    severity: "LOW",
    description: "Controls referrer information sent with requests.",
    recommendation: "strict-origin-when-cross-origin",
  },
  "Permissions-Policy": {
    severity: "LOW",
    description: "Controls browser feature access (camera, mic, etc.).",
    recommendation: "geolocation=(), microphone=(), camera=()",
  },
  "X-XSS-Protection": {
    severity: "INFO",
    description: "Legacy XSS filter (deprecated, CSP is the modern standard).",
    recommendation: "1; mode=block",
  },
};

const LEAKY_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"];

const SEV_COLOR = {
  HIGH:   { bg: "#3d0f0f", border: "#ff3b3b", text: "#ff6b6b", dot: "#ff3b3b" },
  MEDIUM: { bg: "#3d2a00", border: "#ff9500", text: "#ffb340", dot: "#ff9500" },
  LOW:    { bg: "#0d2a3d", border: "#0a84ff", text: "#40b0ff", dot: "#0a84ff" },
  INFO:   { bg: "#1a1a2e", border: "#636380", text: "#a0a0b0", dot: "#636380" },
  PASS:   { bg: "#0a2a1a", border: "#30d158", text: "#34c759", dot: "#30d158" },
  LEAK:   { bg: "#2a1a00", border: "#ff9f0a", text: "#ffcc44", dot: "#ff9f0a" },
};

// ─── Analysis Logic ───────────────────────────────────────────────────────────
function parseHeaders(rawText) {
  const lines = rawText.trim().split("\n");
  const headers = {};
  for (const line of lines) {
    const idx = line.indexOf(":");
    if (idx > 0) {
      const key = line.slice(0, idx).trim().toLowerCase();
      const val = line.slice(idx + 1).trim();
      headers[key] = val;
    }
  }
  return headers;
}

function analyzeHeaders(headers) {
  const missing = [], present = [], leaking = [], warnings = [];

  for (const [name, info] of Object.entries(SECURITY_HEADERS)) {
    const key = name.toLowerCase();
    if (!headers[key]) {
      missing.push({ header: name, ...info });
    } else {
      const value = headers[key];
      const finding = { header: name, value, severity: info.severity };
      if (name === "Strict-Transport-Security" && value.includes("max-age")) {
        const match = value.match(/max-age=(\d+)/);
        if (match && parseInt(match[1]) < 31536000) {
          finding.warning = `max-age=${match[1]} is below recommended 31536000 (1 year)`;
          warnings.push(finding);
        }
      }
      if (name === "Content-Security-Policy" && value.includes("unsafe-inline")) {
        finding.warning = "'unsafe-inline' undermines XSS protection";
        warnings.push(finding);
      }
      present.push(finding);
    }
  }

  for (const h of LEAKY_HEADERS) {
    if (headers[h]) {
      leaking.push({ header: h, value: headers[h] });
    }
  }

  const SEV_DEDUCT = { HIGH: 25, MEDIUM: 15, LOW: 5, INFO: 2 };
  let deductions = missing.reduce((acc, h) => acc + (SEV_DEDUCT[h.severity] || 0), 0);
  deductions += leaking.length * 5 + warnings.length * 5;
  const score = Math.max(0, 100 - deductions);
  const grade = score >= 80 ? "A" : score >= 60 ? "B" : score >= 40 ? "C" : "F";
  const label = score >= 80 ? "Good" : score >= 60 ? "Fair" : score >= 40 ? "Poor" : "Critical";

  return { missing, present, leaking, warnings, score: { score, grade, label } };
}

// ─── Sub-components ───────────────────────────────────────────────────────────
function ScoreRing({ score, grade, label }) {
  const radius = 54;
  const circ = 2 * Math.PI * radius;
  const offset = circ - (score / 100) * circ;
  const color = score >= 80 ? "#30d158" : score >= 60 ? "#ff9500" : score >= 40 ? "#ff6b6b" : "#ff3b3b";

  return (
    <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 4 }}>
      <svg width="130" height="130" style={{ transform: "rotate(-90deg)" }}>
        <circle cx="65" cy="65" r={radius} fill="none" stroke="#1e1e2e" strokeWidth="10" />
        <circle
          cx="65" cy="65" r={radius} fill="none"
          stroke={color} strokeWidth="10"
          strokeDasharray={circ} strokeDashoffset={offset}
          strokeLinecap="round"
          style={{ transition: "stroke-dashoffset 1s ease" }}
        />
      </svg>
      <div style={{ marginTop: -100, textAlign: "center", position: "relative", zIndex: 1 }}>
        <div style={{ fontSize: 32, fontWeight: 900, color, fontFamily: "'JetBrains Mono', monospace" }}>{score}</div>
        <div style={{ fontSize: 11, color: "#636380", letterSpacing: "0.15em", fontFamily: "monospace" }}>/ 100</div>
      </div>
      <div style={{ marginTop: 8, textAlign: "center" }}>
        <span style={{
          fontSize: 28, fontWeight: 900, color,
          fontFamily: "'JetBrains Mono', monospace", display: "block"
        }}>{grade}</span>
        <span style={{ fontSize: 11, color: "#636380", letterSpacing: "0.1em", fontFamily: "monospace" }}>{label.toUpperCase()}</span>
      </div>
    </div>
  );
}

function HeaderBadge({ severity }) {
  const c = SEV_COLOR[severity] || SEV_COLOR.INFO;
  return (
    <span style={{
      fontSize: 9, fontWeight: 700, letterSpacing: "0.12em",
      padding: "2px 6px", borderRadius: 3,
      background: c.bg, border: `1px solid ${c.border}`, color: c.text,
      fontFamily: "monospace",
    }}>{severity}</span>
  );
}

function FindingRow({ item, type }) {
  const [open, setOpen] = useState(false);
  const c = type === "pass" ? SEV_COLOR.PASS
    : type === "leak" ? SEV_COLOR.LEAK
    : SEV_COLOR[item.severity] || SEV_COLOR.INFO;

  return (
    <div style={{
      borderLeft: `3px solid ${c.border}`,
      background: c.bg,
      borderRadius: "0 6px 6px 0",
      marginBottom: 6,
      overflow: "hidden",
      transition: "all 0.2s",
    }}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          width: "100%", textAlign: "left", padding: "10px 14px",
          background: "none", border: "none", cursor: "pointer",
          display: "flex", alignItems: "center", gap: 10,
        }}
      >
        <span style={{ color: c.dot, fontSize: 10 }}>●</span>
        <span style={{ flex: 1, fontFamily: "monospace", fontSize: 13, color: "#e0e0f0", fontWeight: 600 }}>
          {item.header}
        </span>
        {item.value && (
          <span style={{ fontSize: 11, color: "#636380", fontFamily: "monospace", maxWidth: 200, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {item.value}
          </span>
        )}
        {item.severity && type !== "pass" && type !== "leak" && <HeaderBadge severity={item.severity} />}
        <span style={{ color: "#636380", fontSize: 10 }}>{open ? "▲" : "▼"}</span>
      </button>
      {open && (
        <div style={{ padding: "0 14px 12px 28px", fontSize: 12, lineHeight: 1.6, color: "#a0a0b0", fontFamily: "monospace" }}>
          {item.description && <div style={{ marginBottom: 6 }}>{item.description}</div>}
          {item.warning && (
            <div style={{ color: "#ffb340", marginBottom: 6 }}>⚠ {item.warning}</div>
          )}
          {item.recommendation && (
            <div style={{ background: "#0d0d1a", padding: "6px 10px", borderRadius: 4, color: "#50fa7b", marginTop: 4 }}>
              {type !== "pass" ? "Suggested value: " : ""}
              <span style={{ color: "#f1fa8c" }}>{item.recommendation}</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function Section({ title, icon, count, children, defaultOpen = false }) {
  const [open, setOpen] = useState(defaultOpen);
  if (count === 0) return null;
  return (
    <div style={{ marginBottom: 20 }}>
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          width: "100%", textAlign: "left", background: "none", border: "none",
          cursor: "pointer", display: "flex", alignItems: "center", gap: 8,
          marginBottom: open ? 8 : 0, padding: "4px 0",
        }}
      >
        <span style={{ fontSize: 14 }}>{icon}</span>
        <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 13, color: "#c0c0d8", fontWeight: 700, letterSpacing: "0.05em" }}>
          {title}
        </span>
        <span style={{ marginLeft: 4, fontFamily: "monospace", fontSize: 11, color: "#636380" }}>({count})</span>
        <span style={{ marginLeft: "auto", color: "#636380", fontSize: 10 }}>{open ? "▲" : "▼"}</span>
      </button>
      {open && <div>{children}</div>}
    </div>
  );
}

// ─── AI Analysis Component ────────────────────────────────────────────────────
function AIAnalysis({ findings, url }) {
  const [analysis, setAnalysis] = useState("");
  const [loading, setLoading] = useState(false);
  const [done, setDone] = useState(false);

  const getAIAnalysis = async () => {
    setLoading(true);
    setAnalysis("");
    setDone(false);

    const summary = `
URL: ${url}
Score: ${findings.score.score}/100 (Grade: ${findings.score.grade})
Missing headers: ${findings.missing.map(h => `${h.header} [${h.severity}]`).join(", ") || "none"}
Present headers: ${findings.present.map(h => h.header).join(", ") || "none"}
Leaking headers: ${findings.leaking.map(h => `${h.header}: ${h.value}`).join(", ") || "none"}
Warnings: ${findings.warnings.map(h => h.warning).join("; ") || "none"}
    `.trim();

    try {
      const response = await fetch("https://api.anthropic.com/v1/messages", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          model: "claude-sonnet-4-20250514",
          max_tokens: 1000,
          stream: true,
          system: "You are a senior application security engineer. Analyze HTTP security header findings concisely. Be specific, practical, and educational. Use plain text (no markdown). Keep it under 250 words. Focus on the most impactful issues and what an attacker could do with the gaps.",
          messages: [{ role: "user", content: `Analyze these security header findings and give me a practical security assessment:\n\n${summary}` }],
        }),
      });

      const reader = response.body.getReader();
      const decoder = new TextDecoder();

      while (true) {
        const { done: streamDone, value } = await reader.read();
        if (streamDone) break;
        const chunk = decoder.decode(value);
        const lines = chunk.split("\n");
        for (const line of lines) {
          if (line.startsWith("data: ")) {
            try {
              const data = JSON.parse(line.slice(6));
              if (data.type === "content_block_delta" && data.delta?.text) {
                setAnalysis(prev => prev + data.delta.text);
              }
            } catch {}
          }
        }
      }
      setDone(true);
    } catch (e) {
      setAnalysis("Unable to fetch AI analysis. Check your API connection.");
      setDone(true);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ marginTop: 24, borderTop: "1px solid #1e1e2e", paddingTop: 20 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 12 }}>
        <span style={{ fontFamily: "monospace", fontSize: 13, color: "#c0c0d8", fontWeight: 700 }}>🤖 AI Security Analysis</span>
        {!done && (
          <button
            onClick={getAIAnalysis}
            disabled={loading}
            style={{
              marginLeft: "auto",
              padding: "5px 14px",
              background: loading ? "#1a1a2e" : "#0a1628",
              border: "1px solid #0a84ff",
              borderRadius: 4,
              color: "#40b0ff",
              fontFamily: "monospace",
              fontSize: 11,
              cursor: loading ? "default" : "pointer",
              letterSpacing: "0.05em",
            }}
          >
            {loading ? "Analyzing..." : "Run Analysis →"}
          </button>
        )}
      </div>
      {(analysis || loading) && (
        <div style={{
          background: "#050510",
          border: "1px solid #1e1e2e",
          borderRadius: 6,
          padding: "14px 16px",
          fontFamily: "'JetBrains Mono', monospace",
          fontSize: 12,
          color: "#a0f0c0",
          lineHeight: 1.8,
          whiteSpace: "pre-wrap",
          minHeight: 80,
        }}>
          {analysis}
          {loading && <span style={{ animation: "blink 1s infinite", color: "#30d158" }}>█</span>}
        </div>
      )}
    </div>
  );
}

// ─── Main App ─────────────────────────────────────────────────────────────────
export default function SecurityHeaderChecker() {
  const [input, setInput] = useState("");
  const [results, setResults] = useState(null);
  const [url, setUrl] = useState("");
  const [mode, setMode] = useState("paste"); // "paste" | "demo"
  const [animIn, setAnimIn] = useState(false);

  const DEMO_HEADERS = `HTTP/2 200
server: nginx/1.18.0
x-powered-by: PHP/8.1.2
content-type: text/html; charset=UTF-8
cache-control: max-age=0
x-frame-options: SAMEORIGIN
x-content-type-options: nosniff
referrer-policy: strict-origin-when-cross-origin`;

  const DEMO_URL = "https://vulnerable-demo-site.example.com";

  const handleAnalyze = (headersText, targetUrl) => {
    const headers = parseHeaders(headersText);
    const findings = analyzeHeaders(headers);
    setResults(findings);
    setUrl(targetUrl || "Pasted Headers");
    setAnimIn(false);
    setTimeout(() => setAnimIn(true), 50);
  };

  return (
    <div style={{
      minHeight: "100vh",
      background: "#050510",
      fontFamily: "'JetBrains Mono', monospace",
      color: "#e0e0f0",
      padding: "0 0 60px",
    }}>
      <style>{`
        @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700;900&family=Space+Mono:wght@400;700&display=swap');
        * { box-sizing: border-box; }
        ::-webkit-scrollbar { width: 6px; background: #050510; }
        ::-webkit-scrollbar-thumb { background: #1e1e2e; border-radius: 3px; }
        @keyframes blink { 0%,100%{opacity:1} 50%{opacity:0} }
        @keyframes fadeSlideIn { from{opacity:0;transform:translateY(16px)} to{opacity:1;transform:translateY(0)} }
        @keyframes scanLine { 0%{top:-10%} 100%{top:110%} }
        textarea { resize: vertical; }
        button:hover { opacity: 0.85; }
      `}</style>

      {/* Header */}
      <div style={{
        borderBottom: "1px solid #0d0d24",
        padding: "20px 32px",
        background: "#070712",
        display: "flex",
        alignItems: "center",
        gap: 16,
      }}>
        <div style={{
          width: 32, height: 32, borderRadius: 8,
          background: "linear-gradient(135deg, #0a84ff, #30d158)",
          display: "flex", alignItems: "center", justifyContent: "center",
          fontSize: 16,
        }}>🔍</div>
        <div>
          <div style={{ fontSize: 15, fontWeight: 900, letterSpacing: "0.05em", color: "#e0e0f0" }}>
            SecurityHeaderChecker
          </div>
          <div style={{ fontSize: 10, color: "#636380", letterSpacing: "0.15em" }}>
            HTTP SECURITY HEADER ANALYZER · v1.0
          </div>
        </div>
        <div style={{ marginLeft: "auto", display: "flex", gap: 6 }}>
          {["HIGH", "MEDIUM", "LOW"].map(s => (
            <span key={s} style={{
              fontSize: 9, padding: "2px 7px", borderRadius: 3, fontWeight: 700, letterSpacing: "0.1em",
              background: SEV_COLOR[s].bg, border: `1px solid ${SEV_COLOR[s].border}`, color: SEV_COLOR[s].text,
            }}>{s}</span>
          ))}
        </div>
      </div>

      <div style={{ maxWidth: 860, margin: "0 auto", padding: "32px 24px" }}>

        {/* Input Panel */}
        <div style={{
          background: "#070712",
          border: "1px solid #1e1e2e",
          borderRadius: 10,
          padding: 24,
          marginBottom: 28,
        }}>
          <div style={{ display: "flex", gap: 8, marginBottom: 16 }}>
            {[["paste", "Paste Headers"], ["demo", "Load Demo"]].map(([m, label]) => (
              <button
                key={m}
                onClick={() => { setMode(m); if (m === "demo") setInput(DEMO_HEADERS); else setInput(""); }}
                style={{
                  padding: "6px 14px",
                  background: mode === m ? "#0a1628" : "transparent",
                  border: `1px solid ${mode === m ? "#0a84ff" : "#1e1e2e"}`,
                  borderRadius: 4,
                  color: mode === m ? "#40b0ff" : "#636380",
                  fontSize: 11, cursor: "pointer", letterSpacing: "0.05em", fontFamily: "monospace",
                }}
              >{label}</button>
            ))}
          </div>

          <div style={{ marginBottom: 12 }}>
            <label style={{ fontSize: 10, color: "#636380", letterSpacing: "0.12em", display: "block", marginBottom: 6 }}>
              TARGET URL (optional, for report labeling)
            </label>
            <input
              value={url}
              onChange={e => setUrl(e.target.value)}
              placeholder="https://example.com"
              style={{
                width: "100%", padding: "8px 12px",
                background: "#050510", border: "1px solid #1e1e2e", borderRadius: 4,
                color: "#e0e0f0", fontFamily: "monospace", fontSize: 12,
                outline: "none",
              }}
            />
          </div>

          <div style={{ marginBottom: 14 }}>
            <label style={{ fontSize: 10, color: "#636380", letterSpacing: "0.12em", display: "block", marginBottom: 6 }}>
              PASTE RESPONSE HEADERS (one per line, key: value format)
            </label>
            <textarea
              value={input}
              onChange={e => setInput(e.target.value)}
              placeholder={`Content-Type: text/html\nX-Frame-Options: SAMEORIGIN\nStrict-Transport-Security: max-age=31536000\n...`}
              rows={8}
              style={{
                width: "100%", padding: "10px 12px",
                background: "#050510", border: "1px solid #1e1e2e", borderRadius: 4,
                color: "#a0f0a0", fontFamily: "monospace", fontSize: 12, lineHeight: 1.7,
                outline: "none",
              }}
            />
          </div>

          <button
            onClick={() => handleAnalyze(input, url)}
            disabled={!input.trim()}
            style={{
              width: "100%", padding: "12px",
              background: input.trim() ? "linear-gradient(90deg, #0a1628, #071a10)" : "#0d0d1a",
              border: `1px solid ${input.trim() ? "#0a84ff" : "#1e1e2e"}`,
              borderRadius: 6,
              color: input.trim() ? "#40b0ff" : "#404060",
              fontFamily: "monospace", fontSize: 13, fontWeight: 700,
              cursor: input.trim() ? "pointer" : "default",
              letterSpacing: "0.1em",
              transition: "all 0.2s",
            }}
          >
            {input.trim() ? "▶  ANALYZE HEADERS" : "PASTE HEADERS TO BEGIN"}
          </button>
        </div>

        {/* Results */}
        {results && (
          <div style={{ animation: animIn ? "fadeSlideIn 0.4s ease both" : "none" }}>

            {/* Score + summary stats */}
            <div style={{
              background: "#070712",
              border: "1px solid #1e1e2e",
              borderRadius: 10,
              padding: 24,
              marginBottom: 20,
              display: "flex",
              gap: 32,
              alignItems: "center",
              flexWrap: "wrap",
            }}>
              <ScoreRing {...results.score} />

              <div style={{ flex: 1, minWidth: 200 }}>
                <div style={{ fontSize: 10, color: "#636380", letterSpacing: "0.15em", marginBottom: 14 }}>SCAN SUMMARY</div>
                {[
                  ["Missing Headers", results.missing.length, results.missing.length > 0 ? "#ff6b6b" : "#30d158"],
                  ["Present Headers", results.present.length, "#30d158"],
                  ["Leaking Headers", results.leaking.length, results.leaking.length > 0 ? "#ffb340" : "#30d158"],
                  ["Warnings", results.warnings.length, results.warnings.length > 0 ? "#ffb340" : "#30d158"],
                ].map(([label, count, color]) => (
                  <div key={label} style={{ display: "flex", justifyContent: "space-between", marginBottom: 8, alignItems: "center" }}>
                    <span style={{ fontSize: 12, color: "#808090" }}>{label}</span>
                    <span style={{ fontWeight: 700, fontSize: 15, color, fontFamily: "monospace" }}>{count}</span>
                  </div>
                ))}
              </div>

              <div style={{ flex: 1, minWidth: 200 }}>
                <div style={{ fontSize: 10, color: "#636380", letterSpacing: "0.15em", marginBottom: 14 }}>HIGH SEVERITY MISSING</div>
                {results.missing.filter(h => h.severity === "HIGH").length === 0 ? (
                  <div style={{ color: "#30d158", fontSize: 12 }}>✓ None — good job!</div>
                ) : (
                  results.missing.filter(h => h.severity === "HIGH").map(h => (
                    <div key={h.header} style={{ fontSize: 11, color: "#ff6b6b", marginBottom: 5, fontFamily: "monospace" }}>
                      ✗ {h.header}
                    </div>
                  ))
                )}
              </div>
            </div>

            {/* Findings */}
            <div style={{
              background: "#070712",
              border: "1px solid #1e1e2e",
              borderRadius: 10,
              padding: 24,
            }}>
              <Section title="MISSING HEADERS" icon="❌" count={results.missing.length} defaultOpen={true}>
                {results.missing.map(h => <FindingRow key={h.header} item={h} type="missing" />)}
              </Section>

              <Section title="MISCONFIGURED HEADERS" icon="⚠️" count={results.warnings.length} defaultOpen={true}>
                {results.warnings.map(h => <FindingRow key={h.header + "_warn"} item={h} type="warning" />)}
              </Section>

              <Section title="INFORMATION LEAKAGE" icon="💧" count={results.leaking.length} defaultOpen={true}>
                {results.leaking.map(h => <FindingRow key={h.header} item={h} type="leak" />)}
              </Section>

              <Section title="PRESENT HEADERS" icon="✅" count={results.present.length} defaultOpen={false}>
                {results.present.map(h => <FindingRow key={h.header} item={h} type="pass" />)}
              </Section>

              <AIAnalysis findings={results} url={url} />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
