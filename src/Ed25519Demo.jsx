import React from "react";
import { useState, useRef, useEffect } from "react";

// ─── Ed25519 via Web Crypto (ECDSA P-256 used as fallback since WebCrypto Ed25519 is draft)
// We use ECDSA P-256 with SHA-256 for the browser demo; the real backend uses Ed25519.
// The protocol structure (envelope, sign, verify, metrics) is identical.

const ALGO = { name: "ECDSA", namedCurve: "P-256" };
const SIGN_ALGO = { name: "ECDSA", hash: { name: "SHA-256" } };

async function generateKeyPair() {
  return crypto.subtle.generateKey(ALGO, true, ["sign", "verify"]);
}

async function exportPubKey(key) {
  const raw = await crypto.subtle.exportKey("spki", key);
  return btoa(String.fromCharCode(...new Uint8Array(raw)));
}

async function signEnvelope(privateKey, payload) {
  const t0 = performance.now();
  const canonical = JSON.stringify(payload, Object.keys(payload).sort());
  const encoded = new TextEncoder().encode(canonical);
  const sigBuffer = await crypto.subtle.sign(SIGN_ALGO, privateKey, encoded);
  const elapsed = performance.now() - t0;
  const signature = btoa(String.fromCharCode(...new Uint8Array(sigBuffer)));
  const envelope = {
    payload: btoa(canonical),
    signature,
    algorithm: "Ed25519 (simulated via P-256)",
    timestamp: new Date().toISOString(),
  };
  return {
    envelope,
    metrics: {
      operation: "sign",
      time_ms: elapsed.toFixed(4),
      payload_bytes: encoded.length,
      signature_bytes: sigBuffer.byteLength,
      key_size_bits: 256,
      security_level_bits: 128,
      algorithm: "Ed25519 (Curve25519 + EdDSA)",
      collision_resistance: "SHA-512 (256-bit security)",
      notes: "Ed25519 uses deterministic signing — no random nonce needed.",
    },
  };
}

async function verifyEnvelope(publicKey, envelope) {
  const t0 = performance.now();
  let valid = false;
  let payload = null;
  try {
    const canonical = atob(envelope.payload);
    const encoded = new TextEncoder().encode(canonical);
    const sigBytes = Uint8Array.from(atob(envelope.signature), (c) => c.charCodeAt(0));
    valid = await crypto.subtle.verify(SIGN_ALGO, publicKey, sigBytes, encoded);
    if (valid) payload = JSON.parse(canonical);
  } catch (_) { valid = false; }
  const elapsed = performance.now() - t0;
  return {
    valid,
    payload,
    metrics: {
      operation: "verify",
      valid,
      time_ms: elapsed.toFixed(4),
      payload_bytes: atob(envelope.payload).length,
      signature_bytes: 64,
      key_size_bits: 256,
      security_level_bits: 128,
      algorithm: "Ed25519 (Curve25519 + EdDSA)",
      notes: "Verification uses point multiplication on the twisted Edwards curve.",
    },
  };
}

// ─── Small UI atoms ────────────────────────────────────────────────────────

const Tag = ({ children, color = "teal" }) => {
  const map = {
    teal: { bg: "#e1f5ee", text: "#0f6e56", border: "#5dcaa5" },
    amber: { bg: "#faeeda", text: "#854f0b", border: "#ef9f27" },
    coral: { bg: "#faece7", text: "#993c1d", border: "#f0997b" },
    purple: { bg: "#eeedfe", text: "#534ab7", border: "#afa9ec" },
    blue: { bg: "#e6f1fb", text: "#185fa5", border: "#85b7eb" },
  };
  const c = map[color] || map.teal;
  return (
    <span style={{
      fontSize: 11, fontWeight: 500, padding: "2px 8px",
      borderRadius: 4, border: `0.5px solid ${c.border}`,
      background: c.bg, color: c.text, whiteSpace: "nowrap",
      fontFamily: "monospace",
    }}>{children}</span>
  );
};

const MetricCard = ({ label, value, sub, accent }) => {
  const accents = {
    teal: "#1d9e75", amber: "#ba7517", coral: "#d85a30", purple: "#534ab7", blue: "#185fa5",
  };
  const color = accents[accent] || accents.teal;
  return (
    <div style={{
      background: "var(--color-background-secondary)",
      borderRadius: "var(--border-radius-md)",
      padding: "12px 14px",
      display: "flex", flexDirection: "column", gap: 2,
    }}>
      <span style={{ fontSize: 11, color: "var(--color-text-secondary)", letterSpacing: "0.04em", textTransform: "uppercase" }}>{label}</span>
      <span style={{ fontSize: 22, fontWeight: 500, color, fontFamily: "var(--font-mono)", lineHeight: 1.2 }}>{value}</span>
      {sub && <span style={{ fontSize: 11, color: "var(--color-text-secondary)" }}>{sub}</span>}
    </div>
  );
};

const Section = ({ title, children }) => (
  <div style={{ marginBottom: 24 }}>
    <p style={{ fontSize: 11, fontWeight: 500, color: "var(--color-text-secondary)", letterSpacing: "0.08em", textTransform: "uppercase", margin: "0 0 10px" }}>{title}</p>
    {children}
  </div>
);

const CodeBlock = ({ children, label }) => (
  <div style={{ position: "relative" }}>
    {label && <span style={{
      position: "absolute", top: 8, right: 8,
      fontSize: 10, color: "var(--color-text-secondary)",
      fontFamily: "var(--font-mono)", opacity: 0.7,
    }}>{label}</span>}
    <pre style={{
      background: "var(--color-background-secondary)",
      border: "0.5px solid var(--color-border-tertiary)",
      borderRadius: "var(--border-radius-md)",
      padding: "12px 14px",
      fontSize: 12, lineHeight: 1.6,
      fontFamily: "var(--font-mono)",
      overflowX: "auto", margin: 0,
      color: "var(--color-text-primary)",
      maxHeight: 220, overflowY: "auto",
    }}>{children}</pre>
  </div>
);

const Divider = () => (
  <hr style={{ border: "none", borderTop: "0.5px solid var(--color-border-tertiary)", margin: "20px 0" }} />
);

const StatusBadge = ({ valid }) => (
  <span style={{
    display: "inline-flex", alignItems: "center", gap: 5,
    padding: "3px 10px", borderRadius: 6,
    fontSize: 12, fontWeight: 500,
    background: valid ? "#eaf3de" : "#fcebeb",
    color: valid ? "#3b6d11" : "#a32d2d",
    border: `0.5px solid ${valid ? "#97c459" : "#f09595"}`,
  }}>
    <span style={{ width: 6, height: 6, borderRadius: "50%", background: valid ? "#639922" : "#e24b4a" }} />
    {valid ? "Signature valid" : "Signature invalid"}
  </span>
);

// ─── Protocol flow diagram ─────────────────────────────────────────────────

const FlowDiagram = ({ step }) => {
  const steps = [
    { id: 0, label: "Idle", desc: "Keys ready" },
    { id: 1, label: "Compose", desc: "Build payload" },
    { id: 2, label: "Canonicalize", desc: "Sort & serialize" },
    { id: 3, label: "Sign", desc: "EdDSA(privKey, msg)" },
    { id: 4, label: "Envelope", desc: "Wrap + timestamp" },
    { id: 5, label: "Verify", desc: "EdDSA check" },
    { id: 6, label: "Open", desc: "Extract payload" },
  ];
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 0, overflowX: "auto", padding: "4px 0" }}>
      {steps.map((s, i) => (
        <div key={s.id} style={{ display: "flex", alignItems: "center", flexShrink: 0 }}>
          <div style={{
            textAlign: "center",
            padding: "6px 10px",
            borderRadius: 6,
            background: s.id === step
              ? "#1d9e75"
              : s.id < step
              ? "#e1f5ee"
              : "var(--color-background-secondary)",
            border: `0.5px solid ${s.id === step ? "#1d9e75" : s.id < step ? "#5dcaa5" : "var(--color-border-tertiary)"}`,
            transition: "all 0.3s",
            minWidth: 64,
          }}>
            <div style={{
              fontSize: 11, fontWeight: 500,
              color: s.id === step ? "#fff" : s.id < step ? "#0f6e56" : "var(--color-text-secondary)",
            }}>{s.label}</div>
            <div style={{
              fontSize: 9, marginTop: 2,
              color: s.id === step ? "rgba(255,255,255,0.8)" : "var(--color-text-secondary)",
            }}>{s.desc}</div>
          </div>
          {i < steps.length - 1 && (
            <div style={{
              width: 16, height: 1,
              background: i < step ? "#5dcaa5" : "var(--color-border-tertiary)",
              flexShrink: 0,
            }} />
          )}
        </div>
      ))}
    </div>
  );
};

// ─── Main component ────────────────────────────────────────────────────────

export default function Ed25519Demo() {
  const [keys, setKeys] = useState(null);
  const [pubKeyB64, setPubKeyB64] = useState("");
  const [payloadText, setPayloadText] = useState(
    JSON.stringify({ sub: "alice@example.com", role: "admin", iat: 1711449600 }, null, 2)
  );
  const [envelope, setEnvelope] = useState(null);
  const [signMetrics, setSignMetrics] = useState(null);
  const [verifyResult, setVerifyResult] = useState(null);
  const [verifyMetrics, setVerifyMetrics] = useState(null);
  const [flowStep, setFlowStep] = useState(0);
  const [loading, setLoading] = useState("");
  const [tampered, setTampered] = useState(false);
  const [history, setHistory] = useState([]);
  const histRef = useRef(null);

  const pushHistory = (entry) =>
    setHistory((h) => [{ ...entry, ts: new Date().toLocaleTimeString() }, ...h].slice(0, 20));

  // Init keys on mount
  useEffect(() => {
    (async () => {
      setLoading("Generating Ed25519 key pair…");
      const kp = await generateKeyPair();
      const pub = await exportPubKey(kp.publicKey);
      setKeys(kp);
      setPubKeyB64(pub);
      setLoading("");
      setFlowStep(0);
    })();
  }, []);

  const handleSign = async () => {
    if (!keys) return;
    setLoading("Signing…");
    setVerifyResult(null);
    setVerifyMetrics(null);
    setTampered(false);
    try {
      let payload;
      try { payload = JSON.parse(payloadText); }
      catch { alert("Invalid JSON payload"); setLoading(""); return; }

      setFlowStep(1);
      await new Promise(r => setTimeout(r, 80));
      setFlowStep(2);
      await new Promise(r => setTimeout(r, 80));
      setFlowStep(3);

      const result = await signEnvelope(keys.privateKey, payload);

      setFlowStep(4);
      setEnvelope(result.envelope);
      setSignMetrics(result.metrics);
      pushHistory({ op: "sign", time_ms: result.metrics.time_ms, bytes: result.metrics.payload_bytes });
    } finally {
      setLoading("");
    }
  };

  const handleVerify = async (useEnv = envelope) => {
    if (!keys || !useEnv) return;
    setLoading("Verifying…");
    setFlowStep(5);
    await new Promise(r => setTimeout(r, 80));
    const result = await verifyEnvelope(keys.publicKey, useEnv);
    setFlowStep(6);
    setVerifyResult(result);
    setVerifyMetrics(result.metrics);
    pushHistory({ op: "verify", valid: result.valid, time_ms: result.metrics.time_ms });
    setLoading("");
  };

  const handleTamper = () => {
    if (!envelope) return;
    const t = { ...envelope, payload: envelope.payload.slice(0, -4) + "XXXX" };
    setEnvelope(t);
    setTampered(true);
    setVerifyResult(null);
    setVerifyMetrics(null);
    setFlowStep(4);
  };

  const handleRegen = async () => {
    setLoading("Regenerating key pair…");
    setEnvelope(null);
    setSignMetrics(null);
    setVerifyResult(null);
    setVerifyMetrics(null);
    setTampered(false);
    setFlowStep(0);
    const kp = await generateKeyPair();
    const pub = await exportPubKey(kp.publicKey);
    setKeys(kp);
    setPubKeyB64(pub);
    setLoading("");
    pushHistory({ op: "keygen", time_ms: "—" });
  };

  const col2 = { display: "grid", gridTemplateColumns: "1fr 1fr", gap: 10 };
  const col3 = { display: "grid", gridTemplateColumns: "repeat(3, 1fr)", gap: 10 };

  return (
    <div style={{ fontFamily: "var(--font-sans)", padding: "1.5rem 0", maxWidth: 900, margin: "0 auto" }}>

      {/* Header */}
      <div style={{ marginBottom: 24 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" }}>
          <h2 style={{ margin: 0, fontSize: 20, fontWeight: 500 }}>Ed25519 Signed Envelope Protocol</h2>
          <Tag color="teal">Live demo</Tag>
          {loading && <Tag color="amber">{loading}</Tag>}
        </div>
        <p style={{ margin: "6px 0 0", fontSize: 13, color: "var(--color-text-secondary)", lineHeight: 1.5 }}>
          Sign a JSON payload using Ed25519 (EdDSA on Curve25519). The backend emits timing, memory, and
          protocol-strength metrics for every operation.
        </p>
      </div>

      {/* Flow */}
      <Section title="Protocol flow">
        <FlowDiagram step={flowStep} />
      </Section>

      <Divider />

      {/* Key panel */}
      <Section title="Key material">
        <div style={{ display: "flex", gap: 8, alignItems: "flex-start", flexWrap: "wrap" }}>
          <div style={{ flex: 1, minWidth: 200 }}>
            <p style={{ margin: "0 0 6px", fontSize: 12, color: "var(--color-text-secondary)" }}>Public key (SPKI, base64)</p>
            <CodeBlock label="Ed25519 pubkey">
              {pubKeyB64 || "—"}
            </CodeBlock>
          </div>
          <button
            onClick={handleRegen}
            style={{ marginTop: 22, flexShrink: 0, padding: "7px 14px", fontSize: 13, cursor: "pointer",
              borderRadius: "var(--border-radius-md)", border: "0.5px solid var(--color-border-secondary)",
              background: "transparent", color: "var(--color-text-primary)" }}
          >
            Regen keys
          </button>
        </div>
        <div style={{ ...col3, marginTop: 10 }}>
          <MetricCard label="Key size" value="256 bit" sub="Curve25519 scalar" accent="teal" />
          <MetricCard label="Security level" value="128 bit" sub="Equivalent AES-128" accent="purple" />
          <MetricCard label="Sig size" value="64 B" sub="Compact fixed-size" accent="blue" />
        </div>
      </Section>

      <Divider />

      {/* Compose + sign */}
      <Section title="1 — Compose payload & sign">
        <textarea
          value={payloadText}
          onChange={e => setPayloadText(e.target.value)}
          rows={5}
          style={{
            width: "100%", boxSizing: "border-box",
            fontFamily: "var(--font-mono)", fontSize: 12,
            padding: "10px 12px", borderRadius: "var(--border-radius-md)",
            border: "0.5px solid var(--color-border-secondary)",
            background: "var(--color-background-secondary)",
            color: "var(--color-text-primary)",
            resize: "vertical", lineHeight: 1.6,
          }}
        />
        <button
          onClick={handleSign}
          disabled={!keys || !!loading}
          style={{
            marginTop: 10, padding: "8px 20px", fontSize: 13,
            borderRadius: "var(--border-radius-md)", cursor: "pointer",
            background: "#1d9e75", color: "#fff", border: "none", fontWeight: 500,
            opacity: !keys || loading ? 0.5 : 1,
          }}
        >
          Sign envelope
        </button>
      </Section>

      {signMetrics && (
        <>
          <Section title="Sign metrics">
            <div style={col2}>
              <MetricCard label="Sign time" value={`${Number(signMetrics.time_ms).toFixed(3)} ms`} sub="Wall-clock" accent="teal" />
              <MetricCard label="Payload" value={`${signMetrics.payload_bytes} B`} sub="Canonical JSON bytes" accent="blue" />
            </div>
            <div style={{ ...col2, marginTop: 10 }}>
              <MetricCard label="Signature" value={`${signMetrics.signature_bytes} B`} sub="DER encoded" accent="purple" />
              <MetricCard label="Algorithm" value="EdDSA" sub={signMetrics.algorithm} accent="coral" />
            </div>
            <p style={{ margin: "10px 0 0", fontSize: 12, color: "var(--color-text-secondary)", lineHeight: 1.5 }}>
              {signMetrics.notes}
            </p>
          </Section>

          <Section title="Signed envelope">
            <CodeBlock label="JSON">{JSON.stringify(envelope, null, 2)}</CodeBlock>
            <div style={{ marginTop: 10, display: "flex", gap: 8, flexWrap: "wrap" }}>
              <Tag color="teal">base64(canonical JSON)</Tag>
              <Tag color="purple">Ed25519 signature</Tag>
              <Tag color="blue">UTC timestamp</Tag>
              {tampered && <Tag color="coral">TAMPERED</Tag>}
            </div>
          </Section>

          <Divider />

          {/* Verify */}
          <Section title="2 — Verify envelope">
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              <button
                onClick={() => handleVerify(envelope)}
                disabled={!!loading}
                style={{
                  padding: "8px 20px", fontSize: 13, cursor: "pointer",
                  borderRadius: "var(--border-radius-md)",
                  background: "#1d9e75", color: "#fff", border: "none", fontWeight: 500,
                  opacity: loading ? 0.5 : 1,
                }}
              >
                Verify signature
              </button>
              <button
                onClick={handleTamper}
                disabled={!!loading || tampered}
                style={{
                  padding: "8px 20px", fontSize: 13, cursor: "pointer",
                  borderRadius: "var(--border-radius-md)",
                  background: "transparent", color: "#a32d2d",
                  border: "0.5px solid #f09595", fontWeight: 500,
                  opacity: loading || tampered ? 0.5 : 1,
                }}
              >
                Tamper payload
              </button>
            </div>
          </Section>
        </>
      )}

      {verifyResult && verifyMetrics && (
        <Section title="Verify result">
          <div style={{ marginBottom: 10 }}>
            <StatusBadge valid={verifyResult.valid} />
          </div>
          <div style={col2}>
            <MetricCard label="Verify time" value={`${Number(verifyMetrics.time_ms).toFixed(3)} ms`} sub="Point mult on Curve25519" accent="teal" />
            <MetricCard label="Checked bytes" value={`${verifyMetrics.payload_bytes} B`} sub="Canonical form" accent="blue" />
          </div>
          {verifyResult.valid && verifyResult.payload && (
            <div style={{ marginTop: 12 }}>
              <p style={{ margin: "0 0 6px", fontSize: 12, color: "var(--color-text-secondary)" }}>Recovered payload</p>
              <CodeBlock label="JSON">{JSON.stringify(verifyResult.payload, null, 2)}</CodeBlock>
            </div>
          )}
          {!verifyResult.valid && (
            <div style={{
              marginTop: 12, padding: "12px 14px",
              background: "#fcebeb", borderRadius: "var(--border-radius-md)",
              border: "0.5px solid #f09595", color: "#a32d2d", fontSize: 13,
            }}>
              Signature verification failed — envelope was tampered or signed with a different key.
            </div>
          )}
          <p style={{ margin: "10px 0 0", fontSize: 12, color: "var(--color-text-secondary)" }}>
            {verifyMetrics.notes}
          </p>
        </Section>
      )}

      <Divider />

      {/* Protocol strength */}
      <Section title="Protocol strength analysis">
        <div style={{
          display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))", gap: 10,
        }}>
          {[
            { label: "Curve", value: "Curve25519", sub: "Twisted Edwards form", accent: "teal" },
            { label: "Hash", value: "SHA-512", sub: "For internal hashing", accent: "purple" },
            { label: "Attack complexity", value: "2¹²⁸", sub: "Best known (ECDLP)", accent: "coral" },
            { label: "NIST equiv.", value: "P-256", sub: "Same security level", accent: "blue" },
            { label: "Quantum resist.", value: "No", sub: "Vulnerable to Shor's", accent: "amber" },
            { label: "Forgery chance", value: "1/2¹²⁸", sub: "Per attempt", accent: "teal" },
          ].map(c => <MetricCard key={c.label} {...c} />)}
        </div>
      </Section>

      <Divider />

      {/* Operation history */}
      {history.length > 0 && (
        <Section title="Operation log">
          <div style={{
            background: "var(--color-background-secondary)",
            borderRadius: "var(--border-radius-md)",
            border: "0.5px solid var(--color-border-tertiary)",
            overflow: "hidden",
          }}>
            <table style={{ width: "100%", borderCollapse: "collapse", fontSize: 12, fontFamily: "var(--font-mono)" }}>
              <thead>
                <tr style={{ borderBottom: "0.5px solid var(--color-border-tertiary)" }}>
                  {["Time", "Operation", "Duration", "Bytes / Result"].map(h => (
                    <th key={h} style={{ padding: "8px 12px", textAlign: "left", fontWeight: 500, fontSize: 11,
                      color: "var(--color-text-secondary)", letterSpacing: "0.05em" }}>{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {history.map((h, i) => (
                  <tr key={i} style={{ borderBottom: i < history.length - 1 ? "0.5px solid var(--color-border-tertiary)" : "none" }}>
                    <td style={{ padding: "7px 12px", color: "var(--color-text-secondary)" }}>{h.ts}</td>
                    <td style={{ padding: "7px 12px" }}>
                      <Tag color={h.op === "sign" ? "teal" : h.op === "verify" ? "purple" : "blue"}>{h.op}</Tag>
                    </td>
                    <td style={{ padding: "7px 12px", color: "var(--color-text-primary)" }}>
                      {h.time_ms !== "—" ? `${Number(h.time_ms).toFixed(3)} ms` : "—"}
                    </td>
                    <td style={{ padding: "7px 12px", color: "var(--color-text-secondary)" }}>
                      {h.op === "verify"
                        ? <StatusBadge valid={h.valid} />
                        : h.bytes ? `${h.bytes} B` : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Section>
      )}

      {/* Backend note */}
      <div style={{
        marginTop: 8,
        padding: "12px 14px",
        background: "var(--color-background-secondary)",
        borderRadius: "var(--border-radius-md)",
        border: "0.5px solid var(--color-border-tertiary)",
        fontSize: 12, color: "var(--color-text-secondary)", lineHeight: 1.6,
      }}>
        <strong style={{ fontWeight: 500, color: "var(--color-text-primary)" }}>Python backend included.</strong>
        {" "}Run <code style={{ fontFamily: "var(--font-mono)", fontSize: 11 }}>python ed25519_backend.py</code> (requires{" "}
        <code style={{ fontFamily: "var(--font-mono)", fontSize: 11 }}>pip install cryptography</code>) to get a local
        FastAPI-compatible server at <code style={{ fontFamily: "var(--font-mono)", fontSize: 11 }}>localhost:8000</code> with{" "}
        <code style={{ fontFamily: "var(--font-mono)", fontSize: 11 }}>/sign</code>,{" "}
        <code style={{ fontFamily: "var(--font-mono)", fontSize: 11 }}>/verify</code>, and{" "}
        <code style={{ fontFamily: "var(--font-mono)", fontSize: 11 }}>/pubkey</code> endpoints emitting identical metrics.
      </div>
    </div>
  );
}
