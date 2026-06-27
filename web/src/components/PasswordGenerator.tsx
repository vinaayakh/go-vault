import { useState } from "react";
import { getCrypto } from "../crypto/service";

export function PasswordGenerator() {
  const [length, setLength] = useState(20);
  const [uppercase, setUppercase] = useState(true);
  const [lowercase, setLowercase] = useState(true);
  const [digits, setDigits] = useState(true);
  const [symbols, setSymbols] = useState(false);
  const [generated, setGenerated] = useState("");
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState("");

  const generate = async () => {
    setError("");
    if (!uppercase && !lowercase && !digits && !symbols) {
      setError("Select at least one character class.");
      return;
    }
    try {
      const crypto = await getCrypto();
      setGenerated(crypto.generatePassword(length, uppercase, lowercase, digits, symbols));
      setCopied(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const copy = async () => {
    if (!generated) return;
    await navigator.clipboard.writeText(generated);
    setCopied(true);
    setTimeout(() => {
      navigator.clipboard.writeText("").catch(() => {});
      setCopied(false);
      setGenerated("");
    }, 30_000);
  };

  return (
    <div style={{ border: "1px solid #ddd", borderRadius: "6px", padding: "1rem", marginTop: "1rem" }}>
      <h3 style={{ marginTop: 0 }}>Password Generator</h3>
      <div style={{ display: "flex", flexWrap: "wrap", gap: "0.75rem", alignItems: "center", marginBottom: "0.75rem" }}>
        <label>
          Length:&nbsp;
          <input
            type="number"
            min={8}
            max={128}
            value={length}
            onChange={(e) => setLength(Math.max(8, Math.min(128, Number(e.target.value))))}
            style={{ width: "4rem", padding: "0.25rem" }}
          />
        </label>
        <label><input type="checkbox" checked={uppercase} onChange={e => setUppercase(e.target.checked)} /> A–Z</label>
        <label><input type="checkbox" checked={lowercase} onChange={e => setLowercase(e.target.checked)} /> a–z</label>
        <label><input type="checkbox" checked={digits} onChange={e => setDigits(e.target.checked)} /> 0–9</label>
        <label><input type="checkbox" checked={symbols} onChange={e => setSymbols(e.target.checked)} /> !@#…</label>
        <button onClick={generate} style={{ padding: "0.25rem 0.75rem" }}>Generate</button>
      </div>
      {error && <p style={{ color: "crimson", margin: "0.25rem 0" }}>{error}</p>}
      {generated && (
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
          <code style={{ flex: 1, background: "#f5f5f5", padding: "0.4rem 0.6rem", borderRadius: "4px", wordBreak: "break-all" }}>
            {generated}
          </code>
          <button onClick={copy} style={{ whiteSpace: "nowrap" }}>
            {copied ? "Copied! (30s)" : "Copy"}
          </button>
        </div>
      )}
    </div>
  );
}
