import { useState } from "react";
import { api } from "../api/client";
import type { Item } from "../api/client";
import { getCrypto } from "../crypto/service";
import type { PlainItem } from "../crypto/service";
import { useVault } from "../context/VaultContext";

interface Props {
  onAdded: (item: Item) => void;
  onClose: () => void;
}

export function AddItemModal({ onAdded, onClose }: Props) {
  const { vaultKey } = useVault();
  const [name, setName] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [url, setUrl] = useState("");
  const [notes, setNotes] = useState("");
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!vaultKey) { setError("Vault is locked."); return; }
    setError("");
    setSaving(true);

    try {
      const crypto = await getCrypto();
      const plain: PlainItem = { name, username, password, url, notes, totp_seed: "" };
      const ciphertext = crypto.sealItem(plain, vaultKey);

      const item = await api.createItem({ item_type: "login", ciphertext });
      onAdded(item);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setSaving(false);
    }
  };

  const inputStyle = {
    display: "block",
    width: "100%",
    padding: "0.4rem",
    marginTop: "0.2rem",
    boxSizing: "border-box" as const,
  };

  return (
    <div
      style={{
        position: "fixed",
        inset: 0,
        background: "rgba(0,0,0,0.4)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 10,
      }}
    >
      <div
        style={{
          background: "#fff",
          borderRadius: "8px",
          padding: "1.5rem",
          width: "100%",
          maxWidth: "480px",
          boxShadow: "0 4px 20px rgba(0,0,0,0.2)",
        }}
      >
        <h2 style={{ marginTop: 0 }}>Add Login</h2>
        <form onSubmit={handleSubmit}>
          <div style={{ marginBottom: "0.75rem" }}>
            <label>Name *<input type="text" value={name} onChange={e => setName(e.target.value)} required disabled={saving} style={inputStyle} /></label>
          </div>
          <div style={{ marginBottom: "0.75rem" }}>
            <label>Username<input type="text" value={username} onChange={e => setUsername(e.target.value)} disabled={saving} autoComplete="off" style={inputStyle} /></label>
          </div>
          <div style={{ marginBottom: "0.75rem" }}>
            <label>Password<input type="password" value={password} onChange={e => setPassword(e.target.value)} disabled={saving} autoComplete="new-password" style={inputStyle} /></label>
          </div>
          <div style={{ marginBottom: "0.75rem" }}>
            <label>URL<input type="url" value={url} onChange={e => setUrl(e.target.value)} disabled={saving} style={inputStyle} /></label>
          </div>
          <div style={{ marginBottom: "0.75rem" }}>
            <label>Notes<textarea value={notes} onChange={e => setNotes(e.target.value)} disabled={saving} rows={3} style={{ ...inputStyle, resize: "vertical" }} /></label>
          </div>
          {error && <p style={{ color: "crimson", margin: "0.5rem 0" }}>{error}</p>}
          <div style={{ display: "flex", gap: "0.5rem", justifyContent: "flex-end", marginTop: "1rem" }}>
            <button type="button" onClick={onClose} disabled={saving}>Cancel</button>
            <button type="submit" disabled={saving} style={{ padding: "0.4rem 1.2rem" }}>
              {saving ? "Encrypting…" : "Save"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
