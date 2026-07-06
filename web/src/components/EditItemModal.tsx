import { useEffect, useState } from "react";
import { api } from "../api/client";
import type { Item } from "../api/client";
import { getCrypto } from "../crypto/service";
import type { PlainItem } from "../crypto/service";
import { useVault } from "../context/VaultContext";

interface Props {
  item: Item;
  onUpdated: (item: Item) => void;
  onClose: () => void;
}

export function EditItemModal({ item, onUpdated, onClose }: Props) {
  const { vaultKey } = useVault();
  const [name, setName] = useState("");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [url, setUrl] = useState("");
  const [notes, setNotes] = useState("");
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (!vaultKey) {
      setError("Vault is locked.");
      setLoading(false);
      return;
    }

    let cancelled = false;
    void (async () => {
      try {
        const crypto = await getCrypto();
        const plain = crypto.openItem(item.ciphertext, vaultKey);
        if (cancelled) return;
        setName(plain.name);
        setUsername(plain.username);
        setPassword(plain.password);
        setUrl(plain.url);
        setNotes(plain.notes);
        setLoading(false);
      } catch (err) {
        if (cancelled) return;
        setError(err instanceof Error ? err.message : String(err));
        setLoading(false);
      }
    })();

    return () => {
      cancelled = true;
    };
  }, [item.ciphertext, vaultKey]);

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!vaultKey) {
      setError("Vault is locked.");
      return;
    }
    setError("");
    setSaving(true);

    try {
      const crypto = await getCrypto();
      const plain: PlainItem = { name, username, password, url, notes, totp_seed: "" };
      const ciphertext = crypto.sealItem(plain, vaultKey);

      const updated = await api.updateItem(item.id, {
        ciphertext,
        current_revision: item.revision,
      });
      onUpdated(updated);
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.toLowerCase().includes("conflict") || message.includes("409")) {
        setError("This item was updated elsewhere. Refresh the vault and try again.");
      } else {
        setError(message);
      }
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
        <h2 style={{ marginTop: 0 }}>Edit Login</h2>
        {loading ? (
          <p>Decrypting item…</p>
        ) : (
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
              <button type="submit" disabled={saving || loading} style={{ padding: "0.4rem 1.2rem" }}>
                {saving ? "Encrypting…" : "Save"}
              </button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}
