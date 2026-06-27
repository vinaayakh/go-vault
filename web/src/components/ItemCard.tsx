import { useState } from "react";
import { api } from "../api/client";
import { getCrypto } from "../crypto/service";
import type { PlainItem } from "../crypto/service";
import type { Item } from "../api/client";
import { useVault } from "../context/VaultContext";

interface Props {
  item: Item;
  onDeleted: (id: string) => void;
}

type RevealState = "hidden" | "revealing" | "shown" | "error";

export function ItemCard({ item, onDeleted }: Props) {
  const { vaultKey } = useVault();
  const [revealState, setRevealState] = useState<RevealState>("hidden");
  const [plain, setPlain] = useState<PlainItem | null>(null);
  const [copied, setCopied] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [error, setError] = useState("");

  const handleReveal = async () => {
    if (!vaultKey) return;
    if (revealState === "shown") {
      setRevealState("hidden");
      setPlain(null);
      return;
    }
    setRevealState("revealing");
    try {
      const crypto = await getCrypto();
      const decrypted = crypto.openItem(item.ciphertext, vaultKey);
      setPlain(decrypted);
      setRevealState("shown");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setRevealState("error");
    }
  };

  const copyPassword = async () => {
    if (!plain?.password) return;
    await navigator.clipboard.writeText(plain.password);
    setCopied(true);
    // Clear clipboard after 30 seconds.
    setTimeout(() => {
      navigator.clipboard.writeText("").catch(() => {});
      setCopied(false);
    }, 30_000);
  };

  const handleDelete = async () => {
    if (!confirm("Delete this item? This cannot be undone.")) return;
    setDeleting(true);
    try {
      await api.deleteItem(item.id);
      onDeleted(item.id);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setDeleting(false);
    }
  };

  return (
    <div
      style={{
        border: "1px solid #ddd",
        borderRadius: "6px",
        padding: "1rem",
        marginBottom: "0.75rem",
      }}
    >
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div>
          <strong>{plain?.name ?? `[${item.item_type}]`}</strong>
          {plain?.username && (
            <span style={{ color: "#555", marginLeft: "0.5rem" }}>{plain.username}</span>
          )}
          {plain?.url && (
            <span style={{ color: "#888", marginLeft: "0.5rem", fontSize: "0.85rem" }}>{plain.url}</span>
          )}
        </div>
        <div style={{ display: "flex", gap: "0.5rem" }}>
          <button onClick={handleReveal} disabled={revealState === "revealing" || deleting}>
            {revealState === "shown" ? "Hide" : revealState === "revealing" ? "…" : "Reveal"}
          </button>
          <button onClick={handleDelete} disabled={deleting} style={{ color: "crimson" }}>
            {deleting ? "Deleting…" : "Delete"}
          </button>
        </div>
      </div>

      {revealState === "shown" && plain && (
        <div style={{ marginTop: "0.75rem", paddingTop: "0.75rem", borderTop: "1px solid #eee" }}>
          {plain.name && <p style={{ margin: "0.25rem 0" }}><strong>Name:</strong> {plain.name}</p>}
          {plain.username && <p style={{ margin: "0.25rem 0" }}><strong>Username:</strong> {plain.username}</p>}
          {plain.password && (
            <p style={{ margin: "0.25rem 0", display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <strong>Password:</strong>
              <span style={{ fontFamily: "monospace" }}>{"•".repeat(plain.password.length)}</span>
              <button onClick={copyPassword} style={{ fontSize: "0.8rem" }}>
                {copied ? "Copied! (clears in 30s)" : "Copy"}
              </button>
            </p>
          )}
          {plain.url && <p style={{ margin: "0.25rem 0" }}><strong>URL:</strong> {plain.url}</p>}
          {plain.notes && <p style={{ margin: "0.25rem 0" }}><strong>Notes:</strong> {plain.notes}</p>}
        </div>
      )}

      {error && <p style={{ color: "crimson", marginTop: "0.5rem", fontSize: "0.9rem" }}>{error}</p>}
    </div>
  );
}
