import { useState } from "react";
import { api } from "../api/client";
import { getCrypto, toCryptoKdfParams, DEFAULT_KDF_PARAMS } from "../crypto/service";
import { useVault } from "../context/VaultContext";
import type { Item } from "../api/client";

interface Props {
  email: string;
  items: Item[];
  onClose: () => void;
  onRotated?: () => void;
}

export function ChangePasswordModal({ email, items, onClose, onRotated }: Props) {
  const { vaultKey, setVaultKey } = useVault();
  const [currentPassword, setCurrentPassword] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [rotateVaultKey, setRotateVaultKey] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!vaultKey) return;
    if (newPassword !== confirmPassword) {
      setError("New passwords do not match");
      return;
    }
    if (newPassword.length < 12) {
      setError("New password must be at least 12 characters");
      return;
    }

    setBusy(true);
    setError("");
    try {
      const crypto = await getCrypto();
      const sync = await api.sync();
      const oldParams = toCryptoKdfParams(sync.kdf_params);
      const masterKeyB64 = crypto.deriveMasterKey(currentPassword, email, oldParams);
      const { encKey: encKeyB64 } = crypto.stretchMasterKey(masterKeyB64);
      const currentVaultKey = crypto.unwrapVaultKey(sync.protected_symmetric_key, encKeyB64);

      const newVaultKey = rotateVaultKey ? crypto.newVaultKey() : currentVaultKey;
      const newMasterKeyB64 = crypto.deriveMasterKey(newPassword, email, DEFAULT_KDF_PARAMS);
      const { encKey: newEncKeyB64 } = crypto.stretchMasterKey(newMasterKeyB64);
      const newAuthHash = crypto.deriveAuthHash(newMasterKeyB64, newPassword, DEFAULT_KDF_PARAMS);
      const newProtected = crypto.wrapVaultKey(newVaultKey, newEncKeyB64);

      if (rotateVaultKey) {
        for (const item of items) {
          const plain = crypto.openItem(item.ciphertext, currentVaultKey);
          const newCt = crypto.sealItem(plain, newVaultKey);
          await api.updateItem(item.id, {
            ciphertext: newCt,
            current_revision: item.revision,
            item_type: item.item_type,
          });
        }
      }

      await api.updateKey({
        auth_hash: newAuthHash,
        kdf_params: DEFAULT_KDF_PARAMS,
        protected_symmetric_key: newProtected,
      });

      setVaultKey(newVaultKey);
      setCurrentPassword("");
      setNewPassword("");
      setConfirmPassword("");
      onRotated?.();
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div
      role="dialog"
      style={{
        position: "fixed", inset: 0, background: "rgba(0,0,0,0.4)",
        display: "flex", alignItems: "center", justifyContent: "center", zIndex: 100,
      }}
      onClick={onClose}
    >
      <form
        onSubmit={handleSubmit}
        onClick={(e) => e.stopPropagation()}
        style={{ background: "#fff", padding: "1.5rem", borderRadius: "8px", maxWidth: "420px", width: "100%" }}
      >
        <h2 style={{ marginTop: 0 }}>Change master password</h2>
        <label style={{ display: "block", marginBottom: "0.75rem" }}>
          Current password
          <input type="password" value={currentPassword} onChange={(e) => setCurrentPassword(e.target.value)} required disabled={busy}
            style={{ display: "block", width: "100%", padding: "0.5rem", marginTop: "0.25rem" }} />
        </label>
        <label style={{ display: "block", marginBottom: "0.75rem" }}>
          New password
          <input type="password" value={newPassword} onChange={(e) => setNewPassword(e.target.value)} required disabled={busy}
            style={{ display: "block", width: "100%", padding: "0.5rem", marginTop: "0.25rem" }} />
        </label>
        <label style={{ display: "block", marginBottom: "0.75rem" }}>
          Confirm new password
          <input type="password" value={confirmPassword} onChange={(e) => setConfirmPassword(e.target.value)} required disabled={busy}
            style={{ display: "block", width: "100%", padding: "0.5rem", marginTop: "0.25rem" }} />
        </label>
        <label style={{ display: "flex", gap: "0.5rem", marginBottom: "1rem", alignItems: "center" }}>
          <input type="checkbox" checked={rotateVaultKey} onChange={(e) => setRotateVaultKey(e.target.checked)} disabled={busy} />
          Rotate vault key (re-encrypt all items)
        </label>
        {error && <p style={{ color: "crimson" }}>{error}</p>}
        <div style={{ display: "flex", gap: "0.5rem" }}>
          <button type="submit" disabled={busy}>{busy ? "Updating…" : "Update password"}</button>
          <button type="button" onClick={onClose} disabled={busy}>Cancel</button>
        </div>
      </form>
    </div>
  );
}
