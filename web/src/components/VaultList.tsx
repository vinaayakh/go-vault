import { useCallback, useEffect, useRef, useState } from "react";
import { api } from "../api/client";
import type { Item, SyncResponse } from "../api/client";
import { useVault } from "../context/VaultContext";
import { ItemCard } from "./ItemCard";
import { AddItemModal } from "./AddItemModal";
import { PasswordGenerator } from "./PasswordGenerator";
import { TwoFactorSettings } from "./TwoFactorSettings";
import { ActivityView } from "./ActivityView";
import { ChangePasswordModal } from "./ChangePasswordModal";
import { buildExport, downloadExport, parseExportFile } from "../lib/vault-export";
import { getCrypto, toCryptoKdfParams } from "../crypto/service";

type SyncState = "loading" | "ready" | "error";
type SettingsTab = "security" | "activity" | "data";

export function VaultList() {
  const { lock, vaultKey } = useVault();
  const [items, setItems] = useState<Item[]>([]);
  const [sync, setSync] = useState<SyncResponse | null>(null);
  const [email, setEmail] = useState("");
  const [syncState, setSyncState] = useState<SyncState>("loading");
  const [error, setError] = useState("");
  const [showAdd, setShowAdd] = useState(false);
  const [showGenerator, setShowGenerator] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  const [settingsTab, setSettingsTab] = useState<SettingsTab>("security");
  const [showChangePassword, setShowChangePassword] = useState(false);
  const importRef = useRef<HTMLInputElement>(null);

  const loadItems = useCallback(async () => {
    setSyncState("loading");
    try {
      const data = await api.sync();
      setSync(data);
      setItems(data.items);
      setSyncState("ready");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setSyncState("error");
    }
  }, []);

  useEffect(() => { void loadItems(); }, [loadItems]);

  const handleLogout = async () => {
    try {
      await api.logout();
    } finally {
      lock();
    }
  };

  const handleExport = async () => {
    const data = await api.sync();
    const exportEmail = email || "vault@export.local";
    downloadExport(buildExport(exportEmail, data));
  };

  const handleImport = async (file: File) => {
    if (!vaultKey) return;
    const text = await file.text();
    const data = parseExportFile(text);
    const crypto = await getCrypto();
    const params = toCryptoKdfParams(data.kdf_params);
    const password = prompt("Enter master password for this export:");
    if (!password) return;
    const masterKey = crypto.deriveMasterKey(password, data.email, params);
    const { encKey } = crypto.stretchMasterKey(masterKey);
    const vk = crypto.unwrapVaultKey(data.protected_symmetric_key, encKey);
    if (data.items.length > 0) {
      crypto.openItem(data.items[0].ciphertext, vk);
    }
    const overwrite = confirm("Import items? OK = skip existing IDs, Cancel = abort");
    if (!overwrite) return;
    for (const item of data.items) {
      const exists = items.find((i) => i.id === item.id);
      if (exists) continue;
      await api.createItem({ item_type: item.item_type, ciphertext: item.ciphertext });
    }
    await loadItems();
  };

  const handleItemAdded = (item: Item) => {
    setItems((prev) => [...prev, item]);
    setShowAdd(false);
  };

  const handleItemDeleted = (id: string) => {
    setItems((prev) => prev.filter((i) => i.id !== id));
  };

  const handleItemUpdated = (updated: Item) => {
    setItems((prev) => prev.map((i) => (i.id === updated.id ? updated : i)));
  };

  return (
    <main style={{ fontFamily: "system-ui, sans-serif", padding: "1.5rem", maxWidth: "720px", margin: "0 auto" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.25rem" }}>
        <h1 style={{ margin: 0 }}>Secure Vault</h1>
        <div style={{ display: "flex", gap: "0.5rem", flexWrap: "wrap" }}>
          <button onClick={() => setShowGenerator((v) => !v)}>
            {showGenerator ? "Hide Generator" : "Generate Password"}
          </button>
          <button onClick={() => setShowAdd(true)}>+ Add Item</button>
          <button onClick={() => setShowSettings((v) => !v)}>Settings</button>
          <button onClick={handleLogout} style={{ color: "#555" }}>Log Out</button>
        </div>
      </div>

      {showSettings && (
        <section style={{ border: "1px solid #ddd", borderRadius: "8px", padding: "1rem", marginBottom: "1.25rem" }}>
          <div style={{ display: "flex", gap: "1rem", marginBottom: "1rem" }}>
            {(["security", "activity", "data"] as SettingsTab[]).map((tab) => (
              <button
                key={tab}
                onClick={() => setSettingsTab(tab)}
                style={{ fontWeight: settingsTab === tab ? "bold" : "normal" }}
              >
                {tab.charAt(0).toUpperCase() + tab.slice(1)}
              </button>
            ))}
          </div>
          {settingsTab === "security" && (
            <>
              <label style={{ display: "block", marginBottom: "0.75rem" }}>
                Account email (for export metadata)
                <input
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@example.com"
                  style={{ display: "block", width: "100%", padding: "0.5rem", marginTop: "0.25rem" }}
                />
              </label>
              <button onClick={() => setShowChangePassword(true)} style={{ marginBottom: "1rem" }}>
                Change master password
              </button>
              <TwoFactorSettings
                email={email || "user@vault.local"}
                totpEnabled={sync?.totp_enabled ?? false}
                protectedTotpSecret={sync?.protected_totp_secret}
                onChanged={loadItems}
              />
            </>
          )}
          {settingsTab === "activity" && <ActivityView />}
          {settingsTab === "data" && (
            <div>
              <button onClick={() => void handleExport()} style={{ marginRight: "0.5rem" }}>Export vault</button>
              <button onClick={() => importRef.current?.click()}>Import vault</button>
              <input
                ref={importRef}
                type="file"
                accept="application/json,.json"
                hidden
                onChange={(e) => {
                  const f = e.target.files?.[0];
                  if (f) void handleImport(f);
                  e.target.value = "";
                }}
              />
            </div>
          )}
        </section>
      )}

      {showGenerator && <PasswordGenerator />}

      {syncState === "loading" && <p>Loading vault…</p>}
      {syncState === "error" && <p style={{ color: "crimson" }}>Failed to load vault: {error}</p>}

      {syncState === "ready" && (
        <div style={{ marginTop: "1rem" }}>
          {items.length === 0 ? (
            <p style={{ color: "#666" }}>No items yet. Click "+ Add Item" to store your first secret.</p>
          ) : (
            items.map((item) => (
              <ItemCard
                key={item.id}
                item={item}
                onDeleted={handleItemDeleted}
                onUpdated={handleItemUpdated}
              />
            ))
          )}
        </div>
      )}

      {showAdd && <AddItemModal onAdded={handleItemAdded} onClose={() => setShowAdd(false)} />}
      {showChangePassword && (
        <ChangePasswordModal
          email={email || "user@vault.local"}
          items={items}
          onClose={() => setShowChangePassword(false)}
          onRotated={loadItems}
        />
      )}
    </main>
  );
}
