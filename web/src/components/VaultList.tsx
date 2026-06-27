import { useCallback, useEffect, useState } from "react";
import { api } from "../api/client";
import type { Item } from "../api/client";
import { useVault } from "../context/VaultContext";
import { ItemCard } from "./ItemCard";
import { AddItemModal } from "./AddItemModal";
import { PasswordGenerator } from "./PasswordGenerator";

type SyncState = "loading" | "ready" | "error";

export function VaultList() {
  const { lock } = useVault();
  const [items, setItems] = useState<Item[]>([]);
  const [syncState, setSyncState] = useState<SyncState>("loading");
  const [error, setError] = useState("");
  const [showAdd, setShowAdd] = useState(false);
  const [showGenerator, setShowGenerator] = useState(false);

  const loadItems = useCallback(async () => {
    setSyncState("loading");
    try {
      const sync = await api.sync();
      setItems(sync.items);
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

  const handleItemAdded = (item: Item) => {
    setItems((prev) => [...prev, item]);
    setShowAdd(false);
  };

  const handleItemDeleted = (id: string) => {
    setItems((prev) => prev.filter((i) => i.id !== id));
  };

  return (
    <main style={{ fontFamily: "system-ui, sans-serif", padding: "1.5rem", maxWidth: "680px", margin: "0 auto" }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.25rem" }}>
        <h1 style={{ margin: 0 }}>Secure Vault</h1>
        <div style={{ display: "flex", gap: "0.5rem" }}>
          <button onClick={() => setShowGenerator(v => !v)}>
            {showGenerator ? "Hide Generator" : "Generate Password"}
          </button>
          <button onClick={() => setShowAdd(true)}>+ Add Item</button>
          <button onClick={handleLogout} style={{ color: "#555" }}>Log Out</button>
        </div>
      </div>

      {showGenerator && <PasswordGenerator />}

      {syncState === "loading" && <p>Loading vault…</p>}
      {syncState === "error" && <p style={{ color: "crimson" }}>Failed to load vault: {error}</p>}

      {syncState === "ready" && (
        <div style={{ marginTop: "1rem" }}>
          {items.length === 0 ? (
            <p style={{ color: "#666" }}>No items yet. Click "+ Add Item" to store your first secret.</p>
          ) : (
            items.map((item) => (
              <ItemCard key={item.id} item={item} onDeleted={handleItemDeleted} />
            ))
          )}
        </div>
      )}

      {showAdd && <AddItemModal onAdded={handleItemAdded} onClose={() => setShowAdd(false)} />}
    </main>
  );
}
