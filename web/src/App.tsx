import { useEffect, useState } from "react";
import { VaultProvider, useVault } from "./context/VaultContext";
import { LoginForm } from "./components/LoginForm";
import { RegisterForm } from "./components/RegisterForm";
import { VaultList } from "./components/VaultList";
import { getCrypto } from "./crypto/service";

type AppMode = "loading" | "auth" | "vault";
type AuthTab = "login" | "register";

function AppShell() {
  const { vaultKey } = useVault();
  const [mode, setMode] = useState<AppMode>("loading");
  const [tab, setTab] = useState<AuthTab>("login");
  const [loadError, setLoadError] = useState("");

  // Load WASM on mount; show auth once ready.
  useEffect(() => {
    getCrypto()
      .then(() => setMode("auth"))
      .catch((err: unknown) => {
        setLoadError(err instanceof Error ? err.message : String(err));
        setMode("auth"); // still show auth so user sees an error context
      });
  }, []);

  // React to vault key changes: unlocked → vault view, locked → auth.
  useEffect(() => {
    if (vaultKey !== null) {
      setMode("vault");
    } else if (mode === "vault") {
      setMode("auth");
    }
  }, [vaultKey, mode]);

  if (mode === "loading") {
    return (
      <main style={{ fontFamily: "system-ui, sans-serif", padding: "2rem" }}>
        <h1>Secure Vault</h1>
        <p>Loading cryptographic library…</p>
      </main>
    );
  }

  if (mode === "auth") {
    return (
      <main
        style={{
          fontFamily: "system-ui, sans-serif",
          padding: "2rem",
          maxWidth: "480px",
          margin: "0 auto",
        }}
      >
        <h1>Secure Vault</h1>
        {loadError && (
          <p style={{ color: "crimson", background: "#fff0f0", padding: "0.75rem", borderRadius: "4px" }}>
            Crypto library failed to load: {loadError}
          </p>
        )}
        <div style={{ display: "flex", gap: "1rem", marginBottom: "1.5rem" }}>
          <button
            onClick={() => setTab("login")}
            style={{ fontWeight: tab === "login" ? "bold" : "normal", textDecoration: tab === "login" ? "underline" : "none" }}
          >
            Log In
          </button>
          <button
            onClick={() => setTab("register")}
            style={{ fontWeight: tab === "register" ? "bold" : "normal", textDecoration: tab === "register" ? "underline" : "none" }}
          >
            Create Account
          </button>
        </div>
        {tab === "login" ? (
          <LoginForm />
        ) : (
          <RegisterForm onRegistered={() => setTab("login")} />
        )}
      </main>
    );
  }

  return <VaultList />;
}

export function App() {
  return (
    <VaultProvider>
      <AppShell />
    </VaultProvider>
  );
}
