import { useState } from "react";
import { api } from "../api/client";
import { getCrypto, DEFAULT_KDF_PARAMS } from "../crypto/service";
import { useVault } from "../context/VaultContext";

type LoginState = "idle" | "deriving" | "authenticating" | "error";

export function LoginForm() {
  const { setVaultKey } = useVault();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [state, setState] = useState<LoginState>("idle");
  const [error, setError] = useState("");

  const busy = state === "deriving" || state === "authenticating";

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    try {
      setState("deriving");
      const crypto = await getCrypto();

      // Derive master key and auth hash from the master password.
      // This calls Argon2id twice and may freeze the UI for 1–3 s each —
      // the loading label below keeps the user informed.
      const masterKeyB64 = crypto.deriveMasterKey(password, email, DEFAULT_KDF_PARAMS);
      const authHashB64 = crypto.deriveAuthHash(masterKeyB64, password, DEFAULT_KDF_PARAMS);

      setState("authenticating");
      const resp = await api.login({ email, auth_hash: authHashB64 });

      // Unwrap the vault key locally — the server never sees it.
      const { encKey: encKeyB64 } = crypto.stretchMasterKey(masterKeyB64);
      const vaultKeyB64 = crypto.unwrapVaultKey(resp.protected_symmetric_key, encKeyB64);

      // Drop the password from React state (best-effort in JS — GC will reclaim).
      setPassword("");

      setVaultKey(vaultKeyB64);
      setState("idle");
    } catch (err) {
      setState("error");
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  return (
    <form onSubmit={handleSubmit}>
      <div style={{ marginBottom: "1rem" }}>
        <label style={{ display: "block" }}>
          Email
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            required
            disabled={busy}
            autoComplete="username"
            style={{ display: "block", width: "100%", padding: "0.5rem", marginTop: "0.25rem" }}
          />
        </label>
      </div>
      <div style={{ marginBottom: "1rem" }}>
        <label style={{ display: "block" }}>
          Master Password
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            disabled={busy}
            autoComplete="current-password"
            style={{ display: "block", width: "100%", padding: "0.5rem", marginTop: "0.25rem" }}
          />
        </label>
      </div>
      {error && <p style={{ color: "crimson", marginBottom: "1rem" }}>{error}</p>}
      <button type="submit" disabled={busy} style={{ padding: "0.5rem 1.5rem" }}>
        {state === "deriving"
          ? "Deriving keys… (may take a moment)"
          : state === "authenticating"
            ? "Authenticating…"
            : "Log In"}
      </button>
    </form>
  );
}
