import { useState } from "react";
import { api } from "../api/client";
import { getCrypto, DEFAULT_KDF_PARAMS } from "../crypto/service";

type RegisterState = "idle" | "deriving" | "registering" | "done" | "error";

interface Props {
  onRegistered: () => void;
}

export function RegisterForm({ onRegistered }: Props) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [state, setState] = useState<RegisterState>("idle");
  const [error, setError] = useState("");

  const busy = state === "deriving" || state === "registering";

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    if (password !== confirm) {
      setError("Passwords do not match.");
      return;
    }
    if (password.length < 12) {
      setError("Master password must be at least 12 characters.");
      return;
    }

    try {
      setState("deriving");
      const crypto = await getCrypto();

      // All key material is derived and kept client-side; only the auth hash
      // and the vault key wrapped under the stretched master key go to the server.
      const masterKeyB64 = crypto.deriveMasterKey(password, email, DEFAULT_KDF_PARAMS);
      const authHashB64 = crypto.deriveAuthHash(masterKeyB64, password, DEFAULT_KDF_PARAMS);
      const { encKey: encKeyB64 } = crypto.stretchMasterKey(masterKeyB64);

      const vaultKeyB64 = crypto.newVaultKey();
      const protectedSymmetricKey = crypto.wrapVaultKey(vaultKeyB64, encKeyB64);

      setState("registering");
      await api.register({
        email,
        kdf_params: DEFAULT_KDF_PARAMS,
        auth_hash: authHashB64,
        protected_symmetric_key: protectedSymmetricKey,
      });

      // Drop passwords from state immediately.
      setPassword("");
      setConfirm("");

      setState("done");
      onRegistered();
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
          Master Password (min 12 characters)
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            required
            minLength={12}
            disabled={busy}
            autoComplete="new-password"
            style={{ display: "block", width: "100%", padding: "0.5rem", marginTop: "0.25rem" }}
          />
        </label>
      </div>
      <div style={{ marginBottom: "1rem" }}>
        <label style={{ display: "block" }}>
          Confirm Password
          <input
            type="password"
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            required
            disabled={busy}
            autoComplete="new-password"
            style={{ display: "block", width: "100%", padding: "0.5rem", marginTop: "0.25rem" }}
          />
        </label>
      </div>
      {error && <p style={{ color: "crimson", marginBottom: "1rem" }}>{error}</p>}
      <button type="submit" disabled={busy} style={{ padding: "0.5rem 1.5rem" }}>
        {state === "deriving"
          ? "Deriving keys… (may take a moment)"
          : state === "registering"
            ? "Creating account…"
            : "Create Account"}
      </button>
      <p style={{ fontSize: "0.85rem", color: "#666", marginTop: "1rem" }}>
        Your master password is never sent to the server. If you lose it, your vault cannot be recovered.
      </p>
    </form>
  );
}
