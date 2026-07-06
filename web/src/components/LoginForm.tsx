import { useState } from "react";
import { api } from "../api/client";
import { getCrypto, toCryptoKdfParams } from "../crypto/service";
import { useVault } from "../context/VaultContext";

type LoginState = "idle" | "fetching" | "deriving" | "authenticating" | "mfa" | "error";

interface MfaContext {
  masterKeyB64: string;
  cryptoParams: ReturnType<typeof toCryptoKdfParams>;
  mfaToken: string;
  protectedTotpSecret: string;
  protectedSymmetricKey: string;
  kdfParams: Parameters<typeof toCryptoKdfParams>[0];
}

export function LoginForm() {
  const { setVaultKey } = useVault();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [recoveryCode, setRecoveryCode] = useState("");
  const [useRecovery, setUseRecovery] = useState(false);
  const [mfaCtx, setMfaCtx] = useState<MfaContext | null>(null);
  const [state, setState] = useState<LoginState>("idle");
  const [error, setError] = useState("");

  const busy = state === "fetching" || state === "deriving" || state === "authenticating";

  const vaultKeyFromMaster = async (masterKeyB64: string, protectedSymmetricKey: string) => {
    const crypto = await getCrypto();
    const { encKey: encKeyB64 } = crypto.stretchMasterKey(masterKeyB64);
    return crypto.unwrapVaultKey(protectedSymmetricKey, encKeyB64);
  };

  const finishLogin = async (
    protectedSymmetricKey: string,
    kdfParams: Parameters<typeof toCryptoKdfParams>[0],
    masterKeyB64: string,
    cryptoParams: ReturnType<typeof toCryptoKdfParams>
  ) => {
    if (JSON.stringify(toCryptoKdfParams(kdfParams)) !== JSON.stringify(cryptoParams)) {
      throw new Error("KDF parameters changed during login. Please try again.");
    }
    const vaultKeyB64 = await vaultKeyFromMaster(masterKeyB64, protectedSymmetricKey);
    setPassword("");
    setVaultKey(vaultKeyB64);
    setMfaCtx(null);
    setState("idle");
  };

  const handlePasswordSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError("");

    try {
      setState("fetching");
      const { kdf_params: kdfParams } = await api.getLoginKdfParams(email);
      const cryptoParams = toCryptoKdfParams(kdfParams);

      setState("deriving");
      const crypto = await getCrypto();
      const masterKeyB64 = crypto.deriveMasterKey(password, email, cryptoParams);
      const authHashB64 = crypto.deriveAuthHash(masterKeyB64, password, cryptoParams);

      setState("authenticating");
      const resp = await api.login({ email, auth_hash: authHashB64 });

      if (resp.mfa_required && resp.mfa_token && resp.protected_totp_secret && resp.protected_symmetric_key && resp.kdf_params) {
        setMfaCtx({
          masterKeyB64,
          cryptoParams,
          mfaToken: resp.mfa_token,
          protectedTotpSecret: resp.protected_totp_secret,
          protectedSymmetricKey: resp.protected_symmetric_key,
          kdfParams: resp.kdf_params,
        });
        setState("mfa");
        return;
      }

      if (!resp.protected_symmetric_key || !resp.kdf_params) {
        throw new Error("Incomplete login response");
      }
      await finishLogin(resp.protected_symmetric_key, resp.kdf_params, masterKeyB64, cryptoParams);
    } catch (err) {
      setState("error");
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  const handleMfaSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!mfaCtx) return;
    setError("");

    try {
      setState("authenticating");
      const crypto = await getCrypto();
      const vaultKeyB64 = await vaultKeyFromMaster(mfaCtx.masterKeyB64, mfaCtx.protectedSymmetricKey);

      let totpSecret: string | undefined;
      if (!useRecovery) {
        totpSecret = crypto.unwrapTOTPSecret(mfaCtx.protectedTotpSecret, vaultKeyB64);
      }

      const resp = await api.loginMfa({
        mfa_token: mfaCtx.mfaToken,
        ...(useRecovery
          ? { recovery_code: recoveryCode }
          : { totp_code: totpCode, totp_secret: totpSecret }),
      });

      const psk = resp.protected_symmetric_key ?? mfaCtx.protectedSymmetricKey;
      const kp = resp.kdf_params ?? mfaCtx.kdfParams;
      await finishLogin(psk, kp, mfaCtx.masterKeyB64, mfaCtx.cryptoParams);
    } catch (err) {
      setState("mfa");
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  if (state === "mfa" && mfaCtx) {
    return (
      <form onSubmit={handleMfaSubmit}>
        <p>Two-factor authentication required.</p>
        {!useRecovery ? (
          <div style={{ marginBottom: "1rem" }}>
            <label style={{ display: "block" }}>
              Authenticator code
              <input
                type="text"
                inputMode="numeric"
                pattern="[0-9]{6}"
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value)}
                required
                disabled={busy}
                autoComplete="one-time-code"
                style={{ display: "block", width: "100%", padding: "0.5rem", marginTop: "0.25rem" }}
              />
            </label>
          </div>
        ) : (
          <div style={{ marginBottom: "1rem" }}>
            <label style={{ display: "block" }}>
              Recovery code
              <input
                type="text"
                value={recoveryCode}
                onChange={(e) => setRecoveryCode(e.target.value)}
                required
                disabled={busy}
                style={{ display: "block", width: "100%", padding: "0.5rem", marginTop: "0.25rem" }}
              />
            </label>
          </div>
        )}
        <button type="button" onClick={() => setUseRecovery((v) => !v)} style={{ marginBottom: "1rem" }}>
          {useRecovery ? "Use authenticator app" : "Use recovery code"}
        </button>
        {error && <p style={{ color: "crimson", marginBottom: "1rem" }}>{error}</p>}
        <button type="submit" disabled={busy} style={{ padding: "0.5rem 1.5rem" }}>
          {busy ? "Verifying…" : "Verify"}
        </button>
      </form>
    );
  }

  return (
    <form onSubmit={handlePasswordSubmit}>
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
        {state === "fetching"
          ? "Loading account parameters…"
          : state === "deriving"
            ? "Deriving keys… (may take a moment)"
            : state === "authenticating"
              ? "Authenticating…"
              : "Log In"}
      </button>
    </form>
  );
}
