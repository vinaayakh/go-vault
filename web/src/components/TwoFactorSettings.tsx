import { useState } from "react";
import { api } from "../api/client";
import { getCrypto } from "../crypto/service";
import { useVault } from "../context/VaultContext";

interface Props {
  email: string;
  totpEnabled: boolean;
  protectedTotpSecret?: string;
  onChanged: () => void;
}

export function TwoFactorSettings({ email, totpEnabled, protectedTotpSecret, onChanged }: Props) {
  const { vaultKey } = useVault();
  const [step, setStep] = useState<"idle" | "enroll" | "confirm" | "codes">("idle");
  const [secret, setSecret] = useState("");
  const [provisioningURL, setProvisioningURL] = useState("");
  const [totpCode, setTotpCode] = useState("");
  const [recoveryCodes, setRecoveryCodes] = useState<string[]>([]);
  const [disableCode, setDisableCode] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const startEnroll = async () => {
    if (!vaultKey) return;
    setError("");
    setBusy(true);
    try {
      const crypto = await getCrypto();
      const { secret: s, url } = crypto.generateTOTPSecret(email);
      setSecret(s);
      setProvisioningURL(url);
      setStep("confirm");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const confirmEnroll = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!vaultKey || !secret) return;
    setBusy(true);
    setError("");
    try {
      const crypto = await getCrypto();
      const protectedTotp = crypto.wrapTOTPSecret(secret, vaultKey);
      const resp = await api.enroll2fa({
        protected_totp_secret: protectedTotp,
        totp_secret: secret,
        totp_code: totpCode,
      });
      setRecoveryCodes(resp.recovery_codes);
      setStep("codes");
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const disable2FA = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!vaultKey || !protectedTotpSecret) return;
    setBusy(true);
    setError("");
    try {
      const crypto = await getCrypto();
      const totpSecret = crypto.unwrapTOTPSecret(protectedTotpSecret, vaultKey);
      await api.disable2fa({ totp_code: disableCode, totp_secret: totpSecret });
      setStep("idle");
      onChanged();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  const regenerateCodes = async () => {
    if (!vaultKey || !protectedTotpSecret) return;
    setBusy(true);
    setError("");
    try {
      const crypto = await getCrypto();
      const totpSecret = crypto.unwrapTOTPSecret(protectedTotpSecret, vaultKey);
      const code = prompt("Enter current authenticator code:");
      if (!code) return;
      const resp = await api.regenerateRecoveryCodes({ totp_code: code, totp_secret: totpSecret });
      setRecoveryCodes(resp.recovery_codes);
      setStep("codes");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  };

  if (!totpEnabled) {
    if (step === "confirm") {
      return (
        <div>
          <p>Scan this URI in your authenticator app:</p>
          <code style={{ wordBreak: "break-all", fontSize: "0.85rem" }}>{provisioningURL}</code>
          <form onSubmit={confirmEnroll} style={{ marginTop: "1rem" }}>
            <label style={{ display: "block" }}>
              Verification code
              <input
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value)}
                required
                disabled={busy}
                style={{ display: "block", width: "100%", padding: "0.5rem", marginTop: "0.25rem" }}
              />
            </label>
            {error && <p style={{ color: "crimson" }}>{error}</p>}
            <button type="submit" disabled={busy} style={{ marginTop: "0.5rem" }}>
              Enable 2FA
            </button>
          </form>
        </div>
      );
    }
    if (step === "codes") {
      return (
        <div>
          <p><strong>Save these recovery codes</strong> (shown once):</p>
          <ul>{recoveryCodes.map((c) => <li key={c}><code>{c}</code></li>)}</ul>
          <button onClick={() => setStep("idle")}>Done</button>
        </div>
      );
    }
    return (
      <div>
        <p>Two-factor authentication is off.</p>
        <button onClick={startEnroll} disabled={busy}>Enable 2FA</button>
        {error && <p style={{ color: "crimson" }}>{error}</p>}
      </div>
    );
  }

  if (step === "codes" && recoveryCodes.length > 0) {
    return (
      <div>
        <p><strong>New recovery codes</strong> (shown once):</p>
        <ul>{recoveryCodes.map((c) => <li key={c}><code>{c}</code></li>)}</ul>
        <button onClick={() => setStep("idle")}>Done</button>
      </div>
    );
  }

  return (
    <div>
      <p>Two-factor authentication is <strong>enabled</strong>.</p>
      <button onClick={regenerateCodes} disabled={busy} style={{ marginRight: "0.5rem" }}>
        Regenerate recovery codes
      </button>
      <form onSubmit={disable2FA} style={{ marginTop: "1rem" }}>
        <label style={{ display: "block" }}>
          Authenticator code to disable 2FA
          <input
            value={disableCode}
            onChange={(e) => setDisableCode(e.target.value)}
            required
            disabled={busy}
            style={{ display: "block", width: "100%", padding: "0.5rem", marginTop: "0.25rem" }}
          />
        </label>
        {error && <p style={{ color: "crimson" }}>{error}</p>}
        <button type="submit" disabled={busy} style={{ marginTop: "0.5rem", color: "crimson" }}>
          Disable 2FA
        </button>
      </form>
    </div>
  );
}
