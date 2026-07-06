import type { SyncResponse } from "../api/client";

export interface VaultExport {
  format: "secure-vault-export";
  version: 1;
  exported_at: string;
  email: string;
  kdf_params: SyncResponse["kdf_params"];
  protected_symmetric_key: string;
  totp_enabled: boolean;
  protected_totp_secret?: string;
  items: SyncResponse["items"];
}

export function buildExport(email: string, sync: SyncResponse): VaultExport {
  return {
    format: "secure-vault-export",
    version: 1,
    exported_at: new Date().toISOString(),
    email,
    kdf_params: sync.kdf_params,
    protected_symmetric_key: sync.protected_symmetric_key,
    totp_enabled: sync.totp_enabled,
    protected_totp_secret: sync.protected_totp_secret,
    items: sync.items,
  };
}

export function downloadExport(data: VaultExport, filename?: string) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename ?? `secure-vault-export-${data.exported_at.slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

export function parseExportFile(text: string): VaultExport {
  const data = JSON.parse(text) as VaultExport;
  if (data.format !== "secure-vault-export" || data.version !== 1) {
    throw new Error("Unsupported export format");
  }
  if (!data.protected_symmetric_key || !data.kdf_params || !Array.isArray(data.items)) {
    throw new Error("Invalid export file");
  }
  return data;
}
