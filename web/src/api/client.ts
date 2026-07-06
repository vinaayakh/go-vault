// Thin, typed fetch wrapper over the Secure Vault API. Types come from
// src/api/gen/types.ts, generated from ../api/openapi.yaml by `npm run gen:api`,
// so the client stays in lockstep with the backend contract.
import type { components } from "./gen/types";

export type HealthResponse = components["schemas"]["HealthResponse"];
export type Item = components["schemas"]["Item"];
export type NewItem = components["schemas"]["NewItem"];
export type UpdateItem = components["schemas"]["UpdateItem"];
export type RegisterRequest = components["schemas"]["RegisterRequest"];
export type LoginRequest = components["schemas"]["LoginRequest"];
export type LoginResponse = components["schemas"]["LoginResponse"];
export type LoginMfaRequest = components["schemas"]["LoginMfaRequest"];
export type LoginKdfParamsResponse = components["schemas"]["LoginKdfParamsResponse"];
export type SyncResponse = components["schemas"]["SyncResponse"];
export type UpdateKeyRequest = components["schemas"]["UpdateKeyRequest"];
export type Enroll2faRequest = components["schemas"]["Enroll2faRequest"];
export type Enroll2faResponse = components["schemas"]["Enroll2faResponse"];
export type Disable2faRequest = components["schemas"]["Disable2faRequest"];
export type RecoveryCodesResponse = components["schemas"]["RecoveryCodesResponse"];
export type RegenerateRecoveryCodesRequest = components["schemas"]["RegenerateRecoveryCodesRequest"];
export type ActivityResponse = components["schemas"]["ActivityResponse"];
export type ActivityEvent = components["schemas"]["ActivityEvent"];

let refreshInFlight: Promise<boolean> | null = null;

async function refreshSession(): Promise<boolean> {
  if (!refreshInFlight) {
    refreshInFlight = (async () => {
      const res = await fetch("/api/auth/refresh", {
        method: "POST",
        credentials: "include",
        headers: { "X-Vault-CSRF": "1" },
      });
      return res.ok;
    })().finally(() => {
      refreshInFlight = null;
    });
  }
  return refreshInFlight;
}

async function fetchWithAuth(
  path: string,
  init: RequestInit,
  retried = false,
): Promise<Response> {
  const res = await fetch(path, { credentials: "include", ...init });
  if (res.status === 401 && !retried && !path.startsWith("/api/auth/refresh")) {
    const refreshed = await refreshSession();
    if (refreshed) {
      return fetchWithAuth(path, init, true);
    }
  }
  return res;
}

async function getJSON<T>(path: string): Promise<T> {
  const res = await fetchWithAuth(path, { headers: { Accept: "application/json" } });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error((body as { error?: string }).error ?? res.statusText);
  }
  return (await res.json()) as T;
}

async function postJSON<T>(path: string, body: unknown): Promise<T> {
  const res = await fetchWithAuth(path, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      "X-Vault-CSRF": "1",
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const errBody = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error((errBody as { error?: string }).error ?? res.statusText);
  }
  if (res.status === 204 || res.headers.get("Content-Length") === "0") {
    return undefined as T;
  }
  return (await res.json()) as T;
}

async function putJSON<T>(path: string, body: unknown): Promise<T> {
  const res = await fetchWithAuth(path, {
    method: "PUT",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json",
      "X-Vault-CSRF": "1",
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const errBody = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error((errBody as { error?: string }).error ?? res.statusText);
  }
  if (res.status === 204 || res.headers.get("Content-Length") === "0") {
    return undefined as T;
  }
  return (await res.json()) as T;
}

async function deleteJSON(path: string, body?: unknown): Promise<void> {
  const res = await fetchWithAuth(path, {
    method: "DELETE",
    headers: {
      ...(body ? { "Content-Type": "application/json" } : {}),
      "X-Vault-CSRF": "1",
    },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) {
    const errBody = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error((errBody as { error?: string }).error ?? res.statusText);
  }
}

export const api = {
  health: () => getJSON<HealthResponse>("/api/health"),

  register: (req: RegisterRequest) => postJSON<void>("/api/register", req),

  login: (req: LoginRequest) => postJSON<LoginResponse>("/api/login", req),

  loginMfa: (req: LoginMfaRequest) => postJSON<LoginResponse>("/api/login/mfa", req),

  getLoginKdfParams: (email: string) =>
    getJSON<LoginKdfParamsResponse>(`/api/login/kdf-params?email=${encodeURIComponent(email)}`),

  refreshSession: () => refreshSession(),

  logout: () => postJSON<void>("/api/logout", {}),

  sync: () => getJSON<SyncResponse>("/api/sync"),

  createItem: (req: NewItem) => postJSON<Item>("/api/items", req),

  updateItem: (id: string, req: UpdateItem) =>
    putJSON<Item>(`/api/items/${id}`, req),

  deleteItem: (id: string) => deleteJSON(`/api/items/${id}`),

  deleteUser: () => deleteJSON("/api/user"),

  updateKey: (req: UpdateKeyRequest) => putJSON<void>("/api/user/key", req),

  enroll2fa: (req: Enroll2faRequest) => postJSON<Enroll2faResponse>("/api/user/2fa/enroll", req),

  disable2fa: (req: Disable2faRequest) => deleteJSON("/api/user/2fa", req),

  regenerateRecoveryCodes: (req: RegenerateRecoveryCodesRequest) =>
    postJSON<RecoveryCodesResponse>("/api/user/2fa/recovery-codes", req),

  activity: (limit = 50, cursor?: string) => {
    const params = new URLSearchParams({ limit: String(limit) });
    if (cursor) params.set("cursor", cursor);
    return getJSON<ActivityResponse>(`/api/activity?${params}`);
  },
};
