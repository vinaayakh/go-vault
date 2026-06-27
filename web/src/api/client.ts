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
export type SyncResponse = components["schemas"]["SyncResponse"];
export type UpdateKeyRequest = components["schemas"]["UpdateKeyRequest"];

async function getJSON<T>(path: string): Promise<T> {
  const res = await fetch(path, { headers: { Accept: "application/json" } });
  if (!res.ok) {
    const body = await res.json().catch(() => ({ error: res.statusText }));
    throw new Error((body as { error?: string }).error ?? res.statusText);
  }
  return (await res.json()) as T;
}

async function postJSON<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(path, {
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
  const res = await fetch(path, {
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

async function deleteReq(path: string): Promise<void> {
  const res = await fetch(path, {
    method: "DELETE",
    headers: { "X-Vault-CSRF": "1" },
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

  logout: () => postJSON<void>("/api/logout", {}),

  sync: () => getJSON<SyncResponse>("/api/sync"),

  createItem: (req: NewItem) => postJSON<Item>("/api/items", req),

  updateItem: (id: string, req: UpdateItem) =>
    putJSON<Item>(`/api/items/${id}`, req),

  deleteItem: (id: string) => deleteReq(`/api/items/${id}`),

  deleteUser: () => deleteReq("/api/user"),

  updateKey: (req: UpdateKeyRequest) => putJSON<void>("/api/user/key", req),
};
