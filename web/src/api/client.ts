// Thin, typed fetch wrapper over the Secure Vault API. Types come from
// src/api/gen/types.ts, generated from ../api/openapi.yaml by `npm run gen:api`,
// so the client stays in lockstep with the backend contract.
import type { components } from "./gen/types";

export type HealthResponse = components["schemas"]["HealthResponse"];
export type Item = components["schemas"]["Item"];

async function getJSON<T>(path: string): Promise<T> {
  const res = await fetch(path, { headers: { Accept: "application/json" } });
  if (!res.ok) {
    throw new Error(`${path} → ${res.status} ${res.statusText}`);
  }
  return (await res.json()) as T;
}

export const api = {
  health: () => getJSON<HealthResponse>("/api/health"),
};
