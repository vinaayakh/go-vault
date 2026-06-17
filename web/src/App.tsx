import { useEffect, useState } from "react";
import { api } from "./api/client";

type Status =
  | { state: "loading" }
  | { state: "ok"; status: string }
  | { state: "error"; message: string };

// App is the Phase 0 placeholder UI: it proves the React → Vite proxy → Go path
// works by fetching /api/health and rendering the result. The real vault UI
// (unlock, list, add, reveal) arrives in Phase 4.
export function App() {
  const [backend, setBackend] = useState<Status>({ state: "loading" });

  useEffect(() => {
    api
      .health()
      .then((h) => setBackend({ state: "ok", status: h.status }))
      .catch((e) => setBackend({ state: "error", message: String(e) }));
  }, []);

  return (
    <main style={{ fontFamily: "system-ui, sans-serif", padding: "2rem" }}>
      <h1>Secure Vault</h1>
      <p>
        Backend:{" "}
        {backend.state === "loading" && <span>checking…</span>}
        {backend.state === "ok" && (
          <strong style={{ color: "green" }}>{backend.status}</strong>
        )}
        {backend.state === "error" && (
          <strong style={{ color: "crimson" }}>unreachable</strong>
        )}
      </p>
      {backend.state === "error" && (
        <pre style={{ color: "crimson" }}>{backend.message}</pre>
      )}
      <p>
        API docs: <a href="/docs">Swagger UI</a> (served by the Go backend)
      </p>
    </main>
  );
}
