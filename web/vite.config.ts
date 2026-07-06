import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

const csp =
  "default-src 'none'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self'; " +
  "connect-src 'self' https://api.pwnedpasswords.com; img-src 'self' data:; form-action 'self'; " +
  "frame-ancestors 'none'; base-uri 'self'";

// Dev server proxies /api to the Go backend so the browser talks to a single
// origin (no CORS) and the React app uses relative URLs in every environment.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    headers: {
      "Content-Security-Policy": csp,
    },
    proxy: {
      "/api": {
        target: "http://localhost:8080",
        changeOrigin: true,
      },
    },
  },
  preview: {
    port: 5173,
    headers: {
      "Content-Security-Policy": csp,
    },
    proxy: {
      "/api": {
        target: "http://localhost:8080",
        changeOrigin: true,
      },
    },
  },
});
