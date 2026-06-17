// Phase 0 — frontend linter. Flat config (ESLint v9), matching Vite's react-ts
// template. Findings are errors: `eslint .` exits non-zero, failing the
// pre-commit hook (and CI once it lands), same posture as golangci-lint for Go.
import js from "@eslint/js";
import globals from "globals";
import reactHooks from "eslint-plugin-react-hooks";
import reactRefresh from "eslint-plugin-react-refresh";
import tseslint from "typescript-eslint";

export default tseslint.config(
  // Build output and generated API types are not ours to lint
  // (mirrors `.golangci.yml` skipping generated Go).
  { ignores: ["dist", "src/api/gen/**"] },
  {
    files: ["**/*.{ts,tsx}"],
    extends: [
      js.configs.recommended,
      ...tseslint.configs.recommended,
      reactHooks.configs["recommended-latest"],
      reactRefresh.configs.vite,
    ],
    languageOptions: {
      ecmaVersion: 2020,
      globals: globals.browser,
    },
  },
);
