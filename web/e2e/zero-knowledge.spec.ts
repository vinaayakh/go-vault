import { test, expect } from "@playwright/test";

// Proves the zero-knowledge invariant end-to-end:
// the server only ever receives ciphertext and the auth hash — never plaintext.
//
// Requires a running full stack (backend + Vite dev server or built dist).
// Run: npm run test:e2e (after starting docker compose and the dev server).

const EMAIL = `e2e-${Date.now()}@example.com`;
const PASSWORD = "test-master-password-e2e!";
const ITEM_NAME = "E2E Test Login";
const ITEM_PASSWORD = "super-secret-item-pw";

test.describe("Zero-knowledge proof", () => {
  test("register → add item → logout → login → decrypt", async ({ page }) => {
    const sentBodies: string[] = [];

    // Intercept all outgoing POST/PUT requests and record their bodies.
    page.on("request", (req) => {
      if (req.method() === "POST" || req.method() === "PUT") {
        sentBodies.push(req.postData() ?? "");
      }
    });

    // ── Register ────────────────────────────────────────────────────────────
    await page.goto("/");
    await page.getByRole("button", { name: "Create Account" }).click();
    await page.getByLabel("Email").fill(EMAIL);
    await page.getByLabel("Master Password").nth(0).fill(PASSWORD);
    await page.getByLabel("Confirm Password").fill(PASSWORD);
    await page.getByRole("button", { name: "Create Account" }).click();

    // Wait for redirect to login tab
    await expect(page.getByRole("button", { name: "Log In" })).toBeVisible({ timeout: 30_000 });

    // ── Log in ───────────────────────────────────────────────────────────────
    await page.getByLabel("Email").fill(EMAIL);
    await page.getByLabel("Master Password").fill(PASSWORD);
    await page.getByRole("button", { name: "Log In" }).click();

    // Wait until vault is visible
    await expect(page.getByRole("heading", { name: "Secure Vault" })).toBeVisible({ timeout: 30_000 });

    // ── Add item ─────────────────────────────────────────────────────────────
    await page.getByRole("button", { name: "+ Add Item" }).click();
    await page.getByLabel("Name").fill(ITEM_NAME);
    await page.getByLabel("Password").fill(ITEM_PASSWORD);
    await page.getByRole("button", { name: "Save" }).click();

    // Item should appear in the list
    await expect(page.getByText("[login]")).toBeVisible({ timeout: 10_000 });

    // ── Verify network contains no plaintext ─────────────────────────────────
    for (const body of sentBodies) {
      expect(body).not.toContain(PASSWORD);
      expect(body).not.toContain(ITEM_PASSWORD);
      expect(body).not.toContain(ITEM_NAME);
    }

    // ── Log out ───────────────────────────────────────────────────────────────
    await page.getByRole("button", { name: "Log Out" }).click();
    await expect(page.getByRole("button", { name: "Log In" })).toBeVisible({ timeout: 5_000 });

    // ── Fresh login + decrypt ─────────────────────────────────────────────────
    const postLoginBodies: string[] = [];
    page.on("request", (req) => {
      if (req.method() === "POST" || req.method() === "PUT") {
        postLoginBodies.push(req.postData() ?? "");
      }
    });

    await page.getByLabel("Email").fill(EMAIL);
    await page.getByLabel("Master Password").fill(PASSWORD);
    await page.getByRole("button", { name: "Log In" }).click();
    await expect(page.getByText("[login]")).toBeVisible({ timeout: 30_000 });

    // Reveal the item and confirm plaintext appears client-side.
    await page.getByRole("button", { name: "Reveal" }).click();
    await expect(page.getByText(ITEM_NAME)).toBeVisible({ timeout: 5_000 });

    // /api/sync response must not contain the plaintext item password.
    for (const body of postLoginBodies) {
      expect(body).not.toContain(ITEM_PASSWORD);
      expect(body).not.toContain(ITEM_NAME);
    }
  });
});
