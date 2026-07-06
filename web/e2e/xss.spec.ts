import { test, expect } from "@playwright/test";

const EMAIL = `xss-${Date.now()}@example.com`;
const PASSWORD = "test-master-password-xss!";
const XSS_PAYLOAD = '<script>alert("xss")</script>';

async function registerAndLogin(page: import("@playwright/test").Page) {
  await page.goto("/");
  await page.getByRole("button", { name: "Create Account" }).click();
  await page.getByLabel("Email").fill(EMAIL);
  await page.getByLabel("Master Password").nth(0).fill(PASSWORD);
  await page.getByLabel("Confirm Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Create Account" }).click();
  await expect(page.getByRole("button", { name: "Log In" })).toBeVisible({ timeout: 30_000 });

  await page.getByLabel("Email").fill(EMAIL);
  await page.getByLabel("Master Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Log In" }).click();
  await expect(page.getByRole("heading", { name: "Secure Vault" })).toBeVisible({ timeout: 30_000 });
}

test.describe("XSS defense", () => {
  test("item field XSS payload renders as inert text", async ({ page }) => {
    page.on("dialog", (dialog) => {
      throw new Error(`Unexpected dialog: ${dialog.message()}`);
    });

    await registerAndLogin(page);

    await page.getByRole("button", { name: "+ Add Item" }).click();
    await page.getByLabel("Name").fill("XSS Test Item");
    await page.getByLabel("Notes").fill(XSS_PAYLOAD);
    await page.getByRole("button", { name: "Save" }).click();
    await expect(page.getByText("[login]")).toBeVisible({ timeout: 10_000 });

    await page.getByRole("button", { name: "Reveal" }).click();
    await expect(page.getByText("Notes:")).toBeVisible({ timeout: 5_000 });
    await expect(page.getByText(XSS_PAYLOAD)).toBeVisible();
  });
});
