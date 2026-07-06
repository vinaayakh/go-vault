import { test, expect } from "@playwright/test";
import { authenticator } from "@otplib/preset-default";

const EMAIL = `e2e-2fa-${Date.now()}@example.com`;
const PASSWORD = "test-master-password-2fa!";

function secretFromProvisioningURI(uri: string): string {
  const secret = new URL(uri).searchParams.get("secret");
  if (!secret) throw new Error("no secret in provisioning URI");
  return secret;
}

test.describe("Two-factor authentication", () => {
  test("enroll 2FA → logout → login with TOTP", async ({ page }) => {
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

    await page.getByRole("button", { name: "Settings" }).click();
    await page.getByLabel("Account email (for export metadata)").fill(EMAIL);
    await page.getByRole("button", { name: "Enable 2FA" }).click();

    const uri = await page.getByTestId("totp-provisioning-uri").textContent();
    expect(uri).toBeTruthy();
    const secret = secretFromProvisioningURI(uri!);
    const code = authenticator.generate(secret);

    await page.getByLabel("Verification code").fill(code);
    await page.getByRole("button", { name: "Enable 2FA" }).click();
    await expect(page.getByText("Save these recovery codes")).toBeVisible({ timeout: 15_000 });
    await page.getByRole("button", { name: "Done" }).click();

    await page.getByRole("button", { name: "Log Out" }).click();
    await expect(page.getByRole("button", { name: "Log In" })).toBeVisible({ timeout: 10_000 });

    await page.getByLabel("Email").fill(EMAIL);
    await page.getByLabel("Master Password").fill(PASSWORD);
    await page.getByRole("button", { name: "Log In" }).click();

    await expect(page.getByText("Two-factor authentication required")).toBeVisible({ timeout: 30_000 });
    const loginCode = authenticator.generate(secret);
    await page.getByLabel("Authenticator code").fill(loginCode);
    await page.getByRole("button", { name: "Verify" }).click();

    await expect(page.getByRole("heading", { name: "Secure Vault" })).toBeVisible({ timeout: 30_000 });
  });
});
