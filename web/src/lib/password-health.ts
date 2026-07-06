export interface PasswordStrength {
  score: number; // 0-4
  label: string;
  feedback: string[];
}

export function scorePassword(password: string): PasswordStrength {
  const feedback: string[] = [];
  let score = 0;
  if (password.length >= 12) score++;
  else feedback.push("Use at least 12 characters");
  if (password.length >= 16) score++;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
  else feedback.push("Mix upper and lower case");
  if (/\d/.test(password)) score++;
  else feedback.push("Add numbers");
  if (/[^a-zA-Z0-9]/.test(password)) score++;
  else feedback.push("Add symbols");

  const labels = ["Very weak", "Weak", "Fair", "Strong", "Very strong"];
  const capped = Math.min(4, Math.max(0, score));
  return { score: capped, label: labels[capped], feedback };
}

async function sha1Hex(password: string): Promise<string> {
  const data = new TextEncoder().encode(password);
  const hash = await crypto.subtle.digest("SHA-1", data);
  return Array.from(new Uint8Array(hash))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

/** k-anonymity HIBP range lookup — only the first 5 hash chars leave the client. */
export async function checkBreached(password: string): Promise<number> {
  if (!password) return 0;
  const hash = await sha1Hex(password);
  const prefix = hash.slice(0, 5);
  const suffix = hash.slice(5);
  const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
  if (!res.ok) throw new Error("Breach check unavailable");
  const text = await res.text();
  for (const line of text.split("\n")) {
    const [suf, count] = line.split(":");
    if (suf?.trim().toUpperCase() === suffix) {
      return parseInt(count, 10) || 0;
    }
  }
  return 0;
}
