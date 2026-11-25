// The strength rule for a new master or backup password. Mirrors `controller/password.rs`.

export const MIN_PASSWORD_CHARS = 8;

export interface PasswordRule {
  /** Shown in the checklist, such as "8 or more characters". */
  label: string;
  met: (password: string) => boolean;
}

export const PASSWORD_RULES: readonly PasswordRule[] = [
  // Counted in characters, as Rust's `chars()` counts them, not UTF-16 units or bytes.
  { label: `${MIN_PASSWORD_CHARS} or more characters`, met: (p) => [...p].length >= MIN_PASSWORD_CHARS },
  { label: "An uppercase letter", met: (p) => /\p{Uppercase}/u.test(p) },
  { label: "A lowercase letter", met: (p) => /\p{Lowercase}/u.test(p) },
  { label: "A number", met: (p) => /\p{N}/u.test(p) },
  // Anything that is not a letter or a digit, as Rust's `!char::is_alphanumeric`.
  { label: "A special character", met: (p) => /[^\p{Alphabetic}\p{N}]/u.test(p) },
];

/** Whether `password` meets every rule. */
export const isStrongPassword = (password: string): boolean => PASSWORD_RULES.every((r) => r.met(password));
