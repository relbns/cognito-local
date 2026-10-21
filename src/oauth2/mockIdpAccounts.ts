import { createHash } from "node:crypto";
import type { Request, Response } from "express";
import {
  type FederationConfig,
  MOCK_ACCOUNT_EMAIL,
  type MockAccountConfig,
  type MockIdpView,
} from "../server/config";
import {
  type Claims,
  type IdentityProviderConfig,
  subjectClaimName,
} from "./federation";

/** One person in the account chooser: configured, or remembered by this browser. */
export interface MockAccount {
  email: string;
  name: string;
  sub?: string;
  claims?: Record<string, string>;
  configured: boolean;
}

export const REMEMBERED_ACCOUNTS_COOKIE = "cognito_emulator_mock_idp_accounts";
const REMEMBERED_PER_PROVIDER = 5;
const REMEMBERED_COOKIE_MAX_BYTES = 3500;
const REMEMBERED_MAX_AGE_MS = 365 * 24 * 60 * 60 * 1000;
const MAX_EMAIL_LENGTH = 254;
const MAX_NAME_LENGTH = 128;

const normalizeEmail = (email: string) => email.trim().toLowerCase();

export const isMockAccountEmail = (email: string): boolean =>
  email.trim().length <= MAX_EMAIL_LENGTH &&
  MOCK_ACCOUNT_EMAIL.test(email.trim());

const hash = (provider: IdentityProviderConfig, email: string) =>
  createHash("sha256")
    .update(`mock-idp\n${provider.ProviderName}\n${normalizeEmail(email)}`)
    .digest();

const decimalDigits = (bytes: Buffer, count: number) =>
  (BigInt(`0x${bytes.toString("hex")}`) % BigInt(10) ** BigInt(count))
    .toString()
    .padStart(count, "0");

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const base32 = (bytes: Buffer, count: number) =>
  Array.from(bytes.subarray(0, count), (byte) => BASE32[byte % 32]).join("");

/** The provider's id for this email, shaped like that provider's ids, and the same on every sign-in. */
export function mockSubject(
  provider: IdentityProviderConfig,
  email: string,
): string {
  const digest = hash(provider, email);
  const hex = digest.toString("hex");
  switch (provider.ProviderType) {
    case "Google":
      return `1${decimalDigits(digest.subarray(0, 16), 20)}`;
    case "Facebook":
      return `10${decimalDigits(digest.subarray(0, 16), 15)}`;
    case "LoginWithAmazon":
      return `amzn1.account.${base32(digest, 28)}`;
    case "SignInWithApple":
      return `${decimalDigits(digest.subarray(0, 4), 6)}.${hex.slice(8, 40)}.${decimalDigits(digest.subarray(20, 24), 4)}`;
    case "SAML":
      return normalizeEmail(email);
    default:
      return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-5${hex.slice(13, 16)}-${((parseInt(hex[16], 16) & 3) | 8).toString(16)}${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
  }
}

/** "jane.doe+test@example.test" gives "Jane Doe", for an account typed without a name. */
export function nameFromEmail(email: string): string {
  const local = email.trim().split("@")[0].split("+")[0];
  const words = local
    .split(/[._-]+/)
    .filter(Boolean)
    .map((word) => word[0].toUpperCase() + word.slice(1));
  return words.length ? words.join(" ") : email.trim();
}

const STANDARD_CLAIMS = [
  "email",
  "email_verified",
  "name",
  "given_name",
  "family_name",
];

/** The claims the provider returns for this account; feeds the same sign-in path as the developer form. */
export function mockAccountClaims(
  provider: IdentityProviderConfig,
  account: Pick<MockAccount, "email" | "name" | "sub" | "claims">,
): Claims {
  const email = account.email.trim();
  const name = account.name.trim() || nameFromEmail(email);
  const [givenName, ...familyNames] = name.split(/\s+/);
  const claims: Claims = { email, email_verified: "true", name };
  if (givenName) claims.given_name = givenName;
  if (familyNames.length) claims.family_name = familyNames.join(" ");
  const mapping = provider.AttributeMapping ?? {};
  for (const claim of STANDARD_CLAIMS) {
    const mapped = mapping[claim];
    if (mapped && claims[mapped] === undefined) claims[mapped] = claims[claim];
  }
  Object.assign(claims, account.claims ?? {});
  const subjectClaim = subjectClaimName(provider.ProviderType);
  claims[subjectClaim] =
    account.sub ??
    account.claims?.[subjectClaim] ??
    mockSubject(provider, email);
  return claims;
}

/** The configured accounts of a provider: its own MockAccounts, else FederationConfig.MockAccounts. */
export function configuredMockAccounts(
  config: FederationConfig | undefined,
  provider: IdentityProviderConfig,
): MockAccount[] {
  const accounts: MockAccountConfig[] =
    config?.Providers?.[provider.ProviderName]?.MockAccounts ??
    config?.MockAccounts ??
    [];
  return accounts.map((account) => ({
    email: account.email.trim(),
    name: account.name?.trim() || nameFromEmail(account.email),
    sub: account.sub?.trim() || undefined,
    claims: account.claims,
    configured: true,
  }));
}

export function mockIdpView(
  config: FederationConfig | undefined,
  provider: IdentityProviderConfig,
  dev: unknown,
): MockIdpView {
  if (dev === "1" || dev === "true") return "developer";
  if (dev === "0" || dev === "false") return "signin";
  return (
    config?.Providers?.[provider.ProviderName]?.MockView ??
    config?.MockView ??
    "signin"
  );
}

type RememberedAccounts = Record<string, Array<{ e: string; n: string }>>;

function readRemembered(req: Request): RememberedAccounts {
  for (const part of (req.headers.cookie ?? "").split(";")) {
    const [name, ...value] = part.trim().split("=");
    if (name !== REMEMBERED_ACCOUNTS_COOKIE || !value.length) continue;
    try {
      const parsed: unknown = JSON.parse(
        Buffer.from(decodeURIComponent(value.join("=")), "base64url").toString(
          "utf8",
        ),
      );
      if (typeof parsed !== "object" || parsed === null) return {};
      const result: RememberedAccounts = {};
      for (const [provider, list] of Object.entries(parsed)) {
        if (!Array.isArray(list)) continue;
        result[provider] = list
          .filter(
            (entry): entry is { e: string; n: string } =>
              typeof entry?.e === "string" &&
              typeof entry?.n === "string" &&
              isMockAccountEmail(entry.e),
          )
          .slice(0, REMEMBERED_PER_PROVIDER)
          .map((entry) => ({
            e: entry.e.trim(),
            n: entry.n.slice(0, MAX_NAME_LENGTH),
          }));
      }
      return result;
    } catch {
      return {};
    }
  }
  return {};
}

/** The chooser: accounts this browser used with the provider, most recent first, then the configured ones. */
export function chooserAccounts(
  req: Request,
  config: FederationConfig | undefined,
  provider: IdentityProviderConfig,
): MockAccount[] {
  const configured = configuredMockAccounts(config, provider);
  const byEmail = new Map(configured.map((a) => [normalizeEmail(a.email), a]));
  const seen = new Set<string>();
  const accounts: MockAccount[] = [];
  for (const { e, n } of readRemembered(req)[provider.ProviderName] ?? []) {
    const key = normalizeEmail(e);
    if (seen.has(key)) continue;
    seen.add(key);
    accounts.push(
      byEmail.get(key) ?? {
        email: e,
        name: n || nameFromEmail(e),
        configured: false,
      },
    );
  }
  for (const account of configured) {
    const key = normalizeEmail(account.email);
    if (!seen.has(key)) {
      seen.add(key);
      accounts.push(account);
    }
  }
  return accounts;
}

/** The account a sign-in names: the configured one with that email, else one from the form or this browser's list. */
export function resolveMockAccount(
  req: Request,
  config: FederationConfig | undefined,
  provider: IdentityProviderConfig,
  email: string,
  name: string,
): MockAccount {
  const key = normalizeEmail(email);
  const configured = configuredMockAccounts(config, provider).find(
    (account) => normalizeEmail(account.email) === key,
  );
  if (configured) return configured;
  const remembered = (readRemembered(req)[provider.ProviderName] ?? []).find(
    (entry) => normalizeEmail(entry.e) === key,
  );
  return {
    email: key,
    name:
      name.trim().slice(0, MAX_NAME_LENGTH) ||
      remembered?.n ||
      nameFromEmail(key),
    configured: false,
  };
}

/** Puts the account first in this browser's list for the provider. */
export function rememberMockAccount(
  req: Request,
  res: Response,
  provider: IdentityProviderConfig,
  account: MockAccount,
): void {
  const remembered = readRemembered(req);
  const key = normalizeEmail(account.email);
  const list = [
    { e: account.email, n: account.name.slice(0, MAX_NAME_LENGTH) },
    ...(remembered[provider.ProviderName] ?? []).filter(
      (entry) => normalizeEmail(entry.e) !== key,
    ),
  ].slice(0, REMEMBERED_PER_PROVIDER);
  let next: RememberedAccounts = {
    [provider.ProviderName]: list,
    ...Object.fromEntries(
      Object.entries(remembered).filter(
        ([name]) => name !== provider.ProviderName,
      ),
    ),
  };
  const encode = (value: RememberedAccounts) =>
    Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
  if (encode(next).length > REMEMBERED_COOKIE_MAX_BYTES) {
    next = { [provider.ProviderName]: list };
  }
  res.cookie(REMEMBERED_ACCOUNTS_COOKIE, encode(next), {
    httpOnly: true,
    sameSite: "lax",
    secure: req.secure,
    path: "/",
    maxAge: REMEMBERED_MAX_AGE_MS,
  });
}
