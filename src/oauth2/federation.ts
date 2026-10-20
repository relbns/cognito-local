import type { Attribute } from "../services/sdkTypes";
import {
  attribute,
  attributeValue,
  type ProviderLink,
} from "../services/userPoolService";

export interface IdentityProviderConfig {
  ProviderName: string;
  ProviderType: string;
  ProviderDetails?: Record<string, string>;
  AttributeMapping?: Record<string, string>;
  IdpIdentifiers?: string[];
}

export type Claims = Record<string, string>;

export function identityProvidersOf(
  options: unknown,
): IdentityProviderConfig[] {
  const providers = (options as { _identityProviders?: unknown })
    ?._identityProviders;
  return Array.isArray(providers)
    ? (providers as IdentityProviderConfig[])
    : [];
}

export interface FederatedIdentity {
  userId: string;
  providerName: string;
  providerType: string;
  issuer: string | null;
  primary: boolean;
  dateCreated: number;
}

export interface IdentityClaim {
  userId: string;
  providerName: string;
  providerType: string;
  issuer: string | null;
  primary: string;
  dateCreated: string;
}

export const COGNITO_SUBJECT = "Cognito_Subject";

export function subjectClaimName(providerType: string): string {
  switch (providerType) {
    case "Facebook":
      return "id";
    case "LoginWithAmazon":
      return "user_id";
    case "SAML":
      return "NameID";
    default:
      return "sub";
  }
}

export function federatedUserId(
  provider: IdentityProviderConfig,
  claims: Claims,
): string | undefined {
  const subject = subjectClaimName(provider.ProviderType);
  const source =
    provider.ProviderType === "SAML"
      ? subject
      : (provider.AttributeMapping?.username ?? subject);
  const value = claims[source] ?? claims[subject];
  return value ? value : undefined;
}

export const federatedUsername = (providerName: string, userId: string) =>
  `${providerName}_${userId}`;

export function mapAttributes(
  provider: IdentityProviderConfig,
  claims: Claims,
): Attribute[] {
  return Object.entries(provider.AttributeMapping ?? {})
    .filter(([poolAttribute]) => poolAttribute !== "username")
    .filter(([, idpAttribute]) => claims[idpAttribute] !== undefined)
    .map(([poolAttribute, idpAttribute]) =>
      attribute(poolAttribute, claims[idpAttribute]),
    );
}

export function providerIssuer(
  provider: IdentityProviderConfig,
): string | null {
  const details = provider.ProviderDetails ?? {};
  if (provider.ProviderType === "OIDC") return details.oidc_issuer ?? null;
  if (provider.ProviderType === "SAML") {
    const entityId = /entityID="([^"]+)"/.exec(details.MetadataFile ?? "");
    return entityId?.[1] ?? details.MetadataURL ?? null;
  }
  return null;
}

export function parseIdentities(
  value: string | undefined,
): FederatedIdentity[] {
  if (!value) return [];
  try {
    const parsed: unknown = JSON.parse(value);
    return Array.isArray(parsed) ? (parsed as FederatedIdentity[]) : [];
  } catch {
    return [];
  }
}

export const identitiesOf = (attributes: Attribute[] | undefined) =>
  parseIdentities(attributeValue("identities", attributes));

export function identitiesClaim(
  attributes: Attribute[] | undefined,
): IdentityClaim[] | undefined {
  const identities = identitiesOf(attributes);
  if (identities.length === 0) return undefined;
  return identities.map((identity) => ({
    userId: String(identity.userId),
    providerName: identity.providerName,
    providerType: identity.providerType,
    issuer: identity.issuer ?? null,
    primary: String(identity.primary),
    dateCreated: String(identity.dateCreated),
  }));
}

export function newIdentity(
  provider: IdentityProviderConfig,
  userId: string,
  primary: boolean,
  now: Date,
): FederatedIdentity {
  return {
    userId,
    providerName: provider.ProviderName,
    providerType: provider.ProviderType,
    issuer: providerIssuer(provider),
    primary,
    dateCreated: now.getTime(),
  };
}

export function linkMatches(
  link: ProviderLink,
  providerName: string,
  userId: string,
  claims: Claims,
): boolean {
  if (link.providerName !== providerName) return false;
  const presented =
    link.attributeName === COGNITO_SUBJECT
      ? userId
      : claims[link.attributeName];
  return presented === link.attributeValue;
}

export function findLinkedUser<
  T extends {
    Username: string;
    Attributes: Attribute[];
    ProviderLinks?: ProviderLink[];
  },
>(
  users: readonly T[],
  providerName: string,
  userId: string,
  claims: Claims,
): T | undefined {
  const ownUsername = federatedUsername(providerName, userId);
  return users.find((user) => {
    if (user.Username === ownUsername) return false;
    if (user.ProviderLinks) {
      return user.ProviderLinks.some((link) =>
        linkMatches(link, providerName, userId, claims),
      );
    }
    return identitiesOf(user.Attributes).some(
      (identity) =>
        identity.providerName === providerName &&
        String(identity.userId) === userId,
    );
  });
}

export interface MockIdpField {
  label: string;
  claim: string;
  value: string;
}

export interface MockIdpDefaults {
  subjectClaim: string;
  subject: string;
  fields: MockIdpField[];
  extras: Array<[string, string]>;
}

const DEFAULT_SUBJECTS: Record<string, string> = {
  Google: "100000000000000000001",
  Facebook: "10150000000000001",
  LoginWithAmazon: "amzn1.account.AEXAMPLE000000000000000000000",
  SignInWithApple: "000001.0123456789abcdef0123456789abcdef.0001",
  SAML: "jane.doe@example.com",
  OIDC: "oidc-user-0001",
};

const DEFAULT_EMAILS: Record<string, string> = {
  Google: "jane.doe@gmail.com",
  SignInWithApple: "jane.doe@privaterelay.appleid.com",
};

const DEFAULT_EXTRAS: Record<string, Array<[string, string]>> = {
  Google: [
    ["email_verified", "true"],
    ["given_name", "Jane"],
    ["family_name", "Doe"],
  ],
  SignInWithApple: [["email_verified", "true"]],
  OIDC: [["email_verified", "true"]],
};

export function mockIdpDefaults(
  provider: IdentityProviderConfig,
): MockIdpDefaults {
  const type = provider.ProviderType;
  const mapping = provider.AttributeMapping ?? {};
  const claimFor = (poolAttribute: string, fallback: string) =>
    mapping[poolAttribute] ?? fallback;
  return {
    subjectClaim: subjectClaimName(type),
    subject: DEFAULT_SUBJECTS[type] ?? DEFAULT_SUBJECTS.OIDC,
    fields: [
      {
        label: "Email",
        claim: claimFor("email", "email"),
        value: DEFAULT_EMAILS[type] ?? "jane.doe@example.com",
      },
      { label: "Name", claim: claimFor("name", "name"), value: "Jane Doe" },
      {
        label: "Phone",
        claim: claimFor("phone_number", "phone_number"),
        value: "",
      },
    ],
    extras: DEFAULT_EXTRAS[type] ?? [],
  };
}

const asList = (value: unknown): string[] => {
  if (Array.isArray(value)) return value.map(String);
  return value === undefined ? [] : [String(value)];
};

export function claimsFromForm(
  provider: IdentityProviderConfig,
  body: Record<string, unknown>,
): Claims {
  const claims: Claims = {};
  const names = asList(body.claim_name);
  const values = asList(body.claim_value);
  names.forEach((rawName, index) => {
    const name = rawName.trim();
    const value = values[index] ?? "";
    if (name && value !== "") claims[name] = value;
  });
  const subject = typeof body.subject === "string" ? body.subject.trim() : "";
  if (subject) claims[subjectClaimName(provider.ProviderType)] = subject;
  return claims;
}
