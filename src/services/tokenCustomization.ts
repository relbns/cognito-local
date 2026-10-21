import type { Group } from "./userPoolService";

/** The `version` of a pre token generation event: V1_0, V2_0 or V3_0 in LambdaConfig. */
export type PreTokenGenerationVersion = "1" | "2" | "3";

const LAMBDA_VERSIONS: Record<string, PreTokenGenerationVersion> = {
  V1_0: "1",
  V2_0: "2",
  V3_0: "3",
};

export const preTokenGenerationVersion = (
  lambdaConfig: object | undefined,
): PreTokenGenerationVersion => {
  const config = (lambdaConfig as { PreTokenGenerationConfig?: unknown })
    ?.PreTokenGenerationConfig;
  const version =
    config && typeof config === "object"
      ? (config as { LambdaVersion?: unknown }).LambdaVersion
      : undefined;
  return (typeof version === "string" && LAMBDA_VERSIONS[version]) || "1";
};

export interface GroupConfiguration {
  groupsToOverride: string[];
  iamRolesToOverride: string[];
  preferredRole: string | null;
}

export interface GroupOverrideDetails {
  groupsToOverride?: string[] | null;
  iamRolesToOverride?: string[] | null;
  preferredRole?: string | null;
}

export interface TokenGenerationOverrides {
  claimsToAddOrOverride?: Record<string, unknown> | null;
  claimsToSuppress?: string[] | null;
}

export interface AccessTokenGenerationOverrides
  extends TokenGenerationOverrides {
  scopesToAdd?: string[] | null;
  scopesToSuppress?: string[] | null;
}

export interface ClaimsOverrideDetails extends TokenGenerationOverrides {
  groupOverrideDetails?: GroupOverrideDetails | null;
}

export interface ClaimsAndScopeOverrideDetails {
  idTokenGeneration?: TokenGenerationOverrides | null;
  accessTokenGeneration?: AccessTokenGenerationOverrides | null;
  groupOverrideDetails?: GroupOverrideDetails | null;
}

export interface PreTokenGenerationResponse {
  claimsOverrideDetails?: ClaimsOverrideDetails | null;
  claimsAndScopeOverrideDetails?: ClaimsAndScopeOverrideDetails | null;
}

export type Claims = Record<string, unknown>;

const GROUP_CLAIMS = [
  "cognito:groups",
  "cognito:roles",
  "cognito:preferred_role",
] as const;

const FIXED_CLAIMS = new Set([
  "acr",
  "amr",
  "at_hash",
  "aud",
  "auth_time",
  "azp",
  "client_id",
  "device_key",
  "event_id",
  "exp",
  "iat",
  "identities",
  "iss",
  "jti",
  "nbf",
  "nonce",
  "origin_jti",
  "sub",
  "token_use",
  "username",
  "version",
]);

// AWS refuses complex values for these ID token claims.
const SCALAR_ID_TOKEN_CLAIMS = new Set([
  "address",
  "email_verified",
  "phone_number_verified",
  "updated_at",
]);

type TokenKind = "id" | "access";

const canAddOrOverride = (
  claim: string,
  value: unknown,
  kind: TokenKind,
  clientId: string,
): boolean => {
  if (claim.startsWith("cognito:") || claim.startsWith("dev:")) return false;
  if (kind === "access" && claim === "aud") return value === clientId;
  if (kind === "access" && claim === "scope") return false;
  if (FIXED_CLAIMS.has(claim)) return false;
  if (kind === "id" && SCALAR_ID_TOKEN_CLAIMS.has(claim)) {
    return value === null || typeof value !== "object";
  }
  return true;
};

const canSuppress = (claim: string, kind: TokenKind): boolean => {
  if (claim === "cognito:groups") return true;
  if (claim.startsWith("cognito:")) return false;
  if (claim.startsWith("dev:")) return true;
  if (kind === "access" && claim === "scope") return false;
  return !FIXED_CLAIMS.has(claim);
};

const list = (value: unknown): string[] =>
  Array.isArray(value)
    ? value.filter((v): v is string => typeof v === "string")
    : [];

/** groupConfiguration of the event: the user's groups, their roles and the role of the group that takes precedence. */
export const groupConfigurationFor = (
  groups: readonly Pick<Group, "GroupName" | "RoleArn" | "Precedence">[],
): GroupConfiguration => {
  const withRoles = groups.filter((g) => g.RoleArn);
  const rank = (g: Pick<Group, "Precedence">) =>
    g.Precedence ?? Number.POSITIVE_INFINITY;
  const best = Math.min(...withRoles.map(rank));
  const preferred = [
    ...new Set(withRoles.filter((g) => rank(g) === best).map((g) => g.RoleArn)),
  ];
  return {
    groupsToOverride: groups.map((g) => g.GroupName),
    iamRolesToOverride: [...new Set(withRoles.map((g) => g.RoleArn as string))],
    preferredRole: preferred.length === 1 ? (preferred[0] as string) : null,
  };
};

const setList = (token: Claims, claim: string, values: string[]): void => {
  if (values.length) token[claim] = values;
  else delete token[claim];
};

/** Writes cognito:groups to both tokens and cognito:roles / cognito:preferred_role to the ID token. */
export const applyGroupClaims = (
  idToken: Claims,
  accessToken: Claims | undefined,
  config: GroupOverrideDetails | null,
): void => {
  const groups = list(config?.groupsToOverride);
  setList(idToken, "cognito:groups", groups);
  if (accessToken) setList(accessToken, "cognito:groups", groups);
  setList(idToken, "cognito:roles", list(config?.iamRolesToOverride));
  if (typeof config?.preferredRole === "string" && config.preferredRole) {
    idToken["cognito:preferred_role"] = config.preferredRole;
  } else {
    delete idToken["cognito:preferred_role"];
  }
};

const applyClaimOverrides = (
  token: Claims,
  overrides: TokenGenerationOverrides | null | undefined,
  kind: TokenKind,
  clientId: string,
): void => {
  const toAdd = overrides?.claimsToAddOrOverride;
  if (toAdd && typeof toAdd === "object") {
    for (const [claim, value] of Object.entries(toAdd)) {
      if (canAddOrOverride(claim, value, kind, clientId)) token[claim] = value;
    }
  }
  for (const claim of list(overrides?.claimsToSuppress)) {
    if (!canSuppress(claim, kind)) continue;
    if (claim === "cognito:groups") {
      for (const groupClaim of GROUP_CLAIMS) delete token[groupClaim];
    } else {
      delete token[claim];
    }
  }
};

const applyScopeOverrides = (
  token: Claims,
  overrides: AccessTokenGenerationOverrides | null | undefined,
): void => {
  const current = typeof token.scope === "string" ? token.scope.split(" ") : [];
  const suppress = new Set(list(overrides?.scopesToSuppress));
  const scopes = [
    ...new Set([
      ...current,
      ...list(overrides?.scopesToAdd).filter((s) => s && !/\s/.test(s)),
    ]),
  ].filter((s) => s && !suppress.has(s));
  if (scopes.length) token.scope = scopes.join(" ");
  else delete token.scope;
};

export interface TokenClaims {
  idToken?: Claims;
  accessToken: Claims;
}

/** Applies a trigger response to copies of the token claims, by the rules of the event version. */
export const applyPreTokenGenerationResponse = (
  version: PreTokenGenerationVersion,
  response: PreTokenGenerationResponse | null | undefined,
  { idToken, accessToken }: TokenClaims,
  clientId: string,
): TokenClaims => {
  const id = idToken ? { ...idToken } : undefined;
  const access = { ...accessToken };

  if (version === "1") {
    const details = response?.claimsOverrideDetails;
    if (id && details && details.groupOverrideDetails !== undefined) {
      applyGroupClaims(id, access, details.groupOverrideDetails);
    }
    if (id) applyClaimOverrides(id, details, "id", clientId);
    return { idToken: id, accessToken: access };
  }

  const details = response?.claimsAndScopeOverrideDetails;
  if (id && details && details.groupOverrideDetails !== undefined) {
    applyGroupClaims(id, access, details.groupOverrideDetails);
  }
  if (id) applyClaimOverrides(id, details?.idTokenGeneration, "id", clientId);
  applyClaimOverrides(
    access,
    details?.accessTokenGeneration,
    "access",
    clientId,
  );
  applyScopeOverrides(access, details?.accessTokenGeneration);
  return { idToken: id, accessToken: access };
};
