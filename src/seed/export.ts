import { isDeepStrictEqual } from "node:util";
import type { SchemaAttributeType } from "@aws-sdk/client-cognito-identity-provider";
import type { CognitoService } from "../services";
import type { Clock } from "../services/clock";
import { USER_POOL_AWS_DEFAULTS } from "../services/cognitoService";
import type { Context } from "../services/context";
import { attributeValue, type UserPool } from "../services/userPoolService";
import {
  SEED_VERSION,
  type SeedClient,
  type SeedFile,
  type SeedIdentityProvider,
  type SeedResourceServer,
  type SeedUser,
  type SeedUserPool,
} from "./types";

export const PASSWORDS_NOT_EXPORTED =
  "Passwords are not exported (Cognito never returns them). Users re-created from this seed have no usable password until you add Password or TemporaryPassword to them.";

const POOL_FIELDS = [
  "Policies",
  "LambdaConfig",
  "AutoVerifiedAttributes",
  "AliasAttributes",
  "UsernameAttributes",
  "SmsVerificationMessage",
  "EmailVerificationMessage",
  "EmailVerificationSubject",
  "VerificationMessageTemplate",
  "SmsAuthenticationMessage",
  "MfaConfiguration",
  "UserAttributeUpdateSettings",
  "DeviceConfiguration",
  "EmailConfiguration",
  "SmsConfiguration",
  "UserPoolTags",
  "AdminCreateUserConfig",
  "UserPoolAddOns",
  "UsernameConfiguration",
  "AccountRecoverySetting",
] as const;

const CLIENT_FIELDS = [
  "RefreshTokenValidity",
  "AccessTokenValidity",
  "IdTokenValidity",
  "TokenValidityUnits",
  "ReadAttributes",
  "WriteAttributes",
  "ExplicitAuthFlows",
  "SupportedIdentityProviders",
  "CallbackURLs",
  "LogoutURLs",
  "DefaultRedirectURI",
  "AllowedOAuthFlows",
  "AllowedOAuthScopes",
  "AllowedOAuthFlowsUserPoolClient",
  "AnalyticsConfiguration",
  "PreventUserExistenceErrors",
  "EnableTokenRevocation",
  "AuthSessionValidity",
  "RefreshTokenRotation",
] as const;

const defined = <T extends object>(value: T): T =>
  Object.fromEntries(
    Object.entries(value).filter(([, v]) => v !== undefined && v !== null),
  ) as T;

const exportSchema = (
  attributes: SchemaAttributeType[] | undefined,
): SchemaAttributeType[] => {
  const defaults = USER_POOL_AWS_DEFAULTS.SchemaAttributes ?? [];
  const out: SchemaAttributeType[] = [];
  for (const attr of attributes ?? []) {
    if (attr.Name?.startsWith("custom:")) {
      out.push(defined({ ...attr, Name: attr.Name.slice("custom:".length) }));
      continue;
    }
    const standard = defaults.find((d) => d.Name === attr.Name);
    if (
      !standard ||
      !isDeepStrictEqual(defined({ ...standard }), defined({ ...attr }))
    ) {
      out.push(defined({ ...attr }));
    }
  }
  return out;
};

const usernameFor = (
  pool: UserPool,
  user: { Username: string; Attributes: { Name: string; Value?: string }[] },
) => {
  if (user.Username !== attributeValue("sub", user.Attributes)) {
    return user.Username;
  }
  for (const attr of pool.UsernameAttributes ?? []) {
    const value = attributeValue(attr, user.Attributes);
    if (value) return value;
  }
  return user.Username;
};

export const exportUserPool = async (
  ctx: Context,
  cognito: CognitoService,
  userPoolId: string,
): Promise<SeedUserPool> => {
  const service = await cognito.getUserPool(ctx, userPoolId);
  const pool = service.options;
  const options = pool as unknown as Record<string, unknown>;

  const identityProviders = (
    (options._identityProviders as SeedIdentityProvider[] | undefined) ?? []
  ).map((p) =>
    defined({
      ProviderName: p.ProviderName,
      ProviderType: p.ProviderType,
      ProviderDetails: p.ProviderDetails,
      AttributeMapping: p.AttributeMapping,
      IdpIdentifiers: p.IdpIdentifiers,
    }),
  );
  const resourceServers = (
    (options._resourceServers as SeedResourceServer[] | undefined) ?? []
  ).map((s) =>
    defined({ Identifier: s.Identifier, Name: s.Name, Scopes: s.Scopes }),
  );

  const clients: SeedClient[] = (
    await cognito.listAppClients(ctx, pool.Id)
  ).map((client) => {
    const record = client as unknown as Record<string, unknown>;
    return defined({
      ClientId: client.ClientId,
      ClientName: client.ClientName,
      ClientSecret: client.ClientSecret,
      ...Object.fromEntries(CLIENT_FIELDS.map((f) => [f, record[f]])),
    }) as SeedClient;
  });

  const groups = (await service.listGroups(ctx)).map((g) =>
    defined({
      GroupName: g.GroupName,
      Description: g.Description,
      Precedence: g.Precedence,
      RoleArn: g.RoleArn,
    }),
  );

  const users: SeedUser[] = [];
  for (const user of await service.listUsers(ctx)) {
    users.push(
      defined({
        Username: usernameFor(pool, user),
        UserAttributes: user.Attributes.map((a) => ({
          Name: a.Name,
          Value: a.Value ?? "",
        })).sort((a, b) => a.Name.localeCompare(b.Name)),
        UserStatus: user.UserStatus as SeedUser["UserStatus"],
        Enabled: user.Enabled,
        Groups: [...(await service.listUserGroupMembership(ctx, user))],
      }),
    );
  }

  const schema = exportSchema(pool.SchemaAttributes);
  return defined({
    Id: pool.Id,
    PoolName: pool.Name ?? pool.Id,
    ...Object.fromEntries(POOL_FIELDS.map((f) => [f, options[f]])),
    ...(schema.length ? { Schema: schema } : {}),
    ...(identityProviders.length
      ? { IdentityProviders: identityProviders }
      : {}),
    ...(resourceServers.length ? { ResourceServers: resourceServers } : {}),
    Clients: clients,
    Groups: groups,
    Users: users,
  }) as SeedUserPool;
};

export const exportSeed = async (
  ctx: Context,
  services: { cognito: CognitoService; clock: Clock },
): Promise<SeedFile> => {
  const pools = await services.cognito.listUserPools(ctx);
  const userPools: SeedUserPool[] = [];
  for (const pool of [...pools].sort((a, b) => a.Id.localeCompare(b.Id))) {
    userPools.push(await exportUserPool(ctx, services.cognito, pool.Id));
  }
  return {
    $comment: `Exported by cognito-local on ${services.clock.get().toISOString()}. ${PASSWORDS_NOT_EXPORTED}`,
    Version: SEED_VERSION,
    UserPools: userPools,
  };
};
