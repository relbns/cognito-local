import { randomBytes } from "node:crypto";
import { isDeepStrictEqual } from "node:util";
import type { CreateUserPoolRequest } from "@aws-sdk/client-cognito-identity-provider";
import * as uuid from "uuid";
import { CognitoError } from "../errors";
import { COGNITO_PROVIDER } from "../oauth2/oauthRequest";
import type { Services } from "../services";
import { enforceAliasUniqueness } from "../services/aliases";
import {
  type AppClient,
  assertAuthSessionValidity,
  assertRefreshTokenRotation,
  newId,
} from "../services/appClient";
import type { Context } from "../services/context";
import { assertPasswordConformsToPolicy } from "../services/passwordPolicy";
import type { Present } from "../services/sdkTypes";
import {
  attributesAppend,
  attributesInclude,
  attributeValue,
  type Group,
  type User,
  type UserPool,
  type UserPoolService,
} from "../services/userPoolService";
import type { WebAuthnCredential } from "../services/webAuthn";
import { AdminCreateUser } from "../targets/adminCreateUser";
import {
  newUserPoolId,
  userPoolArn,
  userPoolSettingsFromRequest,
} from "../targets/createUserPool";
import type {
  SeedChange,
  SeedClient,
  SeedEntityKind,
  SeedFile,
  SeedGroup,
  SeedIdentityProvider,
  SeedPasskey,
  SeedResourceServer,
  SeedResult,
  SeedUser,
  SeedUserPool,
} from "./types";

export type SeedServices = Pick<
  Services,
  "clock" | "cognito" | "config" | "messages"
>;

export class SeedApplyError extends Error {
  public constructor(
    public readonly source: string,
    public readonly path: string,
    message: string,
  ) {
    super(`Cannot apply seed ${source}: ${path}: ${message}`);
    this.name = "SeedApplyError";
  }
}

const normalize = (value: unknown) =>
  value === undefined ? undefined : JSON.parse(JSON.stringify(value));

const differs = (a: unknown, b: unknown) =>
  !isDeepStrictEqual(normalize(a), normalize(b));

const changedKeys = (
  desired: Record<string, unknown>,
  existing: Record<string, unknown>,
) => Object.keys(desired).filter((k) => differs(desired[k], existing[k]));

const errorMessage = (e: unknown) =>
  e instanceof CognitoError
    ? `${e.code}: ${e.message}`
    : ((e as Error)?.message ?? String(e));

interface StoredIdentityProvider extends SeedIdentityProvider {
  UserPoolId: string;
  CreationDate: Date;
  LastModifiedDate: Date;
}

interface StoredResourceServer extends SeedResourceServer {
  UserPoolId: string;
}

// Pool settings a CreateUserPool request does not carry; the seed stores them as given.
const SEED_ONLY_POOL_KEYS = new Set(["WebAuthnConfiguration"]);

const POOL_SETTING_FOR_SEED_KEY: Record<string, string> = {
  PoolName: "Name",
  Schema: "SchemaAttributes",
};

const looksLikeAlias = (pool: UserPool, username: string) =>
  (pool.UsernameAttributes?.includes("email") && username.includes("@")) ||
  (pool.UsernameAttributes?.includes("phone_number") &&
    /^\+\d+$/.test(username));

const needsDirectWrite = (pool: UserPool, user: SeedUser) =>
  user.UserStatus === "EXTERNAL_PROVIDER" ||
  (!!pool.UsernameAttributes?.length && !looksLikeAlias(pool, user.Username));

const NESTED_POOL_KEYS = new Set([
  "Id",
  "Clients",
  "IdentityProviders",
  "ResourceServers",
  "Groups",
  "Users",
]);

const TOKEN_UNIT_DEFAULTS = {
  AccessToken: "hours",
  IdToken: "hours",
  RefreshToken: "days",
} as const;

class SeedApplier {
  private readonly changes: SeedChange[] = [];

  public constructor(
    private readonly ctx: Context,
    private readonly services: SeedServices,
    private readonly source: string,
  ) {}

  private record(
    kind: SeedEntityKind,
    id: string,
    userPoolId: string,
    action: SeedChange["action"],
    fields?: string[],
  ) {
    this.changes.push({
      kind,
      id,
      userPoolId,
      action,
      ...(fields?.length ? { fields } : {}),
    });
  }

  private async at<T>(path: string, fn: () => Promise<T>): Promise<T> {
    try {
      return await fn();
    } catch (e) {
      if (e instanceof SeedApplyError) throw e;
      throw new SeedApplyError(this.source, path, errorMessage(e));
    }
  }

  public async apply(seed: SeedFile): Promise<SeedResult> {
    for (const [i, pool] of seed.UserPools.entries()) {
      await this.applyPool(pool, `UserPools[${i}]`);
    }
    return { changes: this.changes };
  }

  private desiredPoolSettings(seedPool: SeedUserPool): Partial<UserPool> {
    const request = Object.fromEntries(
      Object.entries(seedPool).filter(
        ([k]) => !NESTED_POOL_KEYS.has(k) && !k.startsWith("$"),
      ),
    );
    const settings = userPoolSettingsFromRequest(
      request as unknown as Present<CreateUserPoolRequest>,
    ) as unknown as Record<string, unknown>;
    const desired: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(request)) {
      if (value === undefined) continue;
      const settingKey = POOL_SETTING_FOR_SEED_KEY[key] ?? key;
      desired[settingKey] = SEED_ONLY_POOL_KEYS.has(key)
        ? value
        : settings[settingKey];
    }
    return desired as Partial<UserPool>;
  }

  private async findPool(
    seedPool: SeedUserPool,
  ): Promise<UserPoolService | null> {
    const pools = await this.services.cognito.listUserPools(this.ctx);
    if (seedPool.Id) {
      return pools.some((p) => p.Id === seedPool.Id)
        ? this.services.cognito.getUserPool(this.ctx, seedPool.Id)
        : null;
    }
    const named = pools.filter((p) => p.Name === seedPool.PoolName);
    if (named.length > 1) {
      throw new Error(
        `${named.length} pools are named "${seedPool.PoolName}" (${named.map((p) => p.Id).join(", ")}); pin the pool with Id`,
      );
    }
    return named.length
      ? this.services.cognito.getUserPool(this.ctx, named[0].Id)
      : null;
  }

  private async applyPool(seedPool: SeedUserPool, path: string) {
    const pool = await this.at(path, async () => {
      const desired = this.desiredPoolSettings(seedPool);
      const now = this.services.clock.get();
      let service = await this.findPool(seedPool);
      let created = false;
      if (!service) {
        const id = seedPool.Id ?? newUserPoolId();
        await this.services.cognito.createUserPool(this.ctx, {
          ...userPoolSettingsFromRequest(
            seedPool as unknown as Present<CreateUserPoolRequest>,
          ),
          Arn: userPoolArn(id),
          CreationDate: now,
          Id: id,
          LastModifiedDate: now,
        });
        service = await this.services.cognito.getUserPool(this.ctx, id);
        created = true;
      }
      const options = service.options as unknown as Record<string, unknown>;
      const changed = changedKeys(desired, options);
      if (changed.length) {
        await service.updateOptions(this.ctx, {
          ...service.options,
          ...Object.fromEntries(
            changed.map((k) => [k, desired[k as keyof UserPool]]),
          ),
          ...(created ? {} : { LastModifiedDate: now }),
        });
      }
      this.record(
        "UserPool",
        service.options.Id,
        service.options.Id,
        created ? "created" : changed.length ? "updated" : "unchanged",
        created ? undefined : changed,
      );
      return service;
    });

    await this.applyIdentityProviders(
      pool,
      seedPool.IdentityProviders ?? [],
      path,
    );
    await this.applyResourceServers(pool, seedPool.ResourceServers ?? [], path);
    for (const [i, client] of (seedPool.Clients ?? []).entries()) {
      await this.at(`${path}.Clients[${i}] (${client.ClientName})`, () =>
        this.applyClient(pool, client),
      );
    }
    for (const [i, group] of (seedPool.Groups ?? []).entries()) {
      await this.at(`${path}.Groups[${i}] (${group.GroupName})`, () =>
        this.applyGroup(pool, group),
      );
    }
    for (const [i, user] of (seedPool.Users ?? []).entries()) {
      await this.at(`${path}.Users[${i}] (${user.Username})`, () =>
        this.applyUser(pool, user),
      );
    }
  }

  private async applyIdentityProviders(
    pool: UserPoolService,
    seedProviders: readonly SeedIdentityProvider[],
    path: string,
  ) {
    if (!seedProviders.length) return;
    const poolId = pool.options.Id;
    const now = this.services.clock.get();
    const stored: StoredIdentityProvider[] = [
      ...((pool.options as { _identityProviders?: StoredIdentityProvider[] })
        ._identityProviders ?? []),
    ];
    let dirty = false;
    for (const seedProvider of seedProviders) {
      const desired: Record<string, unknown> = {
        ProviderName: seedProvider.ProviderName,
        ProviderType: seedProvider.ProviderType,
        ProviderDetails: seedProvider.ProviderDetails ?? {},
        ...(seedProvider.AttributeMapping !== undefined && {
          AttributeMapping: seedProvider.AttributeMapping,
        }),
        ...(seedProvider.IdpIdentifiers !== undefined && {
          IdpIdentifiers: seedProvider.IdpIdentifiers,
        }),
      };
      const index = stored.findIndex(
        (p) => p.ProviderName === seedProvider.ProviderName,
      );
      if (index < 0) {
        stored.push({
          ...(desired as unknown as SeedIdentityProvider),
          UserPoolId: poolId,
          CreationDate: now,
          LastModifiedDate: now,
        });
        dirty = true;
        this.record(
          "IdentityProvider",
          seedProvider.ProviderName,
          poolId,
          "created",
        );
        continue;
      }
      const changed = changedKeys(
        desired,
        stored[index] as unknown as Record<string, unknown>,
      );
      if (changed.length) {
        stored[index] = { ...stored[index], ...desired, LastModifiedDate: now };
        dirty = true;
      }
      this.record(
        "IdentityProvider",
        seedProvider.ProviderName,
        poolId,
        changed.length ? "updated" : "unchanged",
        changed,
      );
    }
    if (dirty) {
      await this.at(`${path}.IdentityProviders`, () =>
        pool.updateOptions(this.ctx, {
          ...pool.options,
          _identityProviders: stored,
        } as UserPool),
      );
    }
  }

  private async applyResourceServers(
    pool: UserPoolService,
    seedServers: readonly SeedResourceServer[],
    path: string,
  ) {
    if (!seedServers.length) return;
    const poolId = pool.options.Id;
    const stored: StoredResourceServer[] = [
      ...((pool.options as { _resourceServers?: StoredResourceServer[] })
        ._resourceServers ?? []),
    ];
    let dirty = false;
    for (const seedServer of seedServers) {
      const desired: StoredResourceServer = {
        UserPoolId: poolId,
        Identifier: seedServer.Identifier,
        Name: seedServer.Name,
        Scopes: seedServer.Scopes ?? [],
      };
      const index = stored.findIndex(
        (s) => s.Identifier === desired.Identifier,
      );
      if (index < 0) {
        stored.push(desired);
        dirty = true;
        this.record("ResourceServer", desired.Identifier, poolId, "created");
        continue;
      }
      const changed = changedKeys(
        desired as unknown as Record<string, unknown>,
        stored[index] as unknown as Record<string, unknown>,
      );
      if (changed.length) {
        stored[index] = desired;
        dirty = true;
      }
      this.record(
        "ResourceServer",
        desired.Identifier,
        poolId,
        changed.length ? "updated" : "unchanged",
        changed,
      );
    }
    if (dirty) {
      await this.at(`${path}.ResourceServers`, () =>
        pool.updateOptions(this.ctx, {
          ...pool.options,
          _resourceServers: stored,
        } as UserPool),
      );
    }
  }

  private async applyClient(pool: UserPoolService, seedClient: SeedClient) {
    const poolId = pool.options.Id;
    const { ClientId, ClientSecret, GenerateSecret, ...fields } = seedClient;
    assertAuthSessionValidity(fields.AuthSessionValidity);
    assertRefreshTokenRotation(fields.RefreshTokenRotation);

    const knownProviders = [
      COGNITO_PROVIDER,
      ...(
        (pool.options as { _identityProviders?: SeedIdentityProvider[] })
          ._identityProviders ?? []
      ).map((p) => p.ProviderName),
    ];
    for (const provider of fields.SupportedIdentityProviders ?? []) {
      if (!knownProviders.includes(provider)) {
        throw new Error(
          `SupportedIdentityProviders: the provider ${provider} does not exist for User Pool ${poolId} (add it to IdentityProviders)`,
        );
      }
    }

    const existing = ClientId
      ? await this.services.cognito.getAppClient(this.ctx, ClientId)
      : ((await this.services.cognito.listAppClients(this.ctx, poolId)).find(
          (c) => c.ClientName === seedClient.ClientName,
        ) ?? null);
    if (existing && existing.UserPoolId !== poolId) {
      throw new Error(
        `ClientId ${ClientId} already belongs to user pool ${existing.UserPoolId}`,
      );
    }

    const desired: Record<string, unknown> = { ...fields };
    if (fields.TokenValidityUnits !== undefined || !existing) {
      desired.TokenValidityUnits = {
        ...TOKEN_UNIT_DEFAULTS,
        ...fields.TokenValidityUnits,
      };
    }
    for (const key of Object.keys(desired)) {
      if (key.startsWith("$")) delete desired[key];
    }

    const now = this.services.clock.get();
    if (!existing) {
      const client = {
        ...desired,
        ClientId: ClientId ?? newId(),
        ClientSecret: ClientSecret ?? (GenerateSecret ? newId() : undefined),
        CreationDate: now,
        LastModifiedDate: now,
        UserPoolId: poolId,
      } as AppClient;
      await pool.saveAppClient(this.ctx, client);
      this.record("Client", client.ClientId, poolId, "created");
      return;
    }

    const changed = changedKeys(
      desired,
      existing as unknown as Record<string, unknown>,
    );
    let secret = existing.ClientSecret;
    if (ClientSecret !== undefined && ClientSecret !== existing.ClientSecret) {
      secret = ClientSecret;
    } else if (GenerateSecret === true && !existing.ClientSecret) {
      secret = newId();
    } else if (
      GenerateSecret === false &&
      ClientSecret === undefined &&
      existing.ClientSecret
    ) {
      secret = undefined;
    }
    if (secret !== existing.ClientSecret) changed.push("ClientSecret");

    if (changed.length) {
      await pool.saveAppClient(this.ctx, {
        ...existing,
        ...desired,
        ClientSecret: secret,
        LastModifiedDate: now,
      } as AppClient);
    }
    this.record(
      "Client",
      existing.ClientId,
      poolId,
      changed.length ? "updated" : "unchanged",
      changed,
    );
  }

  private async applyGroup(pool: UserPoolService, seedGroup: SeedGroup) {
    const poolId = pool.options.Id;
    const existing = await pool.getGroupByGroupName(
      this.ctx,
      seedGroup.GroupName,
    );
    const desired: Record<string, unknown> = Object.fromEntries(
      Object.entries(seedGroup).filter(([k]) => !k.startsWith("$")),
    );
    const now = this.services.clock.get();
    if (!existing) {
      await pool.saveGroup(this.ctx, {
        ...desired,
        GroupName: seedGroup.GroupName,
        CreationDate: now,
        LastModifiedDate: now,
      } as Group);
      this.record("Group", seedGroup.GroupName, poolId, "created");
      return;
    }
    const changed = changedKeys(
      desired,
      existing as unknown as Record<string, unknown>,
    );
    if (changed.length) {
      await pool.saveGroup(this.ctx, {
        ...existing,
        ...desired,
        LastModifiedDate: now,
      } as Group);
    }
    this.record(
      "Group",
      seedGroup.GroupName,
      poolId,
      changed.length ? "updated" : "unchanged",
      changed,
    );
  }

  private async createUser(
    pool: UserPoolService,
    seedUser: SeedUser,
  ): Promise<User> {
    const { clock, cognito, config, messages } = this.services;
    if (seedUser.Password !== undefined) {
      assertPasswordConformsToPolicy(config, pool.options, seedUser.Password);
    }
    if (needsDirectWrite(pool.options, seedUser)) {
      return this.writeUser(pool, seedUser);
    }
    const created = await AdminCreateUser({ clock, cognito, config, messages })(
      this.ctx,
      {
        UserPoolId: pool.options.Id,
        Username: seedUser.Username,
        UserAttributes: seedUser.UserAttributes,
        TemporaryPassword: seedUser.TemporaryPassword,
        MessageAction: "SUPPRESS",
      },
    );
    const username = created.User?.Username ?? seedUser.Username;
    let user = (await pool.getUserByUsername(this.ctx, username)) as User;

    const pinnedSub = attributeValue("sub", seedUser.UserAttributes);
    if (
      pinnedSub &&
      user.Username !== pinnedSub &&
      pool.options.UsernameAttributes?.length
    ) {
      await pool.deleteUser(this.ctx, user);
      user = { ...user, Username: pinnedSub };
    }

    const status =
      seedUser.UserStatus ??
      (seedUser.TemporaryPassword !== undefined
        ? "FORCE_CHANGE_PASSWORD"
        : "CONFIRMED");
    user = {
      ...user,
      Password:
        seedUser.Password ??
        (seedUser.TemporaryPassword === undefined
          ? randomBytes(24).toString("base64url")
          : user.Password),
      Enabled: seedUser.Enabled ?? true,
      UserStatus: status,
    };
    await pool.saveUser(this.ctx, user);
    return user;
  }

  // Federated users and other usernames AdminCreateUser would refuse in an alias pool.
  private async writeUser(
    pool: UserPoolService,
    seedUser: SeedUser,
  ): Promise<User> {
    const attributes = attributesInclude("sub", seedUser.UserAttributes)
      ? [...(seedUser.UserAttributes ?? [])]
      : [{ Name: "sub", Value: uuid.v4() }, ...(seedUser.UserAttributes ?? [])];
    await enforceAliasUniqueness(
      this.ctx,
      pool,
      this.services.clock,
      seedUser.Username,
      attributes,
      { usernameConflict: "UsernameExistsException" },
    );
    const external = seedUser.UserStatus === "EXTERNAL_PROVIDER";
    const now = this.services.clock.get();
    const user: User = {
      Username: seedUser.Username,
      Attributes: attributes.sort((a, b) => a.Name.localeCompare(b.Name)),
      Enabled: seedUser.Enabled ?? true,
      UserStatus:
        seedUser.UserStatus ??
        (seedUser.TemporaryPassword !== undefined
          ? "FORCE_CHANGE_PASSWORD"
          : "CONFIRMED"),
      Password: external
        ? ""
        : (seedUser.Password ??
          seedUser.TemporaryPassword ??
          randomBytes(24).toString("base64url")),
      RefreshTokens: [],
      UserCreateDate: now,
      UserLastModifiedDate: now,
    };
    await pool.saveUser(this.ctx, user);
    return user;
  }

  private async applyUser(pool: UserPoolService, seedUser: SeedUser) {
    const poolId = pool.options.Id;
    const existing = await pool.getUserByUsername(this.ctx, seedUser.Username);
    let user: User;
    const changed: string[] = [];

    if (!existing) {
      user = await this.createUser(pool, seedUser);
    } else {
      user = existing;
      const pinnedSub = attributeValue("sub", seedUser.UserAttributes);
      const currentSub = attributeValue("sub", existing.Attributes);
      if (pinnedSub && pinnedSub !== currentSub) {
        throw new Error(
          `sub is ${currentSub} in the data directory but ${pinnedSub} in the seed; a sub cannot change (reset the data directory to re-create the user)`,
        );
      }
      const attributeChanges = (seedUser.UserAttributes ?? []).filter(
        (a) =>
          a.Name !== "sub" &&
          attributeValue(a.Name, existing.Attributes) !== a.Value,
      );
      if (attributeChanges.length) {
        await enforceAliasUniqueness(
          this.ctx,
          pool,
          this.services.clock,
          existing.Username,
          attributeChanges,
        );
        user = {
          ...user,
          Attributes: attributesAppend(user.Attributes, ...attributeChanges),
        };
        changed.push(
          ...attributeChanges.map((a) => `UserAttributes.${a.Name}`),
        );
      }
      if (
        seedUser.Enabled !== undefined &&
        seedUser.Enabled !== existing.Enabled
      ) {
        user = { ...user, Enabled: seedUser.Enabled };
        changed.push("Enabled");
      }
      if (changed.length) {
        user = { ...user, UserLastModifiedDate: this.services.clock.get() };
        await pool.saveUser(this.ctx, user);
      }
    }

    if (seedUser.Groups) {
      const current = await pool.listUserGroupMembership(this.ctx, user);
      const wanted = new Set(seedUser.Groups);
      for (const name of wanted) {
        if (current.includes(name)) continue;
        const group = await pool.getGroupByGroupName(this.ctx, name);
        if (!group) {
          throw new Error(
            `Groups: group ${name} does not exist in user pool ${poolId} (add it to Groups)`,
          );
        }
        await pool.addUserToGroup(this.ctx, group, user);
        changed.push(`Groups+${name}`);
      }
      for (const name of current) {
        if (wanted.has(name)) continue;
        const group = await pool.getGroupByGroupName(this.ctx, name);
        if (group) await pool.removeUserFromGroup(this.ctx, group, user);
        changed.push(`Groups-${name}`);
      }
    }

    if (seedUser.Passkeys) {
      changed.push(
        ...(await this.applyPasskeys(pool, user, seedUser.Passkeys)),
      );
    }

    this.record(
      "User",
      seedUser.Username,
      poolId,
      !existing ? "created" : changed.length ? "updated" : "unchanged",
      existing ? changed : undefined,
    );
  }

  // The seed lists the user's passkeys; a stored one keeps its higher counter and last use.
  private async applyPasskeys(
    pool: UserPoolService,
    user: User,
    passkeys: SeedPasskey[],
  ): Promise<string[]> {
    const now = this.services.clock.get();
    const stored =
      (await pool.getUserByUsername(this.ctx, user.Username)) ?? user;
    const existing = stored.WebAuthnCredentials ?? [];
    const wanted: WebAuthnCredential[] = passkeys.map((p) => {
      const prior = existing.find((c) => c.CredentialId === p.CredentialId);
      return {
        CredentialId: p.CredentialId,
        PublicKey: p.PublicKey,
        Algorithm: p.Algorithm,
        RelyingPartyId: p.RelyingPartyId,
        FriendlyCredentialName:
          p.FriendlyCredentialName ?? prior?.FriendlyCredentialName ?? "",
        AuthenticatorAttachment:
          p.AuthenticatorAttachment ?? prior?.AuthenticatorAttachment,
        AuthenticatorTransports:
          p.AuthenticatorTransports ?? prior?.AuthenticatorTransports ?? [],
        SignCount: Math.max(p.SignCount ?? 0, prior?.SignCount ?? 0),
        CreatedDate: p.CreatedDate
          ? new Date(p.CreatedDate)
          : (prior?.CreatedDate ?? now),
        ...(prior?.LastAuthenticatedDate
          ? { LastAuthenticatedDate: prior.LastAuthenticatedDate }
          : {}),
      };
    });
    const changes = [
      ...wanted
        .filter((w) => !existing.some((e) => e.CredentialId === w.CredentialId))
        .map((w) => `Passkeys+${w.CredentialId}`),
      ...existing
        .filter((e) => !wanted.some((w) => w.CredentialId === e.CredentialId))
        .map((e) => `Passkeys-${e.CredentialId}`),
      ...wanted
        .filter((w) =>
          existing.some(
            (e) =>
              e.CredentialId === w.CredentialId &&
              (e.PublicKey !== w.PublicKey ||
                e.Algorithm !== w.Algorithm ||
                e.RelyingPartyId !== w.RelyingPartyId),
          ),
        )
        .map((w) => `Passkeys.${w.CredentialId}`),
    ];
    if (changes.length) {
      await pool.updateUser(this.ctx, stored, (latest) => ({
        ...latest,
        WebAuthnCredentials: wanted,
      }));
    }
    return changes;
  }
}

export const applySeed = (
  ctx: Context,
  services: SeedServices,
  seed: SeedFile,
  source = "seed",
): Promise<SeedResult> => new SeedApplier(ctx, services, source).apply(seed);

export const summarizeSeedResult = (result: SeedResult) => {
  const count = (action: SeedChange["action"]) =>
    result.changes.filter((c) => c.action === action).length;
  return {
    created: count("created"),
    updated: count("updated"),
    unchanged: count("unchanged"),
  };
};

export const formatSeedResult = (result: SeedResult): string[] =>
  result.changes
    .filter((c) => c.action !== "unchanged")
    .map(
      (c) =>
        `${c.action} ${c.kind} ${c.id}${c.kind === "UserPool" ? "" : ` in ${c.userPoolId}`}${c.fields?.length ? ` (${c.fields.join(", ")})` : ""}`,
    );
