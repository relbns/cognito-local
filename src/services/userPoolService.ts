import type {
  MFAOptionType,
  SchemaAttributeType,
  UserPoolType,
  UserStatusType,
  WebAuthnConfigurationType,
} from "@aws-sdk/client-cognito-identity-provider";
import { InvalidParameterError, NotAuthorizedError } from "../errors";
import type { AppClient } from "./appClient";
import type { Clock } from "./clock";
import type { Context } from "./context";
import type { DataStore } from "./dataStore/dataStore";
import type { DataStoreFactory } from "./dataStore/factory";
import { FilterConfig } from "./filter";
import type { Attribute } from "./sdkTypes";
import { withRefreshToken } from "./tokenRevocation";
import type {
  WebAuthnCredential,
  WebAuthnRegistrationChallenge,
} from "./webAuthn";

export interface MFAOption {
  DeliveryMedium: "SMS";
  AttributeName: "phone_number";
}

export const attribute = (
  name: string,
  value: string | undefined,
): Attribute => ({ Name: name, Value: value });

export const attributesIncludeMatch = (
  attributeName: string,
  attributeValue: string,
  attributes: Attribute[] | undefined,
) =>
  !!(attributes ?? []).find(
    (x) => x.Name === attributeName && x.Value === attributeValue,
  );

export const attributesInclude = (
  attributeName: string,
  attributes: Attribute[] | undefined,
) => !!(attributes ?? []).find((x) => x.Name === attributeName);

export const attributeValue = (
  attributeName: string | undefined,
  attributes: Attribute[] | undefined,
) => (attributes ?? []).find((x) => x.Name === attributeName)?.Value;

export const attributesToRecord = (
  attributes: Attribute[] | undefined,
): Record<string, string> =>
  (attributes ?? []).reduce(
    (acc, attr) => {
      if (attr.Name && attr.Value) {
        acc[attr.Name] = attr.Value;
      }
      return acc;
    },
    {} as Record<string, string>,
  );

export const attributesFromRecord = (
  attributes: Record<string, string>,
): Attribute[] =>
  Object.entries(attributes)
    .map(([Name, Value]) => ({ Name, Value }))
    .sort((a, b) => a.Name.localeCompare(b.Name));

export const attributesAppend = (
  attributes: Attribute[] | undefined,
  ...toAppend: Attribute[]
): Attribute[] => {
  const attributeSet = attributesToRecord(attributes);

  for (const attr of toAppend) {
    if (attr.Value) {
      attributeSet[attr.Name] = attr.Value;
    } else {
      delete attributeSet[attr.Name];
    }
  }

  return attributesFromRecord(attributeSet);
};

export const attributesRemove = (
  attributes: Attribute[] | undefined,
  ...toRemove: readonly string[]
): Attribute[] => attributes?.filter((x) => !toRemove.includes(x.Name)) ?? [];

export const customAttributes = (
  attributes: Attribute[] | undefined,
): Attribute[] =>
  (attributes ?? []).filter((attr) => attr.Name.startsWith("custom:"));

// UsernameConfiguration.CaseSensitive defaults to true; false folds usernames and the email and
// preferred_username aliases to lower case for every comparison (UsernameConfigurationType).
export const isCaseInsensitivePool = (
  userPool: Pick<UserPool, "UsernameConfiguration">,
): boolean => userPool.UsernameConfiguration?.CaseSensitive === false;

export const usernameComparer = (
  userPool: Pick<UserPool, "UsernameConfiguration">,
): ((value: string | undefined) => string | undefined) =>
  isCaseInsensitivePool(userPool)
    ? (value) => value?.toLowerCase()
    : (value) => value;

export interface User {
  Attributes: Attribute[];
  Enabled: boolean;
  MFAOptions?: MFAOptionType[];
  PreferredMfaSetting?: string;
  UserCreateDate: Date;
  UserLastModifiedDate: Date;
  UserMFASettingList?: string[];
  Username: string;
  UserStatus: UserStatusType;

  // extra attributes for Cognito Local
  Password: string;
  AttributeVerificationCode?: string;
  ConfirmationCode?: string;
  MFACode?: string;
  RefreshTokens: string[];
  /** Rotated-out refresh tokens that stay valid until ExpiresAt (epoch seconds), the client's retry grace period. */
  RefreshTokenGracePeriods?: RefreshTokenGracePeriod[];
  /** Refresh-token sessions whose access tokens are still honoured; emptied by a global sign-out. */
  TokenOrigins?: TokenOrigin[];
  Devices?: any[];

  /**
   * UnverifiedAttributeChanges is a list of attributes that have been requested to be changed
   * but have not yet been verified. This is used to track changes that require user verification
   * before they can be applied to the user.
   */
  UnverifiedAttributeChanges?: Attribute[];

  /**
   * SoftwareTokenMfaConfiguration stores the user's TOTP secret and verification
   * state. Internal only — never returned by GetUser / AdminGetUser responses.
   */
  SoftwareTokenMfaConfiguration?: {
    Secret: string;
    Verified: boolean;
    FriendlyDeviceName?: string;
  };

  // Federated identities linked by AdminLinkProviderForUser. Internal only.
  ProviderLinks?: ProviderLink[];

  // Registered passkeys, the pending registration challenge and passkey MFA. Internal only.
  WebAuthnCredentials?: WebAuthnCredential[];
  WebAuthnRegistration?: WebAuthnRegistrationChallenge;
  WebAuthnMfaEnabled?: boolean;
}

export interface RefreshTokenGracePeriod {
  Token: string;
  ExpiresAt: number;
}

export interface TokenOrigin {
  Jti: string;
  ClientId: string;
  /** Epoch seconds. */
  ExpiresAt: number;
}

export interface ProviderLink {
  providerName: string;
  attributeName: string;
  attributeValue: string;
}

export interface Group {
  /**
   * The name of the group.
   */
  GroupName: string;
  /**
   * A string containing the description of the group.
   */
  Description?: string;
  /**
   * The role ARN for the group.
   */
  RoleArn?: string;
  /**
   * A nonnegative integer value that specifies the precedence of this group relative to the other groups that a user can belong to in the user pool. If a user belongs to two or more groups, it is the group with the highest precedence whose role ARN will be used in the cognito:roles and cognito:preferred_role claims in the user's tokens. Groups with higher Precedence values take precedence over groups with lower Precedence values or with null Precedence values. Two groups can have the same Precedence value. If this happens, neither group takes precedence over the other. If two groups with the same Precedence have the same role ARN, that role is used in the cognito:preferred_role claim in tokens for users in each group. If the two groups have different role ARNs, the cognito:preferred_role claim is not set in users' tokens. The default Precedence value is null.
   */
  Precedence?: number;
  /**
   * The date the group was last modified.
   */
  LastModifiedDate: Date;
  /**
   * The date the group was created.
   */
  CreationDate: Date;

  /**
   * The group's membership, a list of Usernames
   */
  members?: readonly string[];
}

// just use the types from the sdk, but make Id required
export type UserPool = UserPoolType & {
  Id: string;
  SoftwareTokenMfaConfiguration?: {
    Enabled: boolean;
  };
  WebAuthnConfiguration?: WebAuthnConfigurationType;
};

export interface UserPoolService {
  readonly options: UserPool;

  addUserToGroup(ctx: Context, group: Group, user: User): Promise<void>;
  saveAppClient(ctx: Context, appClient: AppClient): Promise<void>;
  deleteAppClient(ctx: Context, appClient: AppClient): Promise<void>;
  deleteGroup(ctx: Context, group: Group): Promise<void>;
  deleteUser(ctx: Context, user: User): Promise<void>;
  getGroupByGroupName(ctx: Context, groupName: string): Promise<Group | null>;
  getUserByUsername(ctx: Context, username: string): Promise<User | null>;
  getUserByRefreshToken(
    ctx: Context,
    refreshToken: string,
  ): Promise<User | null>;
  listGroups(ctx: Context): Promise<readonly Group[]>;
  listUsers(
    ctx: Context,
    filter?: string | undefined,
  ): Promise<readonly User[]>;
  listUserGroupMembership(ctx: Context, user: User): Promise<readonly string[]>;
  updateOptions(ctx: Context, userPool: UserPool): Promise<void>;
  removeUserFromGroup(ctx: Context, group: Group, user: User): Promise<void>;
  saveGroup(ctx: Context, group: Group): Promise<void>;
  saveUser(ctx: Context, user: User): Promise<void>;
  /** Applies `update` to the stored record, so changes made since `user` was loaded are kept. */
  updateUser(
    ctx: Context,
    user: User,
    update: (latest: User) => User,
  ): Promise<User>;
  storeRefreshToken(
    ctx: Context,
    refreshToken: string,
    user: User,
  ): Promise<void>;
}

export interface UserPoolServiceFactory {
  create(
    ctx: Context,
    clientsDataStore: DataStore,
    defaultOptions: UserPool,
  ): Promise<UserPoolService>;
}

export class UserPoolServiceImpl implements UserPoolService {
  private readonly clientsDataStore: DataStore;
  private readonly clock: Clock;
  private readonly dataStore: DataStore;

  private _options: UserPool;

  public get options(): UserPool {
    return this._options;
  }

  public constructor(
    clientsDataStore: DataStore,
    clock: Clock,
    dataStore: DataStore,
    config: UserPool,
  ) {
    this.clientsDataStore = clientsDataStore;
    this._options = config;
    this.clock = clock;
    this.dataStore = dataStore;
  }

  public async saveAppClient(
    ctx: Context,
    appClient: AppClient,
  ): Promise<void> {
    ctx.logger.debug("UserPoolServiceImpl.saveAppClient");
    await this.clientsDataStore.set(
      ctx,
      ["Clients", appClient.ClientId],
      appClient,
    );
  }

  public async deleteAppClient(
    ctx: Context,
    appClient: AppClient,
  ): Promise<void> {
    ctx.logger.debug(
      { clientId: appClient.ClientId },
      "UserPoolServiceImpl.deleteAppClient",
    );
    await this.clientsDataStore.delete(ctx, ["Clients", appClient.ClientId]);
  }

  public async deleteGroup(ctx: Context, group: Group): Promise<void> {
    ctx.logger.debug(
      { groupName: group.GroupName },
      "UserPoolServiceImpl.deleteGroup",
    );
    await this.dataStore.delete(ctx, ["Groups", group.GroupName]);
  }

  public async deleteUser(ctx: Context, user: User): Promise<void> {
    ctx.logger.debug(
      { username: user.Username },
      "UserPoolServiceImpl.deleteUser",
    );

    await this.dataStore.delete(ctx, ["Users", user.Username]);
    await this.removeUserFromAllGroups(ctx, user);
  }

  public async getGroupByGroupName(
    ctx: Context,
    groupName: string,
  ): Promise<Group | null> {
    ctx.logger.debug("UserPoolServiceImpl.getGroupByGroupName");
    const groups = await this.dataStore.get<Record<string, Group>>(
      ctx,
      "Groups",
      {},
    );

    return Object.hasOwn(groups, groupName) ? groups[groupName] : null;
  }

  public async getUserByUsername(
    ctx: Context,
    username: string,
  ): Promise<User | null> {
    ctx.logger.debug({ username }, "UserPoolServiceImpl.getUserByUsername");

    const aliasEmailEnabled =
      this.options.UsernameAttributes?.includes("email");
    const aliasPhoneNumberEnabled =
      this.options.UsernameAttributes?.includes("phone_number");

    const userByUsername = await this.dataStore.get<User>(ctx, [
      "Users",
      username,
    ]);
    if (userByUsername) {
      return userByUsername;
    }

    const users = await this.dataStore.get<Record<string, User>>(
      ctx,
      "Users",
      {},
    );
    const fold = usernameComparer(this.options);

    for (const user of Object.values(users)) {
      if (fold(user.Username) === fold(username)) {
        return user;
      }

      if (attributesIncludeMatch("sub", username, user.Attributes)) {
        return user;
      }

      if (
        aliasEmailEnabled &&
        fold(attributeValue("email", user.Attributes)) === fold(username)
      ) {
        return user;
      }

      if (
        aliasPhoneNumberEnabled &&
        attributesIncludeMatch("phone_number", username, user.Attributes)
      ) {
        return user;
      }
    }

    // AliasAttributes sign in with preferred_username, or with an email or phone number once verified.
    for (const name of this.options.AliasAttributes ?? []) {
      const foldAlias =
        name === "phone_number" ? (value?: string) => value : fold;
      const verifiedFlag =
        name === "preferred_username" ? undefined : `${name}_verified`;
      const match = Object.values(users).find(
        (user) =>
          foldAlias(attributeValue(name, user.Attributes)) ===
            foldAlias(username) &&
          (!verifiedFlag ||
            attributeValue(verifiedFlag, user.Attributes) === "true"),
      );
      if (match) return match;
    }

    return null;
  }

  public async getUserByRefreshToken(
    ctx: Context,
    refreshToken: string,
  ): Promise<User | null> {
    ctx.logger.debug(
      { refreshToken },
      "UserPoolServiceImpl.getUserByRefreshToken",
    );
    const users = await this.listUsers(ctx);
    const user = users.find(
      (user) =>
        Array.isArray(user.RefreshTokens) &&
        user.RefreshTokens.includes(refreshToken),
    );

    return user ?? null;
  }

  public async listUsers(
    ctx: Context,
    filter?: string | undefined,
  ): Promise<readonly User[]> {
    ctx.logger.debug("UserPoolServiceImpl.listUsers");

    // Pools with CaseSensitive=false compare usernames, email and preferred_username in any case.
    const caseFor = isCaseInsensitivePool(this.options)
      ? FilterConfig.caseInsensitive
      : FilterConfig.caseSensitive;
    const filterConfig = new FilterConfig<User>({
      username: caseFor((x) => x.Username),
      email: caseFor((x) => attributeValue("email", x.Attributes)),
      phone_number: FilterConfig.caseSensitive((x) =>
        attributeValue("phone_number", x.Attributes),
      ),
      name: FilterConfig.caseSensitive((x) =>
        attributeValue("name", x.Attributes),
      ),
      given_name: FilterConfig.caseSensitive((x) =>
        attributeValue("given_name", x.Attributes),
      ),
      family_name: FilterConfig.caseSensitive((x) =>
        attributeValue("family_name", x.Attributes),
      ),
      preferred_username: caseFor((x) =>
        attributeValue("preferred_username", x.Attributes),
      ),
      "cognito:user_status": FilterConfig.caseInsensitive((x) => x.UserStatus),
      status: FilterConfig.caseSensitive((x) => x.Enabled),
      sub: FilterConfig.caseSensitive((x) =>
        attributeValue("sub", x.Attributes),
      ),
    });

    const users = await this.dataStore.get<Record<string, User>>(
      ctx,
      "Users",
      {},
    );

    return Object.values(users).filter(filterConfig.parse(filter));
  }

  public async updateOptions(ctx: Context, userPool: UserPool): Promise<void> {
    ctx.logger.debug(
      { userPoolId: userPool.Id },
      "UserPoolServiceImpl.updateOptions",
    );
    await this.dataStore.set(ctx, "Options", userPool);
    this._options = userPool;
  }

  public async saveUser(ctx: Context, user: User): Promise<void> {
    ctx.logger.debug({ user }, "UserPoolServiceImpl.saveUser");

    await this.dataStore.set<User>(ctx, ["Users", user.Username], user);
  }

  public async updateUser(
    ctx: Context,
    user: User,
    update: (latest: User) => User,
  ): Promise<User> {
    const latest =
      (await this.dataStore.get<User>(ctx, ["Users", user.Username])) ?? user;
    const updated = update(latest);
    await this.saveUser(ctx, updated);
    return updated;
  }

  async listGroups(ctx: Context): Promise<readonly Group[]> {
    ctx.logger.debug("UserPoolServiceImpl.listGroups");
    const groups = await this.dataStore.get<Record<string, Group>>(
      ctx,
      "Groups",
      {},
    );

    return Object.values(groups);
  }

  public async addUserToGroup(
    ctx: Context,
    group: Group,
    user: User,
  ): Promise<void> {
    ctx.logger.debug(
      { username: user.Username, groupName: group.GroupName },
      "UserPoolServiceImpl.addUserToFromGroup",
    );

    const groupMembers = new Set(group.members ?? []);
    if (!groupMembers.has(user.Username)) {
      groupMembers.add(user.Username);
      await this.saveGroup(ctx, {
        ...group,
        LastModifiedDate: this.clock.get(),
        members: Array.from(groupMembers),
      });
    }
  }

  public async removeUserFromGroup(
    ctx: Context,
    group: Group,
    user: User,
  ): Promise<void> {
    ctx.logger.debug(
      { username: user.Username, groupName: group.GroupName },
      "UserPoolServiceImpl.removeUserFromGroup",
    );

    const groupMembers = new Set(group.members ?? []);
    if (groupMembers.has(user.Username)) {
      groupMembers.delete(user.Username);
      await this.saveGroup(ctx, {
        ...group,
        LastModifiedDate: this.clock.get(),
        members: Array.from(groupMembers),
      });
    }
  }

  private async removeUserFromAllGroups(
    ctx: Context,
    user: User,
  ): Promise<void> {
    ctx.logger.debug(
      { username: user.Username },
      "UserPoolServiceImpl.removeUserFromAllGroups",
    );
    const groups = await this.listGroups(ctx);

    await Promise.all(
      groups.map((group) => this.removeUserFromGroup(ctx, group, user)),
    );
  }

  async saveGroup(ctx: Context, group: Group): Promise<void> {
    ctx.logger.debug({ group }, "UserPoolServiceImpl.saveGroup");

    await this.dataStore.set<Group>(ctx, ["Groups", group.GroupName], group);
  }

  async listUserGroupMembership(
    ctx: Context,
    user: User,
  ): Promise<readonly string[]> {
    ctx.logger.debug(
      { username: user.Username },
      "UserPoolServiceImpl.listUserGroupMembership",
    );

    // could optimise this by dual-writing group membership to both the group and
    // the user records, but for an initial version this is probably fine unless
    // you have a lot of groups
    const groups = await this.listGroups(ctx);

    return groups
      .filter((x) => x.members?.includes(user.Username))
      .map((x) => x.GroupName)
      .sort((a, b) => a.localeCompare(b));
  }

  async storeRefreshToken(
    ctx: Context,
    refreshToken: string,
    user: User,
  ): Promise<void> {
    ctx.logger.debug(
      { username: user.Username },
      "UserPoolServiceImpl.storeRefreshToken",
    );

    await this.updateUser(ctx, user, (latest) =>
      withRefreshToken(latest, refreshToken, this.clock.get()),
    );
  }
}

export class UserPoolServiceFactoryImpl implements UserPoolServiceFactory {
  private readonly clock: Clock;
  private readonly dataStoreFactory: DataStoreFactory;

  public constructor(clock: Clock, dataStoreFactory: DataStoreFactory) {
    this.clock = clock;
    this.dataStoreFactory = dataStoreFactory;
  }

  public async create(
    ctx: Context,
    clientsDataStore: DataStore,
    defaultOptions: UserPool,
  ): Promise<UserPoolService> {
    const id = defaultOptions.Id;

    ctx.logger.debug({ id }, "UserPoolServiceImpl.create");

    const dataStore = await this.dataStoreFactory.create(ctx, id, {
      Users: {},
      Options: defaultOptions,
    });
    const config = await dataStore.get<UserPool>(
      ctx,
      "Options",
      defaultOptions,
    );

    return new UserPoolServiceImpl(
      clientsDataStore,
      this.clock,
      dataStore,
      config,
    );
  }
}

export const UNAUTHORIZED_ATTRIBUTE_WRITE =
  "A client attempted to write unauthorized attribute";

/** Throws when a user-level request names a developer-only attribute, which only admin operations may write. */
export const assertNoDeveloperOnlyAttributes = (
  attributeNames: readonly string[],
  schemaAttributes: SchemaAttributeType[] | undefined,
): void => {
  for (const name of attributeNames) {
    const attrSchema = schemaAttributes?.find((x) => x.Name === name);
    if (attrSchema?.DeveloperOnlyAttribute || name.startsWith("dev:")) {
      throw new NotAuthorizedError(UNAUTHORIZED_ATTRIBUTE_WRITE);
    }
  }
};

export const validatePermittedAttributeChanges = (
  requestAttributes: Attribute[],
  schemaAttributes: SchemaAttributeType[],
  { admin = false }: { admin?: boolean } = {},
): Attribute[] => {
  for (const attr of requestAttributes) {
    const attrSchema = schemaAttributes.find((x) => x.Name === attr.Name);
    if (!attrSchema) {
      throw new InvalidParameterError(
        `user.${attr.Name}: Attribute does not exist in the schema.`,
      );
    }
    if (!admin && attrSchema.DeveloperOnlyAttribute) {
      throw new NotAuthorizedError(UNAUTHORIZED_ATTRIBUTE_WRITE);
    }
    if (!attrSchema.Mutable) {
      throw new InvalidParameterError(
        `user.${attr.Name}: Attribute cannot be updated. (changing an immutable attribute)`,
      );
    }
  }

  // An administrator may mark the existing email or phone number verified on its own.
  if (admin) {
    return requestAttributes;
  }

  if (
    attributesInclude("email_verified", requestAttributes) &&
    !attributesInclude("email", requestAttributes)
  ) {
    throw new InvalidParameterError(
      "Email is required to verify/un-verify an email",
    );
  }

  if (
    attributesInclude("phone_number_verified", requestAttributes) &&
    !attributesInclude("phone_number", requestAttributes)
  ) {
    throw new InvalidParameterError(
      "Phone Number is required to verify/un-verify a phone number",
    );
  }

  return requestAttributes;
};

export const defaultVerifiedAttributesIfModified = (
  attributes: Attribute[],
): Attribute[] => {
  const attributesToSet = [...attributes];
  if (
    attributesInclude("email", attributes) &&
    !attributesInclude("email_verified", attributes)
  ) {
    attributesToSet.push(attribute("email_verified", "false"));
  }
  if (
    attributesInclude("phone_number", attributes) &&
    !attributesInclude("phone_number_verified", attributes)
  ) {
    attributesToSet.push(attribute("phone_number_verified", "false"));
  }
  return attributesToSet;
};

export const hasUnverifiedContactAttributes = (
  userAttributesToSet: Attribute[] | undefined,
): boolean =>
  attributeValue("email_verified", userAttributesToSet) === "false" ||
  attributeValue("phone_number_verified", userAttributesToSet) === "false";

/**
 * Splits user attributes into two lists:
 * - Immediate attributes that can be set without verification
 * - Delayed attributes that require verification before they can be set
 */
export const splitImmediateAndDelayedAttributes = (
  userAttributesToSet: Attribute[],
  attributesRequireVerificationBeforeUpdate: readonly string[] | undefined,
): [Attribute[], Attribute[]] => {
  const immediateAttributes: Attribute[] = [];
  const delayedAttributes: Attribute[] = [];

  for (const attr of userAttributesToSet) {
    if (attributesRequireVerificationBeforeUpdate?.includes(attr.Name)) {
      delayedAttributes.push(attr);
    } else {
      immediateAttributes.push(attr);
    }
  }

  return [
    defaultVerifiedAttributesIfModified(immediateAttributes),
    defaultVerifiedAttributesIfModified(delayedAttributes),
  ];
};
