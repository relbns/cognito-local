import type {
  AttributeType,
  CreateUserPoolClientRequest,
  CreateUserPoolRequest,
  ResourceServerScopeType,
} from "aws-sdk/clients/cognitoidentityserviceprovider";

export const SEED_VERSION = 1;

export type SeedClient = Omit<CreateUserPoolClientRequest, "UserPoolId"> & {
  /** Pin the client id so tokens and app config stay stable across resets. */
  ClientId?: string;
  /** Pin the client secret; implies a confidential client. */
  ClientSecret?: string;
};

export interface SeedIdentityProvider {
  ProviderName: string;
  ProviderType: string;
  ProviderDetails?: Record<string, string>;
  AttributeMapping?: Record<string, string>;
  IdpIdentifiers?: string[];
}

export interface SeedResourceServer {
  Identifier: string;
  Name: string;
  Scopes?: ResourceServerScopeType[];
}

export interface SeedGroup {
  GroupName: string;
  Description?: string;
  Precedence?: number;
  RoleArn?: string;
}

export interface SeedUser {
  Username: string;
  UserAttributes?: AttributeType[];
  /** Permanent password: the user starts CONFIRMED. Applied only when the user is created. */
  Password?: string;
  /** Temporary password: the user starts FORCE_CHANGE_PASSWORD. Applied only when the user is created. */
  TemporaryPassword?: string;
  /** Applied only when the user is created. */
  UserStatus?:
    | "EXTERNAL_PROVIDER"
    | "CONFIRMED"
    | "UNCONFIRMED"
    | "FORCE_CHANGE_PASSWORD"
    | "RESET_REQUIRED";
  Enabled?: boolean;
  /** The user's full group membership. */
  Groups?: string[];
}

export type SeedUserPool = CreateUserPoolRequest & {
  /** Pin the pool id, e.g. "local_Example1". */
  Id?: string;
  Clients?: SeedClient[];
  IdentityProviders?: SeedIdentityProvider[];
  ResourceServers?: SeedResourceServer[];
  Groups?: SeedGroup[];
  Users?: SeedUser[];
};

export interface SeedFile {
  $schema?: string;
  $comment?: string;
  Version?: number;
  UserPools: SeedUserPool[];
}

export type SeedEntityKind =
  | "UserPool"
  | "Client"
  | "IdentityProvider"
  | "ResourceServer"
  | "Group"
  | "User";

export interface SeedChange {
  kind: SeedEntityKind;
  id: string;
  userPoolId: string;
  action: "created" | "updated" | "unchanged";
  fields?: string[];
}

export interface SeedResult {
  changes: SeedChange[];
}
