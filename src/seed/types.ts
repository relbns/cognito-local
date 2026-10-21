import type {
  CreateUserPoolClientRequest,
  CreateUserPoolRequest,
  ResourceServerScopeType,
  WebAuthnConfigurationType,
} from "@aws-sdk/client-cognito-identity-provider";
import type { Attribute } from "../services/sdkTypes";

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
  UserAttributes?: Attribute[];
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
  /** The user's full set of passkeys: public keys, so they can be exported and re-created. */
  Passkeys?: SeedPasskey[];
}

export interface SeedPasskey {
  /** base64url credential id. */
  CredentialId: string;
  /** COSE_Key of the credential, base64url. */
  PublicKey: string;
  /** COSE algorithm, such as -7 (ES256) or -257 (RS256). */
  Algorithm: number;
  RelyingPartyId: string;
  FriendlyCredentialName?: string;
  AuthenticatorAttachment?: string;
  AuthenticatorTransports?: string[];
  SignCount?: number;
  /** ISO 8601. */
  CreatedDate?: string;
}

export type SeedUserPool = CreateUserPoolRequest & {
  /** Pin the pool id, e.g. "local_Example1". */
  Id?: string;
  /** Passkey settings, as SetUserPoolMfaConfig sets them. */
  WebAuthnConfiguration?: WebAuthnConfigurationType;
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
