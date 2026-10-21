import type { SeedFile } from "./types";

export interface SeedIssue {
  path: string;
  message: string;
}

export class SeedValidationError extends Error {
  public constructor(
    public readonly source: string,
    public readonly issues: readonly SeedIssue[],
  ) {
    super(
      `Invalid seed ${source}:\n${issues.map((i) => `  - ${i.path || "(root)"}: ${i.message}`).join("\n")}`,
    );
    this.name = "SeedValidationError";
  }
}

type Check = (value: unknown, path: string, issues: SeedIssue[]) => void;

const join = (path: string, key: string) => (path ? `${path}.${key}` : key);

const typeOf = (value: unknown) =>
  value === null ? "null" : Array.isArray(value) ? "array" : typeof value;

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeOf(value) === "object";

const str: Check = (v, path, issues) => {
  if (typeof v !== "string") {
    issues.push({ path, message: `must be a string, got ${typeOf(v)}` });
  }
};

const nonEmptyStr: Check = (v, path, issues) => {
  str(v, path, issues);
  if (v === "") issues.push({ path, message: "must not be empty" });
};

const pattern =
  (re: RegExp, hint: string): Check =>
  (v, path, issues) => {
    str(v, path, issues);
    if (typeof v === "string" && !re.test(v)) {
      issues.push({ path, message: `must match ${hint}` });
    }
  };

const bool: Check = (v, path, issues) => {
  if (typeof v !== "boolean") {
    issues.push({ path, message: `must be true or false, got ${typeOf(v)}` });
  }
};

const num: Check = (v, path, issues) => {
  if (typeof v !== "number" || !Number.isFinite(v)) {
    issues.push({ path, message: `must be a number, got ${typeOf(v)}` });
  }
};

const obj: Check = (v, path, issues) => {
  if (!isPlainObject(v)) {
    issues.push({ path, message: `must be an object, got ${typeOf(v)}` });
  }
};

const oneOf =
  (...values: string[]): Check =>
  (v, path, issues) => {
    if (typeof v !== "string" || !values.includes(v)) {
      issues.push({
        path,
        message: `must be one of ${values.join(", ")}, got ${JSON.stringify(v)}`,
      });
    }
  };

const arrayOf =
  (item: Check): Check =>
  (v, path, issues) => {
    if (!Array.isArray(v)) {
      issues.push({ path, message: `must be an array, got ${typeOf(v)}` });
      return;
    }
    v.forEach((x, i) => {
      item(x, `${path}[${i}]`, issues);
    });
  };

const strArray = arrayOf(str);

const stringRecord: Check = (v, path, issues) => {
  obj(v, path, issues);
  if (!isPlainObject(v)) return;
  for (const [k, value] of Object.entries(v)) {
    str(value, join(path, k), issues);
  }
};

const entity =
  (
    spec: Record<string, Check>,
    required: readonly string[] = [],
    extra?: (v: Record<string, unknown>, path: string, i: SeedIssue[]) => void,
  ): Check =>
  (v, path, issues) => {
    if (!isPlainObject(v)) {
      issues.push({ path, message: `must be an object, got ${typeOf(v)}` });
      return;
    }
    for (const key of required) {
      if (v[key] === undefined) {
        issues.push({ path: join(path, key), message: "is required" });
      }
    }
    for (const [key, value] of Object.entries(v)) {
      if (key.startsWith("$")) continue;
      const check = spec[key];
      if (!check) {
        issues.push({
          path: join(path, key),
          message: `unknown field (expected one of ${Object.keys(spec).join(", ")})`,
        });
        continue;
      }
      if (value !== undefined) check(value, join(path, key), issues);
    }
    extra?.(v, path, issues);
  };

const unique =
  (key: string, label: string) =>
  (items: unknown, path: string, issues: SeedIssue[]) => {
    if (!Array.isArray(items)) return;
    const seen = new Map<string, number>();
    items.forEach((item, i) => {
      const value = isPlainObject(item) ? item[key] : undefined;
      if (typeof value !== "string") return;
      const first = seen.get(value);
      if (first !== undefined) {
        issues.push({
          path: `${path}[${i}].${key}`,
          message: `duplicate ${label} "${value}" (also at ${path}[${first}])`,
        });
      } else {
        seen.set(value, i);
      }
    });
  };

export const LAMBDA_CONFIG_KEYS = [
  "PreSignUp",
  "CustomMessage",
  "PostConfirmation",
  "PreAuthentication",
  "PostAuthentication",
  "DefineAuthChallenge",
  "CreateAuthChallenge",
  "VerifyAuthChallengeResponse",
  "PreTokenGeneration",
  "PreTokenGenerationConfig",
  "UserMigration",
  "CustomSMSSender",
  "CustomEmailSender",
  "KMSKeyID",
] as const;

const lambdaTarget: Check = (v, path, issues) => {
  if (typeof v === "string") return;
  entity({ LambdaArn: nonEmptyStr, LambdaVersion: str }, ["LambdaArn"])(
    v,
    path,
    issues,
  );
};

const lambdaConfig: Check = (v, path, issues) => {
  obj(v, path, issues);
  if (!isPlainObject(v)) return;
  for (const [key, value] of Object.entries(v)) {
    if (key.startsWith("$")) continue;
    if (!(LAMBDA_CONFIG_KEYS as readonly string[]).includes(key)) {
      issues.push({
        path: join(path, key),
        message: `unknown trigger (expected one of ${LAMBDA_CONFIG_KEYS.join(", ")})`,
      });
      continue;
    }
    if (key === "KMSKeyID") str(value, join(path, key), issues);
    else lambdaTarget(value, join(path, key), issues);
  }
};

const schemaAttribute = entity(
  {
    Name: nonEmptyStr,
    AttributeDataType: oneOf("String", "Number", "DateTime", "Boolean"),
    DeveloperOnlyAttribute: bool,
    Mutable: bool,
    Required: bool,
    NumberAttributeConstraints: obj,
    StringAttributeConstraints: obj,
  },
  ["Name"],
);

const client = entity(
  {
    ClientId: pattern(/^[\w+]{1,128}$/, "[\\w+]{1,128}"),
    ClientName: nonEmptyStr,
    ClientSecret: pattern(/^[\w+]{1,64}$/, "[\\w+]{1,64}"),
    GenerateSecret: bool,
    RefreshTokenValidity: num,
    AccessTokenValidity: num,
    IdTokenValidity: num,
    TokenValidityUnits: obj,
    ReadAttributes: strArray,
    WriteAttributes: strArray,
    ExplicitAuthFlows: strArray,
    SupportedIdentityProviders: strArray,
    CallbackURLs: strArray,
    LogoutURLs: strArray,
    DefaultRedirectURI: str,
    AllowedOAuthFlows: arrayOf(oneOf("code", "implicit", "client_credentials")),
    AllowedOAuthScopes: strArray,
    AllowedOAuthFlowsUserPoolClient: bool,
    AnalyticsConfiguration: obj,
    PreventUserExistenceErrors: oneOf("LEGACY", "ENABLED"),
    EnableTokenRevocation: bool,
    RefreshTokenRotation: entity(
      {
        Feature: oneOf("ENABLED", "DISABLED"),
        RetryGracePeriodSeconds: num,
      },
      ["Feature"],
    ),
  },
  ["ClientName"],
  (v, path, issues) => {
    if (v.ClientSecret !== undefined && v.GenerateSecret === false) {
      issues.push({
        path: `${path}.GenerateSecret`,
        message: "cannot be false when ClientSecret is set",
      });
    }
  },
);

const identityProvider = entity(
  {
    ProviderName: pattern(
      /^[^_\s].{0,31}$/u,
      "1-32 characters, not starting with an underscore or a space",
    ),
    ProviderType: oneOf(
      "SAML",
      "Facebook",
      "Google",
      "LoginWithAmazon",
      "SignInWithApple",
      "OIDC",
    ),
    ProviderDetails: stringRecord,
    AttributeMapping: stringRecord,
    IdpIdentifiers: strArray,
  },
  ["ProviderName", "ProviderType"],
);

const resourceServer = entity(
  {
    Identifier: nonEmptyStr,
    Name: nonEmptyStr,
    Scopes: arrayOf(
      entity({ ScopeName: nonEmptyStr, ScopeDescription: str }, [
        "ScopeName",
        "ScopeDescription",
      ]),
    ),
  },
  ["Identifier", "Name"],
);

const group = entity(
  {
    GroupName: nonEmptyStr,
    Description: str,
    Precedence: num,
    RoleArn: str,
  },
  ["GroupName"],
);

const user = entity(
  {
    Username: nonEmptyStr,
    UserAttributes: arrayOf(
      entity({ Name: nonEmptyStr, Value: str }, ["Name", "Value"]),
    ),
    Password: nonEmptyStr,
    TemporaryPassword: nonEmptyStr,
    UserStatus: oneOf(
      "EXTERNAL_PROVIDER",
      "CONFIRMED",
      "UNCONFIRMED",
      "FORCE_CHANGE_PASSWORD",
      "RESET_REQUIRED",
    ),
    Enabled: bool,
    Groups: strArray,
  },
  ["Username"],
  (v, path, issues) => {
    if (v.Password !== undefined && v.TemporaryPassword !== undefined) {
      issues.push({
        path: `${path}.TemporaryPassword`,
        message: "set either Password or TemporaryPassword, not both",
      });
    }
  },
);

const userPool = entity(
  {
    Id: pattern(/^[\w-]+_[0-9a-zA-Z]+$/, "<region>_<id>, e.g. local_Example1"),
    PoolName: nonEmptyStr,
    Policies: obj,
    LambdaConfig: lambdaConfig,
    AutoVerifiedAttributes: arrayOf(oneOf("email", "phone_number")),
    AliasAttributes: arrayOf(
      oneOf("email", "phone_number", "preferred_username"),
    ),
    UsernameAttributes: arrayOf(oneOf("email", "phone_number")),
    SmsVerificationMessage: str,
    EmailVerificationMessage: str,
    EmailVerificationSubject: str,
    VerificationMessageTemplate: obj,
    SmsAuthenticationMessage: str,
    MfaConfiguration: oneOf("OFF", "ON", "OPTIONAL"),
    UserAttributeUpdateSettings: obj,
    DeviceConfiguration: obj,
    EmailConfiguration: obj,
    SmsConfiguration: obj,
    UserPoolTags: stringRecord,
    AdminCreateUserConfig: obj,
    Schema: arrayOf(schemaAttribute),
    UserPoolAddOns: obj,
    UsernameConfiguration: obj,
    AccountRecoverySetting: obj,
    Clients: arrayOf(client),
    IdentityProviders: arrayOf(identityProvider),
    ResourceServers: arrayOf(resourceServer),
    Groups: arrayOf(group),
    Users: arrayOf(user),
  },
  ["PoolName"],
  (v, path, issues) => {
    unique("ClientId", "ClientId")(v.Clients, `${path}.Clients`, issues);
    unique("ClientName", "ClientName")(v.Clients, `${path}.Clients`, issues);
    unique("ProviderName", "ProviderName")(
      v.IdentityProviders,
      `${path}.IdentityProviders`,
      issues,
    );
    unique("Identifier", "Identifier")(
      v.ResourceServers,
      `${path}.ResourceServers`,
      issues,
    );
    unique("GroupName", "GroupName")(v.Groups, `${path}.Groups`, issues);
    unique("Username", "Username")(v.Users, `${path}.Users`, issues);
  },
);

const seedFile = entity(
  {
    Version: (v, path, issues) => {
      if (v !== 1) issues.push({ path, message: "must be 1" });
    },
    UserPools: arrayOf(userPool),
  },
  ["UserPools"],
  (v, _path, issues) => {
    unique("Id", "pool Id")(v.UserPools, "UserPools", issues);
    if (!Array.isArray(v.UserPools)) return;
    const seen = new Map<string, number>();
    v.UserPools.forEach((p, i) => {
      if (!isPlainObject(p) || p.Id !== undefined) return;
      if (typeof p.PoolName !== "string") return;
      const first = seen.get(p.PoolName);
      if (first === undefined) {
        seen.set(p.PoolName, i);
        return;
      }
      issues.push({
        path: `UserPools[${i}].PoolName`,
        message: `duplicate PoolName "${p.PoolName}" without a pinned Id (also at UserPools[${first}]); set Id on both`,
      });
    });
  },
);

export const validateSeed = (value: unknown): SeedIssue[] => {
  const issues: SeedIssue[] = [];
  seedFile(value, "", issues);
  return issues;
};

export const assertValidSeed: (
  value: unknown,
  source: string,
) => asserts value is SeedFile = (value, source) => {
  const issues = validateSeed(value);
  if (issues.length) throw new SeedValidationError(source, issues);
};
