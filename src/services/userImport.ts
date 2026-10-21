import type {
  SchemaAttributeType,
  UserImportJobType,
} from "@aws-sdk/client-cognito-identity-provider";
import * as uuid from "uuid";
import { findAliasConflicts } from "./aliases";
import type { Clock } from "./clock";
import type { Context } from "./context";
import type { Attribute } from "./sdkTypes";
import type { User, UserPool, UserPoolService } from "./userPoolService";

export const USER_IMPORT_PATH = "/_import";
export const USER_IMPORT_MAX_BYTES = 100 * 1024 * 1024;

const STANDARD_COLUMNS = [
  "name",
  "given_name",
  "family_name",
  "middle_name",
  "nickname",
  "preferred_username",
  "profile",
  "picture",
  "website",
  "email",
  "email_verified",
  "gender",
  "birthdate",
  "zoneinfo",
  "locale",
  "phone_number",
  "phone_number_verified",
  "address",
  "updated_at",
];
const MFA_COLUMN = "cognito:mfa_enabled";
const USERNAME_COLUMN = "cognito:username";

export const COMPLETED_SUCCESSFULLY = "Import Job Completed Successfully.";
export const TOO_MANY_FAILURES =
  "Too many users have failed or been skipped during the import.";

export interface StoredUserImportJob extends UserImportJobType {
  /** Secret part of the PreSignedUrl. */
  _uploadToken?: string;
  /** The uploaded CSV, kept until the job runs. */
  _csv?: string;
  /** One line per failed row, in the job's log format. */
  _log?: string[];
}

export const importJobsOf = (pool: UserPool): StoredUserImportJob[] =>
  ((pool as { _importJobs?: StoredUserImportJob[] })._importJobs ?? []).map(
    (job) => ({ ...job }),
  );

export const saveImportJobs = (
  ctx: Context,
  userPool: UserPoolService,
  jobs: StoredUserImportJob[],
) =>
  userPool.updateOptions(ctx, {
    ...userPool.options,
    _importJobs: jobs,
  } as UserPool);

export const toUserImportJob = ({
  _uploadToken,
  _csv,
  _log,
  ...job
}: StoredUserImportJob): UserImportJobType => job;

export const userImportUrl = (
  base: string,
  userPoolId: string,
  jobId: string,
  token: string,
): string =>
  `${base.replace(/\/+$/, "")}${USER_IMPORT_PATH}/${encodeURIComponent(userPoolId)}/${jobId}?X-Amz-Signature=${token}`;

export const csvHeaderFor = (pool: UserPool): string[] => [
  ...STANDARD_COLUMNS,
  ...(pool.SchemaAttributes ?? [])
    .map((s) => s.Name ?? "")
    .filter((name) => name.startsWith("custom:")),
  MFA_COLUMN,
  USERNAME_COLUMN,
];

/** Parses RFC 4180 CSV: quoted fields, doubled quotes, CRLF or LF line ends. */
export const parseCsv = (text: string): string[][] => {
  const rows: string[][] = [];
  let row: string[] = [];
  let field = "";
  let quoted = false;
  const input = text.replace(/^﻿/, "");
  for (let i = 0; i < input.length; i++) {
    const c = input[i];
    if (quoted) {
      if (c === '"' && input[i + 1] === '"') {
        field += '"';
        i++;
      } else if (c === '"') {
        quoted = false;
      } else {
        field += c;
      }
    } else if (c === '"') {
      quoted = true;
    } else if (c === ",") {
      row.push(field);
      field = "";
    } else if (c === "\n" || c === "\r") {
      if (c === "\r" && input[i + 1] === "\n") i++;
      row.push(field);
      rows.push(row);
      row = [];
      field = "";
    } else {
      field += c;
    }
  }
  if (field !== "" || row.length > 0) {
    row.push(field);
    rows.push(row);
  }
  return rows;
};

const BOOLEAN = /^(true|false)$/i;
const PHONE = /^\+[0-9]{4,20}$/;
const EMAIL = /^[^@\s]+@[^@\s]+$/;

interface RowContext {
  pool: UserPool;
  userPool: UserPoolService;
  header: string[];
  schema: SchemaAttributeType[];
  seen: Set<string>;
  now: Date;
}

class RowError extends Error {}

const buildUser = async (
  ctx: Context,
  rc: RowContext,
  values: string[],
): Promise<User> => {
  if (values.length !== rc.header.length) {
    throw new RowError(
      `The record has ${values.length} fields, but the header has ${rc.header.length}.`,
    );
  }
  const record = new Map(rc.header.map((name, i) => [name, values[i].trim()]));
  const value = (name: string) => record.get(name) ?? "";

  const givenUsername = value(USERNAME_COLUMN);
  if (!givenUsername) throw new RowError("cognito:username is required.");

  const mfa = value(MFA_COLUMN);
  if (!BOOLEAN.test(mfa)) {
    throw new RowError("cognito:mfa_enabled must be TRUE or FALSE.");
  }
  const mfaEnabled = mfa.toLowerCase() === "true";

  for (const flag of ["email_verified", "phone_number_verified"]) {
    if (value(flag) && !BOOLEAN.test(value(flag))) {
      throw new RowError(`${flag} must be TRUE or FALSE.`);
    }
  }
  if (value("email") && !EMAIL.test(value("email"))) {
    throw new RowError("Invalid email address format.");
  }
  if (value("phone_number") && !PHONE.test(value("phone_number"))) {
    throw new RowError("Invalid phone number format.");
  }
  if (value("updated_at") && !/^[0-9]+$/.test(value("updated_at"))) {
    throw new RowError("updated_at must be a number of seconds since 1970.");
  }
  if (mfaEnabled && !value("phone_number")) {
    throw new RowError(
      "cognito:mfa_enabled is TRUE, but the record has no phone_number.",
    );
  }

  const usesEmailUsername = rc.pool.UsernameAttributes?.includes("email");
  const email =
    value("email") ||
    (usesEmailUsername && givenUsername.includes("@") ? givenUsername : "");
  if (usesEmailUsername && !email) {
    throw new RowError(
      "The user pool uses email as the username, but the record has no email.",
    );
  }

  const autoVerified = rc.pool.AutoVerifiedAttributes ?? [];
  if (
    autoVerified.length > 0 &&
    !autoVerified.some(
      (name) => value(`${name}_verified`).toLowerCase() === "true",
    )
  ) {
    throw new RowError(
      "The User Record does not set any of the auto verified attributes to true. (Example: email_verified to true).",
    );
  }

  const sub = uuid.v4();
  const attributes: Attribute[] = [{ Name: "sub", Value: sub }];
  for (const name of rc.header) {
    if (name === MFA_COLUMN || name === USERNAME_COLUMN) continue;
    const v = name === "email" ? email : value(name);
    if (!v) continue;
    attributes.push({
      Name: name,
      Value: name.endsWith("_verified") ? v.toLowerCase() : v,
    });
  }
  if (email && !rc.header.includes("email")) {
    attributes.push({ Name: "email", Value: email });
  }

  for (const s of rc.schema) {
    if (
      s.Required &&
      s.Name &&
      s.Name !== "sub" &&
      !attributes.some((a) => a.Name === s.Name)
    ) {
      throw new RowError(`The attribute ${s.Name} is required.`);
    }
  }

  const username = usesEmailUsername ? sub : givenUsername;
  const key = usesEmailUsername ? email.toLowerCase() : givenUsername;
  if (
    rc.seen.has(key) ||
    (!usesEmailUsername &&
      (await rc.userPool.getUserByUsername(ctx, givenUsername)))
  ) {
    throw new RowError("User already exists.");
  }
  const conflicts = await findAliasConflicts(
    ctx,
    rc.userPool,
    username,
    attributes,
  );
  if (conflicts.length > 0) {
    throw new RowError(
      conflicts[0].kind === "username"
        ? "User already exists."
        : `An account with the given ${conflicts[0].attributeName} already exists.`,
    );
  }
  rc.seen.add(key);

  return {
    Username: username,
    Password: "",
    Attributes: attributes.sort((a, b) => a.Name.localeCompare(b.Name)),
    Enabled: true,
    UserStatus: "RESET_REQUIRED",
    UserCreateDate: rc.now,
    UserLastModifiedDate: rc.now,
    RefreshTokens: [],
    ...(mfaEnabled
      ? {
          MFAOptions: [
            { DeliveryMedium: "SMS", AttributeName: "phone_number" },
          ],
          UserMFASettingList: ["SMS_MFA"],
          PreferredMfaSetting: "SMS_MFA",
        }
      : {}),
  };
};

export interface UserImportResult {
  status: "Succeeded" | "Failed";
  completionMessage: string;
  imported: number;
  failed: number;
  skipped: number;
  log: string[];
}

const failedJob = (message: string): UserImportResult => ({
  status: "Failed",
  completionMessage: message,
  imported: 0,
  failed: 0,
  skipped: 0,
  log: [message],
});

/** Creates the users of an uploaded CSV as a Cognito import job does. */
export const runUserImport = async (
  ctx: Context,
  userPool: UserPoolService,
  clock: Clock,
  csv: string | undefined,
): Promise<UserImportResult> => {
  if (csv === undefined) {
    return failedJob("No CSV file was uploaded to the job's PreSignedUrl.");
  }
  const rows = parseCsv(csv);
  const header = (rows.shift() ?? []).map((h) => h.trim());
  if (header.length === 0 || header.every((h) => !h)) {
    return failedJob("The CSV file is empty.");
  }
  const known = csvHeaderFor(userPool.options);
  const unknown = header.filter((h) => !known.includes(h));
  if (unknown.length > 0) {
    return failedJob(
      `The CSV header has columns the user pool does not have: ${unknown.join(", ")}.`,
    );
  }
  const missing = [USERNAME_COLUMN, MFA_COLUMN].filter(
    (h) => !header.includes(h),
  );
  if (missing.length > 0) {
    return failedJob(`The CSV header is missing ${missing.join(", ")}.`);
  }
  const duplicate = header.find((h, i) => header.indexOf(h) !== i);
  if (duplicate) {
    return failedJob(`The CSV header has ${duplicate} twice.`);
  }

  const rc: RowContext = {
    pool: userPool.options,
    userPool,
    header,
    schema: userPool.options.SchemaAttributes ?? [],
    seen: new Set(),
    now: clock.get(),
  };
  const log: string[] = [];
  let imported = 0;
  let failed = 0;
  for (const [index, values] of rows.entries()) {
    if (values.every((v) => v.trim() === "")) continue;
    const line = index + 2;
    try {
      const user = await buildUser(ctx, rc, values);
      await userPool.saveUser(ctx, user);
      imported++;
    } catch (e) {
      if (!(e instanceof RowError)) throw e;
      failed++;
      log.push(`[ERROR] Line Number ${line} - ${e.message}`);
    }
  }

  const allFailed = failed > 0 && imported === 0;
  return {
    status: allFailed ? "Failed" : "Succeeded",
    completionMessage: allFailed ? TOO_MANY_FAILURES : COMPLETED_SUCCESSFULLY,
    imported,
    failed,
    skipped: 0,
    log,
  };
};
