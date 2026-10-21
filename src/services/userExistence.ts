import * as crypto from "node:crypto";
import type { VerifiedAttributeType } from "@aws-sdk/client-cognito-identity-provider";
import { NotAuthorizedError, UserNotFoundError } from "../errors";
import type { AppClient } from "./appClient";
import type { DeliveryDetails } from "./messageDelivery/messageDelivery";
import type { User } from "./userPoolService";

export const INCORRECT_CREDENTIALS = "Incorrect username or password.";
export const USER_DOES_NOT_EXIST = "User does not exist.";
export const USERNAME_CLIENT_NOT_FOUND =
  "Username/client id combination not found.";

/** PreventUserExistenceErrors ENABLED; unset means LEGACY, the CreateUserPoolClient default. */
export const preventsUserExistenceErrors = (
  client: Pick<AppClient, "PreventUserExistenceErrors"> | null | undefined,
): boolean => client?.PreventUserExistenceErrors === "ENABLED";

/** The sign-in error for an unknown user: generic when existence errors are prevented. */
export const unknownUserSignInError = (
  client: Pick<AppClient, "PreventUserExistenceErrors"> | null | undefined,
): Error =>
  preventsUserExistenceErrors(client)
    ? new NotAuthorizedError(INCORRECT_CREDENTIALS)
    : new UserNotFoundError(USER_DOES_NOT_EXIST);

/** A stand-in for a user that does not exist, so a simulated challenge runs like a real one. */
export const phantomUser = (username: string): User => ({
  Username: username,
  Attributes: [],
  Enabled: true,
  UserStatus: "CONFIRMED",
  Password: "",
  RefreshTokens: [],
  UserCreateDate: new Date(0),
  UserLastModifiedDate: new Date(0),
});

const digest = (...parts: string[]): Buffer =>
  crypto.createHash("sha256").update(parts.join("\u0000")).digest();

/** The same salt every time for one username in one pool (RFC 5054 section 2.5.1.3). */
export const phantomSalt = (userPoolId: string, username: string): string => {
  const bytes = digest("salt", userPoolId, username).subarray(0, 16);
  if (bytes[0] === 0) bytes[0] = 1;
  return bytes.toString("hex");
};

/** The same UUID every time for one username in one pool, as USER_ID_FOR_SRP. */
export const phantomUserId = (userPoolId: string, username: string): string => {
  const hex = digest("user", userPoolId, username).subarray(0, 16);
  hex[6] = (hex[6] & 0x0f) | 0x40;
  hex[8] = (hex[8] & 0x3f) | 0x80;
  const s = hex.toString("hex");
  return `${s.slice(0, 8)}-${s.slice(8, 12)}-${s.slice(12, 16)}-${s.slice(16, 20)}-${s.slice(20)}`;
};

const looksLikeEmail = (value: string) => /^[^@\s]+@[^@\s]+$/.test(value);
const looksLikePhone = (value: string) => /^\+\d{4,}$/.test(value);

/**
 * CodeDeliveryDetails for a user who does not exist, from the format of the username and the
 * pool's verification settings: an email or phone username is its own destination.
 */
export const simulatedDelivery = (
  username: string,
  preferred: readonly VerifiedAttributeType[],
): DeliveryDetails => {
  if (looksLikeEmail(username)) {
    return {
      AttributeName: "email",
      DeliveryMedium: "EMAIL",
      Destination: username,
    };
  }
  if (looksLikePhone(username)) {
    return {
      AttributeName: "phone_number",
      DeliveryMedium: "SMS",
      Destination: username,
    };
  }
  if (preferred[0] === "phone_number") {
    return {
      AttributeName: "phone_number",
      DeliveryMedium: "SMS",
      Destination: "+*******0000",
    };
  }
  return {
    AttributeName: "email",
    DeliveryMedium: "EMAIL",
    Destination: `${username.charAt(0) || "u"}***@e***`,
  };
};
