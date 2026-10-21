import type {
  AccountRecoverySettingType,
  VerifiedAttributeType,
} from "@aws-sdk/client-cognito-identity-provider";
import { attributeValue, type User } from "../userPoolService";
import type { DeliveryDetails } from "./messageDelivery";

export const selectAppropriateDeliveryMethod = (
  desiredDeliveryMediums: VerifiedAttributeType[],
  user: User,
): DeliveryDetails | null => {
  if (desiredDeliveryMediums.includes("phone_number")) {
    const phoneNumber =
      attributeValue("phone_number", user.UnverifiedAttributeChanges) ??
      attributeValue("phone_number", user.Attributes);
    if (phoneNumber) {
      return {
        AttributeName: "phone_number",
        DeliveryMedium: "SMS",
        Destination: phoneNumber,
      };
    }
  }

  if (desiredDeliveryMediums.includes("email")) {
    const email =
      attributeValue("email", user.UnverifiedAttributeChanges) ??
      attributeValue("email", user.Attributes);
    if (email) {
      return {
        AttributeName: "email",
        DeliveryMedium: "EMAIL",
        Destination: email,
      };
    }
  }

  return null;
};

// Without AccountRecoverySetting, Cognito sends the code to a verified phone number first.
const DEFAULT_RECOVERY_ORDER = ["verified_phone_number", "verified_email"];

/** The attributes ForgotPassword may send to, in AccountRecoverySetting priority order. */
export const recoveryAttributeOrder = (
  setting: AccountRecoverySettingType | undefined,
): VerifiedAttributeType[] => {
  const mechanisms = setting?.RecoveryMechanisms;
  const names = mechanisms?.length
    ? [...mechanisms]
        .sort((a, b) => (a.Priority ?? 0) - (b.Priority ?? 0))
        .map((m) => m.Name)
    : DEFAULT_RECOVERY_ORDER;
  return names.flatMap((name): VerifiedAttributeType[] =>
    name === "verified_email"
      ? ["email"]
      : name === "verified_phone_number"
        ? ["phone_number"]
        : [],
  );
};

/** Where ForgotPassword sends the code: the first verified email or phone number the recovery setting allows. */
export const selectRecoveryDeliveryMethod = (
  setting: AccountRecoverySettingType | undefined,
  user: User,
): DeliveryDetails | null => {
  for (const attribute of recoveryAttributeOrder(setting)) {
    const value = attributeValue(attribute, user.Attributes);
    if (!value) continue;
    if (attributeValue(`${attribute}_verified`, user.Attributes) !== "true") {
      continue;
    }
    return attribute === "email"
      ? { AttributeName: "email", DeliveryMedium: "EMAIL", Destination: value }
      : {
          AttributeName: "phone_number",
          DeliveryMedium: "SMS",
          Destination: value,
        };
  }
  return null;
};
