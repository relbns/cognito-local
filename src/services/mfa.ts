import type { DeliveryDetails } from "./messageDelivery/messageDelivery";
import { attributeValue, type User, type UserPool } from "./userPoolService";

export type MfaMethod = "SMS_MFA" | "SOFTWARE_TOKEN_MFA";

export const isMfaRequired = (
  userPool: Pick<UserPool, "MfaConfiguration">,
  user: User,
): boolean => {
  const userHasMfa =
    (user.MFAOptions ?? []).length > 0 ||
    (user.UserMFASettingList ?? []).length > 0;
  return (
    userPool.MfaConfiguration === "ON" ||
    (userPool.MfaConfiguration !== "OFF" && userHasMfa)
  );
};

export const enabledMfaMethods = (user: User): readonly MfaMethod[] => {
  const explicit = user.UserMFASettingList ?? [];
  const legacy =
    explicit.length === 0 &&
    (user.MFAOptions ?? []).some((o) => o.DeliveryMedium === "SMS")
      ? ["SMS_MFA"]
      : [];
  const methods = new Set<string>([...explicit, ...legacy]);

  const result: MfaMethod[] = [];
  if (methods.has("SMS_MFA")) result.push("SMS_MFA");
  // A TOTP challenge before registration is verified could never be answered.
  if (
    methods.has("SOFTWARE_TOKEN_MFA") &&
    user.SoftwareTokenMfaConfiguration?.Verified
  ) {
    result.push("SOFTWARE_TOKEN_MFA");
  }
  return result;
};

// SMS MFA codes go to phone_number, the only attribute an SMS MFAOption can name.
export const smsMfaDelivery = (user: User): DeliveryDetails | null => {
  const destination = attributeValue("phone_number", user.Attributes);
  return destination
    ? {
        DeliveryMedium: "SMS",
        AttributeName: "phone_number",
        Destination: destination,
      }
    : null;
};
