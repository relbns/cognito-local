import type { VerifiedAttributeType } from "@aws-sdk/client-cognito-identity-provider";
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
