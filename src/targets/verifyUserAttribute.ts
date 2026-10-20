import type {
  VerifyUserAttributeRequest,
  VerifyUserAttributeResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import { CodeMismatchError } from "../errors";
import type { Services } from "../services";
import { enforceAliasUniqueness } from "../services/aliases";
import { attribute, attributesAppend } from "../services/userPoolService";
import type { Target } from "./Target";

export type VerifyUserAttributeTarget = Target<
  VerifyUserAttributeRequest,
  VerifyUserAttributeResponse
>;

type VerifyUserAttributeServices = Pick<Services, "clock" | "tokenVerifier">;

export const VerifyUserAttribute =
  ({
    clock,
    tokenVerifier,
  }: VerifyUserAttributeServices): VerifyUserAttributeTarget =>
  async (ctx, req) => {
    const { user, userPool } = await tokenVerifier.verifyAccessToken(
      ctx,
      req.AccessToken,
    );

    if (req.Code !== user.AttributeVerificationCode) {
      throw new CodeMismatchError();
    }

    const attributesToUpdate = [
      ...user.Attributes,
      ...(user.UnverifiedAttributeChanges ?? []),
    ];

    if (req.AttributeName !== "email" && req.AttributeName !== "phone_number") {
      // not sure what to do here
      return {};
    }

    const verifiedAttributes = attributesAppend(
      attributesToUpdate,
      attribute(`${req.AttributeName}_verified`, "true"),
    );

    // Verifying a value that is another user's verified alias moves the alias, without AliasExistsException.
    await enforceAliasUniqueness(
      ctx,
      userPool,
      clock,
      user.Username,
      verifiedAttributes,
      { attributeNames: [req.AttributeName], forceAliasCreation: true },
    );

    await userPool.saveUser(ctx, {
      ...user,
      Attributes: verifiedAttributes,
      UserLastModifiedDate: clock.get(),
      UnverifiedAttributeChanges: undefined,
      AttributeVerificationCode: undefined,
    });

    return {};
  };
