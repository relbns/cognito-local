import type {
  AdminRespondToAuthChallengeRequest,
  AdminRespondToAuthChallengeResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import { v4 } from "uuid";
import {
  CodeMismatchError,
  InvalidParameterError,
  NotAuthorizedError,
  UnsupportedError,
} from "../errors";
import type { Services } from "../services";
import {
  isCustomAuthSession,
  respondToCustomAuthChallenge,
} from "../services/customAuth";
import { assertPasswordConformsToPolicy } from "../services/passwordPolicy";
import { verifyPasswordClaim } from "../services/srp";
import { verify as verifyTotp } from "../services/totp";
import { attributesToRecord } from "../services/userPoolService";
import type { Target } from "./Target";

export type AdminRespondToAuthChallengeTarget = Target<
  AdminRespondToAuthChallengeRequest,
  AdminRespondToAuthChallengeResponse
>;

type AdminRespondToAuthChallengeServices = Pick<
  Services,
  | "authSessions"
  | "clock"
  | "cognito"
  | "srpSessions"
  | "triggers"
  | "tokenGenerator"
  | "tokenVerifier"
> &
  Partial<Pick<Services, "config">>;

export const AdminRespondToAuthChallenge =
  (
    services: AdminRespondToAuthChallengeServices,
  ): AdminRespondToAuthChallengeTarget =>
  async (ctx, req) => {
    const { clock, cognito, triggers, tokenGenerator } = services;
    if (!req.ChallengeResponses) {
      throw new InvalidParameterError(
        "Missing required parameter challenge responses",
      );
    }
    if (!req.ChallengeResponses.USERNAME) {
      throw new InvalidParameterError("Missing required parameter USERNAME");
    }
    if (!req.Session && req.ChallengeName !== "PASSWORD_VERIFIER") {
      throw new InvalidParameterError("Missing required parameter Session");
    }

    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const userPoolClient = await cognito.getAppClient(ctx, req.ClientId);

    const user = await userPool.getUserByUsername(
      ctx,
      req.ChallengeResponses.USERNAME,
    );
    if (userPoolClient) {
      services.tokenVerifier.verifySecretHash(
        userPoolClient,
        [req.ChallengeResponses.USERNAME],
        req.ChallengeResponses.SECRET_HASH,
      );
    }
    if (!user || !userPoolClient) {
      throw new NotAuthorizedError();
    }

    if (
      req.ChallengeName === "CUSTOM_CHALLENGE" ||
      (req.ChallengeName === "PASSWORD_VERIFIER" &&
        req.Session &&
        isCustomAuthSession(services, req.Session))
    ) {
      return respondToCustomAuthChallenge(ctx, services, {
        userPool,
        user,
        client: userPoolClient,
        sessionId: req.Session as string,
        challengeName: req.ChallengeName,
        challengeResponses: req.ChallengeResponses,
        clientMetadata: req.ClientMetadata,
      });
    }

    if (req.ChallengeName === "SMS_MFA") {
      if (user.MFACode !== req.ChallengeResponses.SMS_MFA_CODE) {
        throw new CodeMismatchError();
      }

      await userPool.saveUser(ctx, {
        ...user,
        MFACode: undefined,
        UserLastModifiedDate: clock.get(),
      });
    } else if (req.ChallengeName === "SOFTWARE_TOKEN_MFA") {
      const code = req.ChallengeResponses.SOFTWARE_TOKEN_MFA_CODE;
      const secret = user.SoftwareTokenMfaConfiguration?.Secret;
      if (
        !code ||
        !secret ||
        !user.SoftwareTokenMfaConfiguration?.Verified ||
        !verifyTotp(secret, code)
      ) {
        throw new CodeMismatchError();
      }
      await userPool.saveUser(ctx, {
        ...user,
        UserLastModifiedDate: clock.get(),
      });
    } else if (req.ChallengeName === "NEW_PASSWORD_REQUIRED") {
      if (!req.ChallengeResponses.NEW_PASSWORD) {
        throw new InvalidParameterError(
          "Missing required parameter NEW_PASSWORD",
        );
      }

      assertPasswordConformsToPolicy(
        services.config,
        userPool.options,
        req.ChallengeResponses.NEW_PASSWORD,
      );

      await userPool.saveUser(ctx, {
        ...user,
        Password: req.ChallengeResponses.NEW_PASSWORD,
        UserLastModifiedDate: clock.get(),
        UserStatus: "CONFIRMED",
      });
    } else if (req.ChallengeName === "PASSWORD_VERIFIER") {
      verifyPasswordClaim(services.srpSessions, {
        userPoolId: userPool.options.Id,
        clientId: userPoolClient.ClientId,
        user,
        challengeResponses: req.ChallengeResponses,
      });
      if (
        (userPool.options.MfaConfiguration === "OPTIONAL" &&
          ((user.MFAOptions ?? []).length > 0 ||
            (user.UserMFASettingList ?? []).length > 0)) ||
        userPool.options.MfaConfiguration === "ON"
      ) {
        return {
          ChallengeName:
            user.PreferredMfaSetting === "SOFTWARE_TOKEN_MFA"
              ? "SOFTWARE_TOKEN_MFA"
              : "SMS_MFA",
          ChallengeParameters: {
            USER_ID_FOR_SRP: user.Username,
          } as AdminRespondToAuthChallengeResponse["ChallengeParameters"],
          Session: v4(),
        };
      }
      if (user.UserStatus === "FORCE_CHANGE_PASSWORD") {
        return {
          ChallengeName: "NEW_PASSWORD_REQUIRED",
          ChallengeParameters: {
            USER_ID_FOR_SRP: user.Username,
            requiredAttributes: JSON.stringify([]),
            userAttributes: JSON.stringify(attributesToRecord(user.Attributes)),
          } as AdminRespondToAuthChallengeResponse["ChallengeParameters"],
          Session: v4(),
        };
      }
    } else if (req.ChallengeName === "MFA_SETUP") {
      if (!req.ChallengeResponses.SOFTWARE_TOKEN_MFA_CODE) {
        throw new InvalidParameterError(
          "Missing required parameter SOFTWARE_TOKEN_MFA_CODE",
        );
      }
      const mfaSettingList = user.UserMFASettingList ?? [];
      if (!mfaSettingList.includes("SOFTWARE_TOKEN_MFA")) {
        mfaSettingList.push("SOFTWARE_TOKEN_MFA");
      }
      await userPool.saveUser(ctx, {
        ...user,
        UserMFASettingList: mfaSettingList,
        PreferredMfaSetting: "SOFTWARE_TOKEN_MFA",
        UserLastModifiedDate: clock.get(),
      });
    } else {
      throw new UnsupportedError(
        `adminRespondToAuthChallenge with ChallengeName=${req.ChallengeName}`,
      );
    }

    if (triggers.enabled("PostAuthentication", req.UserPoolId)) {
      await triggers.postAuthentication(ctx, {
        clientId: req.ClientId,
        clientMetadata: req.ClientMetadata,
        source: "PostAuthentication_Authentication",
        userAttributes: user.Attributes,
        username: user.Username,
        userPoolId: req.UserPoolId,
      });
    }

    const userGroups = await userPool.listUserGroupMembership(ctx, user);
    const tokens = await tokenGenerator.generate(
      ctx,
      user,
      userGroups,
      userPoolClient,
      req.ClientMetadata,
      "Authentication",
    );
    await userPool.storeRefreshToken(ctx, tokens.RefreshToken, user);

    return {
      ChallengeParameters: {},
      AuthenticationResult: tokens,
    };
  };
