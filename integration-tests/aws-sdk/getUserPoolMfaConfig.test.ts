import { describe, expect, it } from "vitest";
import { withCognitoSdk } from "./setup";

describe(
  "CognitoIdentityServiceProvider.getUserPoolMfaConfig",
  withCognitoSdk((Cognito) => {
    it("gets the user pool MFA config", async () => {
      const client = Cognito();

      const up = await client
        .createUserPool({
          PoolName: "pool",
          MfaConfiguration: "OPTIONAL",
          SmsAuthenticationMessage: "Your code is {####}",
        })
        .promise();

      const getResponse = await client
        .getUserPoolMfaConfig({
          UserPoolId: up.UserPool?.Id!,
        })
        .promise();

      expect(getResponse).toEqual({
        MfaConfiguration: "OPTIONAL",
        SmsMfaConfiguration: {
          SmsAuthenticationMessage: "Your code is {####}",
        },
        SoftwareTokenMfaConfiguration: {
          Enabled: false,
        },
      });
    });
  }),
);
