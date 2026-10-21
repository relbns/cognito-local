import {
  AuthenticationDetails,
  CognitoUser,
  CognitoUserPool,
  type CognitoUserSession,
} from "amazon-cognito-identity-js";
import type { CognitoIdentityServiceProvider } from "aws-sdk";
import { describe, expect, it } from "vitest";
import { ClockFake } from "../../src/__tests__/clockFake";
import { fakeLambdaClient } from "../../src/__tests__/fakeLambdaClient";
import { srpClient } from "../../src/__tests__/srpClient";
import { LambdaService } from "../../src/services";
import { withCognitoSdk } from "./setup";

type TriggerEvent = {
  triggerSource: string;
  request: Record<string, any>;
  response: Record<string, any>;
};

type SignInResult =
  | { result: "success"; session: CognitoUserSession }
  | { result: "newPasswordRequired" }
  | { result: "customChallenge"; user: CognitoUser };

const PASSWORD = "Example-Passw0rd!";

// SRP first, then a fixed custom challenge.
const handlers: Record<string, (event: TriggerEvent) => TriggerEvent> = {
  DefineAuthChallenge(event) {
    const last = event.request.session.at(-1);
    event.response.issueTokens = false;
    event.response.failAuthentication = false;
    if (last?.challengeName === "SRP_A") {
      event.response.challengeName = "PASSWORD_VERIFIER";
    } else if (last?.challengeName === "PASSWORD_VERIFIER") {
      event.response.challengeName = "CUSTOM_CHALLENGE";
    } else if (last?.challengeResult === true) {
      event.response.issueTokens = true;
    } else {
      event.response.failAuthentication = true;
    }
    return event;
  },
  CreateAuthChallenge(event) {
    event.response.privateChallengeParameters = { answer: "42" };
    return event;
  },
  VerifyAuthChallengeResponse(event) {
    event.response.answerCorrect = event.request.challengeAnswer === "42";
    return event;
  },
};

const signIn = (
  pool: CognitoUserPool,
  username: string,
  password: string,
  flow: "USER_SRP_AUTH" | "CUSTOM_AUTH" = "USER_SRP_AUTH",
) =>
  new Promise<SignInResult>((resolve, reject) => {
    const user = new CognitoUser({ Username: username, Pool: pool });
    user.setAuthenticationFlowType(flow);
    user.authenticateUser(
      new AuthenticationDetails({ Username: username, Password: password }),
      {
        onSuccess: (session) => resolve({ result: "success", session }),
        onFailure: reject,
        newPasswordRequired: () => resolve({ result: "newPasswordRequired" }),
        customChallenge: () => resolve({ result: "customChallenge", user }),
      },
    );
  });

const answerCustomChallenge = (user: CognitoUser, answer: string) =>
  new Promise<CognitoUserSession>((resolve, reject) => {
    user.sendCustomChallengeAnswer(answer, {
      onSuccess: resolve,
      onFailure: reject,
    });
  });

const setup = async (
  client: CognitoIdentityServiceProvider,
  serverUrl: string,
  user: { temporary?: boolean } = {},
) => {
  const pool = await client.createUserPool({ PoolName: "srp" }).promise();
  const userPoolId = pool.UserPool?.Id as string;
  const upc = await client
    .createUserPoolClient({ UserPoolId: userPoolId, ClientName: "srp" })
    .promise();
  await client
    .adminCreateUser({
      UserPoolId: userPoolId,
      Username: "srp-user",
      MessageAction: "SUPPRESS",
      TemporaryPassword: PASSWORD,
      UserAttributes: [{ Name: "email", Value: "srp-user@example.test" }],
    })
    .promise();
  if (!user.temporary) {
    await client
      .adminSetUserPassword({
        UserPoolId: userPoolId,
        Username: "srp-user",
        Password: PASSWORD,
        Permanent: true,
      })
      .promise();
  }
  return {
    userPoolId,
    clientId: upc.UserPoolClient?.ClientId as string,
    pool: new CognitoUserPool({
      UserPoolId: userPoolId,
      ClientId: upc.UserPoolClient?.ClientId as string,
      endpoint: serverUrl,
    }),
  };
};

describe(
  "USER_SRP_AUTH with amazon-cognito-identity-js",
  withCognitoSdk((Cognito, { serverUrl }) => {
    it("signs in with the right password", async () => {
      const { pool } = await setup(Cognito(), serverUrl());

      for (let i = 0; i < 3; i++) {
        const outcome = await signIn(pool, "srp-user", PASSWORD);

        expect(outcome.result).toEqual("success");
        if (outcome.result === "success") {
          expect(outcome.session.getIdToken().payload["cognito:username"]).toBe(
            "srp-user",
          );
        }
      }
    });

    it("signs in by email alias, keyed on the internal username", async () => {
      const client = Cognito();
      const pool = await client
        .createUserPool({ PoolName: "srp", UsernameAttributes: ["email"] })
        .promise();
      const userPoolId = pool.UserPool?.Id as string;
      const upc = await client
        .createUserPoolClient({ UserPoolId: userPoolId, ClientName: "srp" })
        .promise();
      await client
        .adminCreateUser({
          UserPoolId: userPoolId,
          Username: "alias@example.test",
          MessageAction: "SUPPRESS",
        })
        .promise();
      await client
        .adminSetUserPassword({
          UserPoolId: userPoolId,
          Username: "alias@example.test",
          Password: PASSWORD,
          Permanent: true,
        })
        .promise();

      const outcome = await signIn(
        new CognitoUserPool({
          UserPoolId: userPoolId,
          ClientId: upc.UserPoolClient?.ClientId as string,
          endpoint: serverUrl(),
        }),
        "alias@example.test",
        PASSWORD,
      );

      expect(outcome.result).toEqual("success");
    });

    it("fails with NotAuthorizedException for a wrong password", async () => {
      const { pool } = await setup(Cognito(), serverUrl());

      await expect(
        signIn(pool, "srp-user", "Wrong-Passw0rd!"),
      ).rejects.toMatchObject({
        code: "NotAuthorizedException",
        message: "Incorrect username or password.",
      });
    });

    it("asks for a new password after the right temporary password only", async () => {
      const { pool } = await setup(Cognito(), serverUrl(), {
        temporary: true,
      });

      await expect(signIn(pool, "srp-user", PASSWORD)).resolves.toEqual({
        result: "newPasswordRequired",
      });
      await expect(
        signIn(pool, "srp-user", "Wrong-Passw0rd!"),
      ).rejects.toMatchObject({ code: "NotAuthorizedException" });
    });

    it("verifies AdminInitiateAuth USER_SRP_AUTH claims", async () => {
      const client = Cognito();
      const { userPoolId, clientId } = await setup(client, serverUrl());

      const answer = async (password: string) => {
        const srp = srpClient(userPoolId);
        const challenge = await client
          .adminInitiateAuth({
            UserPoolId: userPoolId,
            ClientId: clientId,
            AuthFlow: "USER_SRP_AUTH",
            AuthParameters: { USERNAME: "srp-user", SRP_A: srp.srpA },
          })
          .promise();
        return client
          .adminRespondToAuthChallenge({
            UserPoolId: userPoolId,
            ClientId: clientId,
            ChallengeName: "PASSWORD_VERIFIER",
            ChallengeResponses: srp.respond(
              challenge.ChallengeParameters as Record<string, string>,
              password,
            ),
            Session: challenge.Session,
          })
          .promise();
      };

      const result = await answer(PASSWORD);
      expect(result.AuthenticationResult?.IdToken).toEqual(expect.any(String));
      await expect(answer("Wrong-Passw0rd!")).rejects.toMatchObject({
        code: "NotAuthorizedException",
        message: "Incorrect username or password.",
      });
    });
  }),
);

describe(
  "CUSTOM_AUTH with an SRP step, with amazon-cognito-identity-js",
  withCognitoSdk(
    (Cognito, { serverUrl }) => {
      it("checks the password before the custom challenge", async () => {
        const { pool } = await setup(Cognito(), serverUrl());

        const outcome = await signIn(pool, "srp-user", PASSWORD, "CUSTOM_AUTH");
        expect(outcome.result).toEqual("customChallenge");
        if (outcome.result !== "customChallenge") return;

        const session = await answerCustomChallenge(outcome.user, "42");
        expect(session.getAccessToken().getJwtToken()).toEqual(
          expect.any(String),
        );
      });

      it("fails with NotAuthorizedException for a wrong password", async () => {
        const { pool } = await setup(Cognito(), serverUrl());

        await expect(
          signIn(pool, "srp-user", "Wrong-Passw0rd!", "CUSTOM_AUTH"),
        ).rejects.toMatchObject({
          code: "NotAuthorizedException",
          message: "Incorrect username or password.",
        });
      });
    },
    {
      clock: new ClockFake(new Date()),
      lambda: () =>
        new LambdaService(
          {
            DefineAuthChallenge: "DefineAuthChallenge",
            CreateAuthChallenge: "CreateAuthChallenge",
            VerifyAuthChallengeResponse: "VerifyAuthChallengeResponse",
          },
          fakeLambdaClient((functionName, event) =>
            handlers[functionName](event),
          ),
        ),
    },
  ),
);
