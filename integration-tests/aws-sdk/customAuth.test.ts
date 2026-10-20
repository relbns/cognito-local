import type { CognitoIdentityServiceProvider } from "aws-sdk";
import { describe, expect, it } from "vitest";
import { ClockFake } from "../../src/__tests__/clockFake";
import { LambdaService } from "../../src/services";
import { withCognitoSdk } from "./setup";

type TriggerEvent = {
  triggerSource: string;
  request: Record<string, any>;
  response: Record<string, any>;
};

const invocations: TriggerEvent[] = [];
let nextCode = 0;

const handlers: Record<string, (event: TriggerEvent) => TriggerEvent> = {
  DefineAuthChallenge(event) {
    const session = event.request.session;
    const last = session.at(-1);
    if (session.length >= 3 && last.challengeResult === false) {
      event.response.issueTokens = false;
      event.response.failAuthentication = true;
    } else if (
      last?.challengeName === "CUSTOM_CHALLENGE" &&
      last.challengeResult === true
    ) {
      event.response.issueTokens = true;
      event.response.failAuthentication = false;
    } else {
      event.response.issueTokens = false;
      event.response.failAuthentication = false;
      event.response.challengeName = "CUSTOM_CHALLENGE";
    }
    return event;
  },
  CreateAuthChallenge(event) {
    const session = event.request.session;
    const code = session.length
      ? session.at(-1).challengeMetadata.replace("CODE-", "")
      : String(++nextCode).padStart(6, "0");
    event.response.publicChallengeParameters = { hint: "otp" };
    event.response.privateChallengeParameters = { secretLoginCode: code };
    event.response.challengeMetadata = `CODE-${code}`;
    return event;
  },
  VerifyAuthChallengeResponse(event) {
    event.response.answerCorrect =
      event.request.challengeAnswer ===
      event.request.privateChallengeParameters.secretLoginCode;
    return event;
  },
};

const fakeLambda = () =>
  new LambdaService(
    {
      DefineAuthChallenge: "DefineAuthChallenge",
      CreateAuthChallenge: "CreateAuthChallenge",
      VerifyAuthChallengeResponse: "VerifyAuthChallengeResponse",
    },
    {
      invoke: (params: { FunctionName: string; Payload: string }) => ({
        promise: async () => {
          const result = handlers[params.FunctionName](
            JSON.parse(params.Payload),
          );
          invocations.push(structuredClone(result));
          return { StatusCode: 200, Payload: JSON.stringify(result) };
        },
      }),
    } as any,
  );

const clock = new ClockFake(new Date());

const setup = async (client: CognitoIdentityServiceProvider) => {
  invocations.length = 0;
  const pool = await client.createUserPool({ PoolName: "test" }).promise();
  const userPoolId = pool.UserPool?.Id as string;
  const upc = await client
    .createUserPoolClient({ UserPoolId: userPoolId, ClientName: "test" })
    .promise();
  await client
    .adminCreateUser({
      UserPoolId: userPoolId,
      Username: "otp-user",
      MessageAction: "SUPPRESS",
      UserAttributes: [{ Name: "email", Value: "otp@example.com" }],
    })
    .promise();
  return upc.UserPoolClient?.ClientId as string;
};

const lastCode = () =>
  invocations
    .filter((e) => e.triggerSource === "CreateAuthChallenge_Authentication")
    .at(-1)?.response.privateChallengeParameters.secretLoginCode as string;

describe(
  "CUSTOM_AUTH challenge sessions",
  withCognitoSdk(
    (Cognito) => {
      const start = (clientId: string) =>
        Cognito()
          .initiateAuth({
            ClientId: clientId,
            AuthFlow: "CUSTOM_AUTH",
            AuthParameters: { USERNAME: "otp-user" },
          })
          .promise();

      const answer = (clientId: string, session: string, ANSWER: string) =>
        Cognito()
          .respondToAuthChallenge({
            ClientId: clientId,
            ChallengeName: "CUSTOM_CHALLENGE",
            Session: session,
            ChallengeResponses: { USERNAME: "otp-user", ANSWER },
          })
          .promise();

      it("issues tokens for the correct answer and passes privateChallengeParameters to Verify", async () => {
        const clientId = await setup(Cognito());

        const challenge = await start(clientId);
        expect(challenge.ChallengeName).toEqual("CUSTOM_CHALLENGE");
        expect(challenge.ChallengeParameters).toMatchObject({ hint: "otp" });

        const result = await answer(
          clientId,
          challenge.Session as string,
          lastCode(),
        );

        expect(result.AuthenticationResult?.IdToken).toEqual(
          expect.any(String),
        );
        const verify = invocations.find(
          (e) =>
            e.triggerSource === "VerifyAuthChallengeResponse_Authentication",
        );
        expect(verify?.request.privateChallengeParameters).toEqual({
          secretLoginCode: lastCode(),
        });
      });

      it("accepts the same code on the second round after a wrong answer", async () => {
        const clientId = await setup(Cognito());
        const challenge = await start(clientId);
        const code = lastCode();

        const retry = await answer(
          clientId,
          challenge.Session as string,
          "wrong",
        );
        expect(retry.ChallengeName).toEqual("CUSTOM_CHALLENGE");
        expect(retry.Session).not.toEqual(challenge.Session);
        expect(lastCode()).toEqual(code);

        const result = await answer(clientId, retry.Session as string, code);
        expect(result.AuthenticationResult?.AccessToken).toEqual(
          expect.any(String),
        );

        const defines = invocations.filter(
          (e) => e.triggerSource === "DefineAuthChallenge_Authentication",
        );
        expect(defines.map((e) => e.request.session)).toEqual([
          [],
          [
            {
              challengeName: "CUSTOM_CHALLENGE",
              challengeResult: false,
              challengeMetadata: `CODE-${code}`,
            },
          ],
          [
            {
              challengeName: "CUSTOM_CHALLENGE",
              challengeResult: false,
              challengeMetadata: `CODE-${code}`,
            },
            {
              challengeName: "CUSTOM_CHALLENGE",
              challengeResult: true,
              challengeMetadata: `CODE-${code}`,
            },
          ],
        ]);
      });

      it("fails with NotAuthorized after three wrong answers", async () => {
        const clientId = await setup(Cognito());
        const challenge = await start(clientId);
        const second = await answer(
          clientId,
          challenge.Session as string,
          "bad",
        );
        const third = await answer(clientId, second.Session as string, "bad");

        await expect(
          answer(clientId, third.Session as string, "bad"),
        ).rejects.toMatchObject({ code: "NotAuthorizedException" });
      });

      it("rejects an unknown session", async () => {
        const clientId = await setup(Cognito());

        await expect(
          answer(clientId, "not-a-session", "000001"),
        ).rejects.toMatchObject({
          code: "NotAuthorizedException",
          message: "Invalid session for the user.",
        });
      });

      it("rejects an expired session", async () => {
        const clientId = await setup(Cognito());
        const challenge = await start(clientId);
        clock.advanceBy(3 * 60_000);

        await expect(
          answer(clientId, challenge.Session as string, lastCode()),
        ).rejects.toMatchObject({
          code: "NotAuthorizedException",
          message: "Invalid session for the user, session is expired.",
        });
      });
    },
    { clock, lambda: fakeLambda },
  ),
);
