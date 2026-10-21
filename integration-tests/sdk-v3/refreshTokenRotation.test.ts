import {
  AdminCreateUserCommand,
  AdminSetUserPasswordCommand,
  CognitoIdentityProviderClient,
  CreateUserPoolClientCommand,
  CreateUserPoolCommand,
  DescribeUserPoolClientCommand,
  GetTokensFromRefreshTokenCommand,
  InitiateAuthCommand,
  InvalidParameterException,
  NotAuthorizedException,
} from "@aws-sdk/client-cognito-identity-provider";
import jwt from "jsonwebtoken";
import { describe, expect, it } from "vitest";
import { ClockFake } from "../../src/__tests__/clockFake";
import { withCognitoSdk } from "../aws-sdk/setup";

const PASSWORD = "Passw0rd!";
const credentials = { accessKeyId: "local", secretAccessKey: "local" };
const clock = new ClockFake(new Date());

describe(
  "refresh token rotation",
  withCognitoSdk(
    (_, { serverUrl }) => {
      const setup = async (rotation?: {
        Feature: "ENABLED" | "DISABLED";
        RetryGracePeriodSeconds?: number;
      }) => {
        clock.advanceTo(new Date());
        const cognito = new CognitoIdentityProviderClient({
          region: "us-east-1",
          endpoint: serverUrl(),
          credentials,
        });
        const pool = await cognito.send(
          new CreateUserPoolCommand({ PoolName: "rotation" }),
        );
        const UserPoolId = pool.UserPool!.Id!;
        const app = await cognito.send(
          new CreateUserPoolClientCommand({
            UserPoolId,
            ClientName: "web",
            ExplicitAuthFlows: ["ALLOW_USER_PASSWORD_AUTH"],
            AllowedOAuthFlows: ["code"],
            AllowedOAuthFlowsUserPoolClient: true,
            AllowedOAuthScopes: ["openid"],
            CallbackURLs: ["http://localhost:9876"],
            RefreshTokenRotation: rotation,
          }),
        );
        const ClientId = app.UserPoolClient!.ClientId!;
        await cognito.send(
          new AdminCreateUserCommand({
            UserPoolId,
            Username: "jane@example.test",
            MessageAction: "SUPPRESS",
          }),
        );
        await cognito.send(
          new AdminSetUserPasswordCommand({
            UserPoolId,
            Username: "jane@example.test",
            Password: PASSWORD,
            Permanent: true,
          }),
        );
        const auth = await cognito.send(
          new InitiateAuthCommand({
            ClientId,
            AuthFlow: "USER_PASSWORD_AUTH",
            AuthParameters: { USERNAME: "jane@example.test", PASSWORD },
          }),
        );
        return {
          cognito,
          UserPoolId,
          ClientId,
          refreshToken: auth.AuthenticationResult!.RefreshToken!,
        };
      };

      const refresh = (
        cognito: CognitoIdentityProviderClient,
        ClientId: string,
        RefreshToken: string,
      ) =>
        cognito.send(
          new GetTokensFromRefreshTokenCommand({ ClientId, RefreshToken }),
        );

      it("returns no refresh token without rotation", async () => {
        const { cognito, ClientId, refreshToken } = await setup();

        const result = await refresh(cognito, ClientId, refreshToken);

        expect(result.AuthenticationResult?.AccessToken).toBeDefined();
        expect(result.AuthenticationResult?.RefreshToken).toBeUndefined();
        await expect(
          refresh(cognito, ClientId, refreshToken),
        ).resolves.toBeDefined();
      });

      it("rotates the refresh token and retires the old one after the grace period", async () => {
        const { cognito, UserPoolId, ClientId, refreshToken } = await setup({
          Feature: "ENABLED",
          RetryGracePeriodSeconds: 10,
        });
        const described = await cognito.send(
          new DescribeUserPoolClientCommand({ UserPoolId, ClientId }),
        );
        expect(described.UserPoolClient?.RefreshTokenRotation).toEqual({
          Feature: "ENABLED",
          RetryGracePeriodSeconds: 10,
        });

        clock.advanceBy(2_000);
        const first = await refresh(cognito, ClientId, refreshToken);
        const rotated = first.AuthenticationResult!.RefreshToken!;
        expect(rotated).toBeDefined();
        expect(rotated).not.toEqual(refreshToken);
        const before = jwt.decode(refreshToken) as { exp: number; jti: string };
        expect(jwt.decode(rotated)).toMatchObject({
          exp: before.exp,
          jti: before.jti,
        });
        expect(
          (
            jwt.decode(first.AuthenticationResult!.AccessToken!) as {
              origin_jti: string;
            }
          ).origin_jti,
        ).toBe(before.jti);

        clock.advanceBy(5_000);
        const retry = await refresh(cognito, ClientId, refreshToken);
        expect(retry.AuthenticationResult?.RefreshToken).toBeDefined();

        clock.advanceBy(6_000);
        await expect(
          refresh(cognito, ClientId, refreshToken),
        ).rejects.toMatchObject({
          name: "NotAuthorizedException",
          message: "Refresh Token has been revoked",
        });
        await expect(
          refresh(cognito, ClientId, rotated),
        ).resolves.toBeDefined();
      });

      it("retires the old token at once without a grace period", async () => {
        const { cognito, ClientId, refreshToken } = await setup({
          Feature: "ENABLED",
        });

        await refresh(cognito, ClientId, refreshToken);

        await expect(
          refresh(cognito, ClientId, refreshToken),
        ).rejects.toBeInstanceOf(NotAuthorizedException);
      });

      it("refuses REFRESH_TOKEN_AUTH", async () => {
        const { cognito, ClientId, refreshToken } = await setup({
          Feature: "ENABLED",
        });

        await expect(
          cognito.send(
            new InitiateAuthCommand({
              ClientId,
              AuthFlow: "REFRESH_TOKEN_AUTH",
              AuthParameters: { REFRESH_TOKEN: refreshToken },
            }),
          ),
        ).rejects.toBeInstanceOf(InvalidParameterException);
      });

      it("returns a new refresh_token from the token endpoint", async () => {
        const { cognito, ClientId, refreshToken } = await setup({
          Feature: "ENABLED",
        });
        const res = await fetch(`${serverUrl()}/oauth2/token`, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "refresh_token",
            client_id: ClientId,
            refresh_token: refreshToken,
          }).toString(),
        });

        expect(res.status).toBe(200);
        const body = await res.json();
        expect(body.refresh_token).toBeDefined();
        expect(body.refresh_token).not.toEqual(refreshToken);
        await expect(
          refresh(cognito, ClientId, body.refresh_token),
        ).resolves.toBeDefined();
      });
    },
    { clock },
  ),
);
