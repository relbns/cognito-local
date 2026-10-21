import { createHmac } from "node:crypto";
import jwt from "jsonwebtoken";
import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockCognitoService } from "../__tests__/mockCognitoService";
import { newMockTriggers } from "../__tests__/mockTriggers";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import {
  InvalidParameterError,
  NotAuthorizedError,
  UserNotFoundError,
} from "../errors";
import PrivateKey from "../keys/cognitoLocal.private.json";
import type { CognitoService } from "./cognitoService";
import { JwtTokenGenerator } from "./tokenGenerator";
import { withRefreshToken } from "./tokenRevocation";
import {
  assertClientSecret,
  assertSecretHash,
  computeSecretHash,
  JwtTokenVerifier,
  refreshSecretHashUsername,
} from "./tokenVerifier";
import {
  attributeValue,
  type User,
  type UserPoolService,
} from "./userPoolService";

const ISSUER_DOMAIN = "http://localhost:9229";

describe("JwtTokenVerifier", () => {
  const clock = new ClockFake(new Date(2026, 0, 1, 12, 0, 0));
  const client = TDB.appClient({ UserPoolId: "pool", ClientId: "client" });
  let pool: MockedObject<UserPoolService>;
  let cognito: MockedObject<CognitoService>;
  let verifier: JwtTokenVerifier;
  let user: User;
  let tokens: { AccessToken: string; IdToken: string; RefreshToken: string };

  const verifierWith = (config: object = {}) =>
    new JwtTokenVerifier(clock, cognito, {
      IssuerDomain: ISSUER_DOMAIN,
      ...config,
    });

  beforeEach(async () => {
    clock.advanceTo(new Date(2026, 0, 1, 12, 0, 0));
    pool = newMockUserPoolService({ Id: "pool" });
    cognito = newMockCognitoService(pool);
    cognito.getAppClient.mockImplementation(async (_ctx, id) =>
      id === client.ClientId ? client : null,
    );
    verifier = verifierWith();

    const triggers = newMockTriggers();
    triggers.enabled.mockReturnValue(false);
    const generator = new JwtTokenGenerator(clock, triggers, {
      IssuerDomain: ISSUER_DOMAIN,
    });
    const issuedTo = TDB.user({ Username: "alice" });
    tokens = await generator.generate(
      TestContext,
      issuedTo,
      [],
      client,
      undefined,
      "Authentication",
    );
    user = withRefreshToken(issuedTo, tokens.RefreshToken, clock.get());
    pool.getUserByUsername.mockImplementation(async (_ctx, name) =>
      name === user.Username ? user : null,
    );
  });

  const sign = (claims: object, key = PrivateKey.pem) =>
    jwt.sign(claims, key, { algorithm: "RS256", keyid: "CognitoLocal" });
  const accessClaims = () =>
    jwt.decode(tokens.AccessToken) as Record<string, unknown>;

  describe("verifyAccessToken", () => {
    it("returns the claims, user and pool of a valid token", async () => {
      const result = await verifier.verifyAccessToken(
        TestContext,
        tokens.AccessToken,
      );

      expect(result.user).toBe(user);
      expect(result.userPool).toBe(pool);
      expect(result.claims.username).toEqual("alice");
    });

    it.each([
      ["missing", undefined],
      ["garbage", "not-a-jwt"],
      [
        "a JSON array payload",
        `x.${Buffer.from("[]").toString("base64url")}.y`,
      ],
    ])("rejects a %s token as invalid", async (_, token) => {
      await expect(
        verifier.verifyAccessToken(TestContext, token),
      ).rejects.toEqual(new NotAuthorizedError("Invalid Access Token"));
    });

    it("rejects a token with a bad signature", async () => {
      const [header, payload] = tokens.AccessToken.split(".");
      const tampered = `${header}.${payload}.${"A".repeat(342)}`;

      await expect(
        verifier.verifyAccessToken(TestContext, tampered),
      ).rejects.toEqual(new NotAuthorizedError("Invalid Access Token"));
    });

    it("rejects an ID token", async () => {
      await expect(
        verifier.verifyAccessToken(TestContext, tokens.IdToken),
      ).rejects.toEqual(new NotAuthorizedError("Invalid Access Token"));
    });

    it("rejects a token for an unknown client", async () => {
      const token = sign({ ...accessClaims(), client_id: "gone" });

      await expect(
        verifier.verifyAccessToken(TestContext, token),
      ).rejects.toEqual(new NotAuthorizedError("Invalid Access Token"));
    });

    it("rejects a token from another issuer", async () => {
      const token = sign({ ...accessClaims(), iss: "http://other/pool" });

      await expect(
        verifier.verifyAccessToken(TestContext, token),
      ).rejects.toEqual(new NotAuthorizedError("Invalid Access Token"));
    });

    it("rejects an expired token", async () => {
      clock.advanceBy(60 * 60 * 1000);

      await expect(
        verifier.verifyAccessToken(TestContext, tokens.AccessToken),
      ).rejects.toEqual(new NotAuthorizedError("Access Token has expired"));
    });

    it("rejects a token whose user is gone, or was recreated", async () => {
      pool.getUserByUsername.mockResolvedValueOnce(null);
      await expect(
        verifier.verifyAccessToken(TestContext, tokens.AccessToken),
      ).rejects.toEqual(new UserNotFoundError("User does not exist."));

      pool.getUserByUsername.mockResolvedValueOnce(
        TDB.user({ Username: "alice" }),
      );
      await expect(
        verifier.verifyAccessToken(TestContext, tokens.AccessToken),
      ).rejects.toEqual(new UserNotFoundError("User does not exist."));
    });

    it("rejects a disabled user's token", async () => {
      user = { ...user, Enabled: false };

      await expect(
        verifier.verifyAccessToken(TestContext, tokens.AccessToken),
      ).rejects.toEqual(new NotAuthorizedError("User is disabled."));
    });

    it("rejects a token whose session was revoked", async () => {
      user = { ...user, TokenOrigins: [] };

      await expect(
        verifier.verifyAccessToken(TestContext, tokens.AccessToken),
      ).rejects.toEqual(
        new NotAuthorizedError("Access Token has been revoked"),
      );
    });

    it("needs aws.cognito.signin.user.admin unless told otherwise", async () => {
      const token = sign({ ...accessClaims(), scope: "openid email" });

      await expect(
        verifier.verifyAccessToken(TestContext, token),
      ).rejects.toEqual(
        new NotAuthorizedError("Access Token does not have required scopes"),
      );
      await expect(
        verifier.verifyAccessToken(TestContext, token, {
          requireAdminScope: false,
        }),
      ).resolves.toMatchObject({ user });
    });

    it("refuses a client credentials token on user operations", async () => {
      const generator = new JwtTokenGenerator(clock, newMockTriggers(), {
        IssuerDomain: ISSUER_DOMAIN,
      });
      const { AccessToken } = await generator.generateClientCredentials(
        TestContext,
        client,
        ["example.test/read"],
        undefined,
      );

      await expect(
        verifier.verifyAccessToken(TestContext, AccessToken),
      ).rejects.toEqual(
        new NotAuthorizedError("Access Token does not have required scopes"),
      );
      await expect(
        verifier.verifyAccessToken(TestContext, AccessToken, {
          requireAdminScope: false,
        }),
      ).rejects.toEqual(new NotAuthorizedError("Invalid Access Token"));
    });

    describe("with TokenConfig.Verify false", () => {
      it("decodes the token without checking it", async () => {
        clock.advanceBy(48 * 60 * 60 * 1000);
        user = { ...user, TokenOrigins: [] };
        pool.getUserByUsername.mockResolvedValue(user);

        await expect(
          verifierWith({ Verify: false }).verifyAccessToken(
            TestContext,
            tokens.AccessToken,
          ),
        ).resolves.toMatchObject({ user });
      });

      it("keeps the old errors", async () => {
        const lenient = verifierWith({ Verify: false });
        pool.getUserByUsername.mockResolvedValue(null);

        await expect(
          lenient.verifyAccessToken(TestContext, "garbage"),
        ).rejects.toBeInstanceOf(InvalidParameterError);
        await expect(
          lenient.verifyAccessToken(TestContext, tokens.AccessToken),
        ).rejects.toBeInstanceOf(UserNotFoundError);
      });
    });
  });

  describe("verifyRefreshToken", () => {
    it("returns the user of a valid refresh token", async () => {
      const result = await verifier.verifyRefreshToken(
        TestContext,
        tokens.RefreshToken,
        client.ClientId,
      );

      expect(result.user).toBe(user);
      expect(result.claims.jti).toEqual(
        (jwt.decode(tokens.AccessToken) as any).origin_jti,
      );
    });

    it.each([
      ["garbage", () => "garbage"],
      ["an access token", () => tokens.AccessToken],
      [
        "a token with another signature",
        () =>
          `${tokens.RefreshToken.split(".").slice(0, 2).join(".")}.${"A".repeat(342)}`,
      ],
    ])("rejects %s as invalid", async (_, token) => {
      await expect(
        verifier.verifyRefreshToken(TestContext, token(), client.ClientId),
      ).rejects.toEqual(new NotAuthorizedError("Invalid Refresh Token"));
    });

    it("rejects a refresh token issued to another client", async () => {
      cognito.getAppClient.mockResolvedValue(client);

      await expect(
        verifier.verifyRefreshToken(TestContext, tokens.RefreshToken, "other"),
      ).rejects.toEqual(new NotAuthorizedError("Invalid Refresh Token"));
    });

    it("rejects an expired refresh token", async () => {
      clock.advanceBy(30 * 24 * 60 * 60 * 1000);

      await expect(
        verifier.verifyRefreshToken(
          TestContext,
          tokens.RefreshToken,
          client.ClientId,
        ),
      ).rejects.toEqual(new NotAuthorizedError("Refresh Token has expired"));
    });

    it("rejects a revoked refresh token", async () => {
      user = { ...user, RefreshTokens: [] };

      await expect(
        verifier.verifyRefreshToken(
          TestContext,
          tokens.RefreshToken,
          client.ClientId,
        ),
      ).rejects.toEqual(
        new NotAuthorizedError("Refresh Token has been revoked"),
      );
    });

    it("rejects the refresh token of a disabled or deleted user", async () => {
      user = { ...user, Enabled: false };
      await expect(
        verifier.verifyRefreshToken(
          TestContext,
          tokens.RefreshToken,
          client.ClientId,
        ),
      ).rejects.toEqual(new NotAuthorizedError("User is disabled."));

      pool.getUserByUsername.mockResolvedValue(null);
      await expect(
        verifier.verifyRefreshToken(
          TestContext,
          tokens.RefreshToken,
          client.ClientId,
        ),
      ).rejects.toEqual(new NotAuthorizedError("User does not exist."));
    });

    it("only looks the token up when TokenConfig.Verify is false", async () => {
      clock.advanceBy(60 * 24 * 60 * 60 * 1000);
      pool.getUserByRefreshToken.mockResolvedValue(user);

      await expect(
        verifierWith({ Verify: false }).verifyRefreshToken(
          TestContext,
          tokens.RefreshToken,
          client.ClientId,
        ),
      ).resolves.toMatchObject({ user });

      pool.getUserByRefreshToken.mockResolvedValue(null);
      await expect(
        verifierWith({ Verify: false }).verifyRefreshToken(
          TestContext,
          tokens.RefreshToken,
          client.ClientId,
        ),
      ).rejects.toEqual(new NotAuthorizedError());
    });
  });

  describe("secrets", () => {
    const secretClient = TDB.appClient({
      ClientId: "client",
      ClientSecret: "s3cret",
    });

    it("computes SECRET_HASH as base64 HMAC-SHA256 of username + client id", () => {
      expect(computeSecretHash("alice", "client", "s3cret")).toEqual(
        createHmac("sha256", "s3cret").update("aliceclient").digest("base64"),
      );
    });

    it("accepts any client without a secret", () => {
      expect(() =>
        assertSecretHash(client, ["alice"], undefined),
      ).not.toThrow();
      expect(() => assertClientSecret(client, undefined)).not.toThrow();
    });

    it("requires and checks SECRET_HASH", () => {
      const good = computeSecretHash("alice", "client", "s3cret");

      expect(() =>
        assertSecretHash(secretClient, ["alice"], undefined),
      ).toThrow(
        new NotAuthorizedError(
          "Client client is configured for secret but secret was not received",
        ),
      );
      expect(() => assertSecretHash(secretClient, ["bob"], good)).toThrow(
        new NotAuthorizedError(
          "Unable to verify secret hash for client client",
        ),
      );
      expect(() =>
        assertSecretHash(secretClient, [undefined, "alice"], good),
      ).not.toThrow();
    });

    it("requires and checks a ClientSecret", () => {
      expect(() => assertClientSecret(secretClient, undefined)).toThrow(
        NotAuthorizedError,
      );
      expect(() => assertClientSecret(secretClient, "wrong")).toThrow(
        NotAuthorizedError,
      );
      expect(() => assertClientSecret(secretClient, "s3cret")).not.toThrow();
    });

    it("skips both checks when TokenConfig.CheckSecretHash is false", () => {
      const lenient = verifierWith({ CheckSecretHash: false });

      expect(() =>
        lenient.verifySecretHash(secretClient, ["alice"], undefined),
      ).not.toThrow();
      expect(() =>
        lenient.verifyClientSecret(secretClient, undefined),
      ).not.toThrow();
      expect(() =>
        verifier.verifySecretHash(secretClient, ["alice"], undefined),
      ).toThrow(NotAuthorizedError);
    });

    it("uses the sub for refresh SECRET_HASH when the pool signs in with an attribute", () => {
      expect(refreshSecretHashUsername(pool, user)).toEqual("alice");

      pool.options.UsernameAttributes = ["email"];
      expect(refreshSecretHashUsername(pool, user)).toEqual(
        attributeValue("sub", user.Attributes),
      );
    });
  });
});
