import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { localRequest } from "../__tests__/localRequest";
import { MockLogger } from "../__tests__/mockLogger";
import { TestContext } from "../__tests__/testContext";
import { createDefaultServices } from "../server/defaults";
import type { Router } from "../server/Router";
import { createServer } from "../server/server";
import type { Services } from "../services";
import { applySeed, SeedApplyError } from "./apply";
import { exportSeed } from "./export";
import { loadSeedFile, parseSeed, relativizeSeedFileTargets } from "./load";
import type { SeedFile } from "./types";
import type { SeedValidationError } from "./validate";

const request = localRequest();

const EXAMPLES = path.resolve(__dirname, "../../examples");

const withoutComment = ({ $comment: _, ...seed }: SeedFile) => seed;

describe("seed files", () => {
  let dataDirectory: string;
  let services: Services;
  let router: Router;

  const servicesFor = async (dir: string) =>
    (
      await createDefaultServices(MockLogger as never, {
        dataDirectory: dir,
        adminUi: true,
      })
    ).services;

  beforeEach(async () => {
    dataDirectory = fs.mkdtempSync(
      path.join(os.tmpdir(), "cognito-local-seed-"),
    );
    ({ services, router } = await createDefaultServices(MockLogger as never, {
      dataDirectory,
      adminUi: true,
    }));
  });

  afterEach(() => {
    fs.rmSync(dataDirectory, { recursive: true, force: true });
  });

  const basic = () => loadSeedFile(path.join(EXAMPLES, "seed.basic.json"));

  describe("apply", () => {
    it("creates pools, clients, resource servers, groups and users with pinned ids", async () => {
      const result = await applySeed(TestContext, services, basic());

      expect(result.changes.filter((c) => c.action !== "created")).toEqual([]);
      expect(result.changes.map((c) => `${c.kind}:${c.id}`)).toEqual([
        "UserPool:local_Example1",
        "ResourceServer:https://api.example.test",
        "Client:examplewebclient0000000001",
        "Client:examplebackendclient000001",
        "Group:admins",
        "Group:members",
        "User:admin@example.test",
        "User:jane@example.test",
        "User:pending@example.test",
      ]);

      const pool = await services.cognito.getUserPool(
        TestContext,
        "local_Example1",
      );
      expect(pool.options).toMatchObject({
        Name: "example",
        UsernameAttributes: ["email"],
        Policies: {
          PasswordPolicy: { MinimumLength: 8, RequireSymbols: false },
        },
      });
      expect(
        pool.options.SchemaAttributes?.find(
          (a) => a.Name === "custom:tenant_id",
        ),
      ).toMatchObject({ AttributeDataType: "String", Mutable: true });

      const backend = await services.cognito.getAppClient(
        TestContext,
        "examplebackendclient000001",
      );
      expect(backend?.ClientSecret).toBe(
        "examplebackendsecret0000000000000000000000000000001",
      );

      const admin = await pool.getUserByUsername(
        TestContext,
        "admin@example.test",
      );
      expect(admin).toMatchObject({
        Username: "00000000-0000-4000-8000-000000000001",
        UserStatus: "CONFIRMED",
        Password: "Passw0rdAdmin",
        Enabled: true,
      });
      expect(await pool.listUserGroupMembership(TestContext, admin!)).toEqual([
        "admins",
        "members",
      ]);
      expect(
        (await pool.getUserByUsername(TestContext, "jane@example.test"))
          ?.UserStatus,
      ).toBe("FORCE_CHANGE_PASSWORD");
      expect(
        (await pool.getUserByUsername(TestContext, "pending@example.test"))
          ?.UserStatus,
      ).toBe("UNCONFIRMED");
    });

    it("is idempotent: a second apply changes nothing and duplicates nothing", async () => {
      await applySeed(TestContext, services, basic());
      const second = await applySeed(TestContext, services, basic());

      expect(second.changes.every((c) => c.action === "unchanged")).toBe(true);
      expect(await services.cognito.listUserPools(TestContext)).toHaveLength(1);
      expect(
        await services.cognito.listAppClients(TestContext, "local_Example1"),
      ).toHaveLength(2);
      const pool = await services.cognito.getUserPool(
        TestContext,
        "local_Example1",
      );
      expect(await pool.listUsers(TestContext)).toHaveLength(3);
    });

    it("survives a restart: state is read back from the data directory", async () => {
      await applySeed(TestContext, services, basic());
      const restarted = await servicesFor(dataDirectory);
      const again = await applySeed(TestContext, restarted, basic());
      expect(again.changes.every((c) => c.action === "unchanged")).toBe(true);
    });

    it("updates what differs and keeps passwords of existing users", async () => {
      await applySeed(TestContext, services, basic());
      const pool = await services.cognito.getUserPool(
        TestContext,
        "local_Example1",
      );
      const admin = await pool.getUserByUsername(
        TestContext,
        "admin@example.test",
      );
      await pool.saveUser(TestContext, {
        ...admin!,
        Password: "ChangedLocally1",
      });

      const seed = basic();
      seed.UserPools[0].MfaConfiguration = "OPTIONAL";
      seed.UserPools[0].Clients![0].CallbackURLs = ["http://localhost:4000/cb"];
      seed.UserPools[0].Groups![1].Description = "Members";
      const user = seed.UserPools[0].Users![0];
      user.Password = "AnotherPassw0rd";
      user.Groups = ["members"];
      user.UserAttributes = [
        ...(user.UserAttributes ?? []),
        { Name: "family_name", Value: "Example" },
      ];

      const result = await applySeed(TestContext, services, seed);
      const changed = result.changes
        .filter((c) => c.action === "updated")
        .map((c) => `${c.kind}:${c.id}:${c.fields?.join(",")}`);
      expect(changed).toEqual([
        "UserPool:local_Example1:MfaConfiguration",
        "Client:examplewebclient0000000001:CallbackURLs",
        "Group:members:Description",
        "User:admin@example.test:UserAttributes.family_name,Groups-admins",
      ]);

      const updated = await pool.getUserByUsername(
        TestContext,
        "admin@example.test",
      );
      expect(updated?.Password).toBe("ChangedLocally1");
      expect(await pool.listUserGroupMembership(TestContext, updated!)).toEqual(
        ["members"],
      );
      expect(pool.options.MfaConfiguration).toBe("OPTIONAL");
    });

    it("matches unpinned pools and clients by name", async () => {
      const seed: SeedFile = {
        UserPools: [
          {
            PoolName: "unpinned",
            UsernameAttributes: [],
            Clients: [{ ClientName: "app", GenerateSecret: true }],
            Users: [{ Username: "someone", Password: "Passw0rd!Some" }],
          },
        ],
      };
      const first = await applySeed(TestContext, services, seed);
      const second = await applySeed(TestContext, services, seed);
      expect(second.changes.every((c) => c.action === "unchanged")).toBe(true);
      const poolId = first.changes[0].id;
      const clients = await services.cognito.listAppClients(
        TestContext,
        poolId,
      );
      expect(clients).toHaveLength(1);
      expect(clients[0].ClientSecret).toMatch(/^\w+$/);
      const pool = await services.cognito.getUserPool(TestContext, poolId);
      expect(pool.options.UsernameAttributes).toEqual([]);
      expect(
        (await pool.getUserByUsername(TestContext, "someone"))?.Username,
      ).toBe("someone");
    });

    it("names the entity and path when applying fails", async () => {
      const seed = basic();
      seed.UserPools[0].Users![0].Password = "short";
      const error = await applySeed(
        TestContext,
        services,
        seed,
        "seed.json",
      ).catch((e) => e);
      expect(error).toBeInstanceOf(SeedApplyError);
      expect(error.message).toBe(
        "Cannot apply seed seed.json: UserPools[0].Users[0] (admin@example.test): InvalidPasswordException: Password does not conform to policy: Password not long enough",
      );

      const missingGroup = basic();
      missingGroup.UserPools[0].Users![1].Groups = ["nope"];
      await expect(
        applySeed(
          TestContext,
          await servicesFor(fs.mkdtempSync(path.join(dataDirectory, "x"))),
          missingGroup,
        ),
      ).rejects.toThrow(
        "UserPools[0].Users[1] (jane@example.test): Groups: group nope does not exist in user pool local_Example1",
      );
    });

    it("refuses a client whose identity provider is missing", async () => {
      const seed = basic();
      seed.UserPools[0].Clients![0].SupportedIdentityProviders = [
        "COGNITO",
        "Google",
      ];
      await expect(applySeed(TestContext, services, seed)).rejects.toThrow(
        "UserPools[0].Clients[0] (web): SupportedIdentityProviders: the provider Google does not exist for User Pool local_Example1",
      );
    });
  });

  describe("validation", () => {
    it("lists every problem with its path", () => {
      let error: SeedValidationError | undefined;
      try {
        parseSeed(
          JSON.stringify({
            UserPools: [
              {
                Id: "bad id",
                PoolName: "p",
                MfaConfiguration: "MAYBE",
                WebAuthnConfiguration: { UserVerification: "always" },
                Clientz: [],
                Clients: [
                  { ClientName: "a" },
                  { ClientName: "a", GenerateSecret: "yes" },
                ],
                Users: [
                  { Username: "u", Password: "x", TemporaryPassword: "y" },
                ],
                LambdaConfig: { PreSignup: "file:./x.js" },
              },
            ],
          }),
          "/tmp/seed.json",
          "/tmp",
        );
      } catch (e) {
        error = e as SeedValidationError;
      }
      expect(error?.issues.map((i) => i.path)).toEqual([
        "UserPools[0].Id",
        "UserPools[0].MfaConfiguration",
        "UserPools[0].WebAuthnConfiguration.UserVerification",
        "UserPools[0].Clientz",
        "UserPools[0].Clients[1].GenerateSecret",
        "UserPools[0].Users[0].TemporaryPassword",
        "UserPools[0].LambdaConfig.PreSignup",
        "UserPools[0].Clients[1].ClientName",
      ]);
      expect(error?.issues[3].message).toMatch(/^unknown field/);
      expect(error?.issues[7].message).toBe(
        'duplicate ClientName "a" (also at UserPools[0].Clients[0])',
      );
    });

    it("checks RefreshTokenRotation on a client", () => {
      const parse = (RefreshTokenRotation: unknown) =>
        parseSeed(
          JSON.stringify({
            UserPools: [
              {
                PoolName: "p",
                Clients: [{ ClientName: "a", RefreshTokenRotation }],
              },
            ],
          }),
          "/tmp/seed.json",
          "/tmp",
        );

      expect(() =>
        parse({ Feature: "ENABLED", RetryGracePeriodSeconds: 10 }),
      ).not.toThrow();
      let error: SeedValidationError | undefined;
      try {
        parse({ Feature: "ON" });
      } catch (e) {
        error = e as SeedValidationError;
      }
      expect(error?.issues.map((i) => i.path)).toEqual([
        "UserPools[0].Clients[0].RefreshTokenRotation.Feature",
      ]);
    });

    it("reports invalid JSON and a missing file", () => {
      expect(() => parseSeed("{", "/tmp/s.json", "/tmp")).toThrow(
        /Invalid seed \/tmp\/s.json:\n {2}- \(root\): not valid JSON/,
      );
      expect(() => loadSeedFile("/nonexistent/seed.json")).toThrow(
        /cannot read file/,
      );
    });

    it("resolves file: triggers relative to the seed file and checks they exist", () => {
      const seed = loadSeedFile(
        path.join(EXAMPLES, "seed.custom-auth-otp.json"),
      );
      expect(seed.UserPools[0].LambdaConfig).toEqual({
        DefineAuthChallenge: `file:${EXAMPLES}/triggers/define-auth-challenge.js`,
        CreateAuthChallenge: `file:${EXAMPLES}/triggers/create-auth-challenge.mjs`,
        VerifyAuthChallengeResponse: `file:${EXAMPLES}/triggers/verify-auth-challenge-response.js`,
      });

      expect(() =>
        parseSeed(
          JSON.stringify({
            UserPools: [
              {
                PoolName: "p",
                LambdaConfig: { PreSignUp: "file:./missing.js" },
              },
            ],
          }),
          "/tmp/s.json",
          "/tmp",
        ),
      ).toThrow(
        "UserPools[0].LambdaConfig.PreSignUp: trigger file /tmp/missing.js does not exist",
      );
    });

    it("relativizes trigger paths for a portable export", () => {
      const seed = loadSeedFile(
        path.join(EXAMPLES, "seed.custom-auth-otp.json"),
      );
      expect(
        relativizeSeedFileTargets(seed, EXAMPLES).UserPools[0].LambdaConfig
          ?.DefineAuthChallenge,
      ).toBe("file:./triggers/define-auth-challenge.js");
      expect(
        relativizeSeedFileTargets(seed, path.join(EXAMPLES, "a")).UserPools[0]
          .LambdaConfig?.DefineAuthChallenge,
      ).toBe("file:../triggers/define-auth-challenge.js");
      expect(
        relativizeSeedFileTargets(seed, "/elsewhere/deep").UserPools[0]
          .LambdaConfig?.DefineAuthChallenge,
      ).toBe(`file:${EXAMPLES}/triggers/define-auth-challenge.js`);
    });
  });

  describe("export", () => {
    it("round-trips: export, apply to a fresh data directory, export again", async () => {
      await applySeed(TestContext, services, basic());
      await applySeed(
        TestContext,
        services,
        loadSeedFile(path.join(EXAMPLES, "seed.federation.json")),
      );
      await applySeed(
        TestContext,
        services,
        loadSeedFile(path.join(EXAMPLES, "seed.custom-auth-otp.json")),
      );
      await applySeed(
        TestContext,
        services,
        loadSeedFile(path.join(EXAMPLES, "seed.passkeys.json")),
      );
      const passkeyPool = await services.cognito.getUserPool(
        TestContext,
        "local_PasskeyExample",
      );
      expect(passkeyPool.options.WebAuthnConfiguration).toEqual({
        RelyingPartyId: "localhost",
        UserVerification: "preferred",
      });
      await applySeed(TestContext, services, {
        UserPools: [
          {
            Id: "local_FedExample",
            PoolName: "federation-example",
            Users: [
              {
                Username: "Google_1234567890",
                UserStatus: "EXTERNAL_PROVIDER",
                UserAttributes: [
                  { Name: "email", Value: "fed@example.test" },
                  {
                    Name: "identities",
                    Value: '[{"userId":"1234567890","providerName":"Google"}]',
                  },
                ],
              },
            ],
          },
        ],
      });
      const fedPool = await services.cognito.getUserPool(
        TestContext,
        "local_FedExample",
      );
      expect(
        await fedPool.getUserByUsername(TestContext, "Google_1234567890"),
      ).toMatchObject({ UserStatus: "EXTERNAL_PROVIDER", Password: "" });

      const exported = await exportSeed(TestContext, services);
      expect(exported.$comment).toContain("Passwords are not exported");
      expect(JSON.stringify(exported)).not.toContain("Passw0rdAdmin");

      const fresh = fs.mkdtempSync(
        path.join(os.tmpdir(), "cognito-local-seed-"),
      );
      try {
        const freshServices = await servicesFor(fresh);
        const roundTrip = JSON.parse(JSON.stringify(exported));
        await applySeed(TestContext, freshServices, roundTrip);
        const again = await exportSeed(TestContext, freshServices);
        expect(withoutComment(again)).toEqual(withoutComment(exported));

        const reapplied = await applySeed(
          TestContext,
          freshServices,
          roundTrip,
        );
        expect(reapplied.changes.every((c) => c.action === "unchanged")).toBe(
          true,
        );
      } finally {
        fs.rmSync(fresh, { recursive: true, force: true });
      }
    });

    it("exports a developer-only attribute under its schema name", async () => {
      await applySeed(TestContext, services, {
        UserPools: [
          {
            Id: "local_DevAttr",
            PoolName: "dev-attr",
            Schema: [
              {
                Name: "tier",
                AttributeDataType: "String",
                DeveloperOnlyAttribute: true,
              },
            ],
          },
        ],
      });
      const pool = await services.cognito.getUserPool(
        TestContext,
        "local_DevAttr",
      );
      expect(pool.options.SchemaAttributes?.map((a) => a.Name)).toContain(
        "dev:custom:tier",
      );

      const exported = await exportSeed(TestContext, services);
      const schema = exported.UserPools?.find(
        (p) => p.Id === "local_DevAttr",
      )?.Schema;
      expect(schema).toEqual([
        expect.objectContaining({ Name: "tier", DeveloperOnlyAttribute: true }),
      ]);
    });
  });

  describe("admin API", () => {
    const app = () =>
      createServer(
        () => () => Promise.reject(new Error("unused")),
        MockLogger as never,
        {},
        services,
      ).application;

    it("applies a seed and exports it", async () => {
      const seed = basic();
      const applied = await request(app())
        .post("/_admin/api/seed?source=test.json")
        .send(seed)
        .expect(200);
      expect(applied.body.summary).toEqual({
        created: 9,
        updated: 0,
        unchanged: 0,
      });
      expect(applied.body.lines[0]).toBe("created UserPool local_Example1");

      const exported = await request(app())
        .get("/_admin/api/export?download=1")
        .expect(200);
      expect(exported.header["content-disposition"]).toContain(
        "cognito-local.seed.json",
      );
      expect(exported.body.UserPools[0].Id).toBe("local_Example1");

      const status = await request(app()).get("/_admin/api/status").expect(200);
      expect(status.body).toMatchObject({ running: true, pools: 1 });
    });

    it("returns validation issues as 400", async () => {
      const res = await request(app())
        .post("/_admin/api/seed")
        .send({ UserPools: [{}] })
        .expect(400);
      expect(res.body.issues).toEqual([
        { path: "UserPools[0].PoolName", message: "is required" },
      ]);
    });

    it("links the export from the pools page", async () => {
      const res = await request(app()).get("/_admin").expect(200);
      expect(res.text).toContain('href="/_admin/api/export?download=1"');
      expect(res.text).toContain("Export as seed");
    });
  });

  describe("file triggers wired through the seed", () => {
    it("signs in with CUSTOM_AUTH using the example OTP triggers", async () => {
      await applySeed(
        TestContext,
        services,
        loadSeedFile(path.join(EXAMPLES, "seed.custom-auth-otp.json")),
      );
      const started = await router("InitiateAuth")(TestContext, {
        AuthFlow: "CUSTOM_AUTH",
        ClientId: "otpexampleclient0000000001",
        AuthParameters: { USERNAME: "alice@example.test" },
      });
      expect(started.ChallengeName).toBe("CUSTOM_CHALLENGE");
      expect(started.ChallengeParameters.email).toBe("alice@example.test");

      const wrong = await router("RespondToAuthChallenge")(TestContext, {
        ChallengeName: "CUSTOM_CHALLENGE",
        ClientId: "otpexampleclient0000000001",
        Session: started.Session,
        ChallengeResponses: {
          USERNAME: "alice@example.test",
          ANSWER: "000000x",
        },
      });
      expect(wrong.ChallengeName).toBe("CUSTOM_CHALLENGE");

      const [session] = services.authSessions.list();
      const code = session.session.pendingChallenge.privateChallengeParameters
        ?.answer as string;
      expect(code).toMatch(/^\d{6}$/);
      expect(services.codeLog?.list().map((e) => e.type)).toContain(
        "CUSTOM_AUTH",
      );

      const done = await router("RespondToAuthChallenge")(TestContext, {
        ChallengeName: "CUSTOM_CHALLENGE",
        ClientId: "otpexampleclient0000000001",
        Session: wrong.Session,
        ChallengeResponses: { USERNAME: "alice@example.test", ANSWER: code },
      });
      expect(done.AuthenticationResult.IdToken).toEqual(expect.any(String));
    });
  });
});
