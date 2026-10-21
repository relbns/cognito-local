import { afterEach, describe, expect, it, vi } from "vitest";
import {
  newMockDataStore,
  newMockDataStoreFactory,
} from "../__tests__/mockDataStore";
import { TestContext } from "../__tests__/testContext";
import { DefaultConfig, loadConfig } from "./config";

describe("loadConfig", () => {
  it("returns the default config if no config exists", async () => {
    const config = await loadConfig(TestContext, newMockDataStoreFactory());

    expect(config).toEqual(DefaultConfig);
  });

  it("merges the defaults with any existing config", async () => {
    const ds = newMockDataStore();
    const mockDataStoreFactory = newMockDataStoreFactory(ds);

    ds.getRoot.mockResolvedValue({
      TriggerFunctions: {
        CustomMessage: "custom-config",
      },
      UserPoolDefaults: {
        MFAOptions: "OPTIONAL",
      },
    });

    const config = await loadConfig(TestContext, mockDataStoreFactory);

    expect(config).toEqual({
      ...DefaultConfig,
      TriggerFunctions: {
        CustomMessage: "custom-config",
      },
      UserPoolDefaults: {
        // new field
        MFAOptions: "OPTIONAL",
        // field from defaults
        UsernameAttributes: ["email"],
      },
    });
  });

  it("can unset a property when merging", async () => {
    const ds = newMockDataStore();
    const mockDataStoreFactory = newMockDataStoreFactory(ds);

    ds.getRoot.mockResolvedValue({
      UserPoolDefaults: {
        UsernameAttributes: null,
      },
    });

    const config = await loadConfig(TestContext, mockDataStoreFactory);

    expect(config).toEqual({
      ...DefaultConfig,
      UserPoolDefaults: {
        UsernameAttributes: null,
      },
    });
  });

  it("keeps a null credentials or region so the SDK default chains apply", async () => {
    const ds = newMockDataStore();
    ds.getRoot.mockResolvedValue({
      LambdaClient: { credentials: null },
      KMSConfig: { credentials: null, region: null },
    });

    const config = await loadConfig(TestContext, newMockDataStoreFactory(ds));

    expect(config.LambdaClient).toEqual({ credentials: null, region: "local" });
    expect(config.KMSConfig).toEqual({ credentials: null, region: null });
  });

  it("overwrites arrays when merging", async () => {
    const ds = newMockDataStore();
    const mockDataStoreFactory = newMockDataStoreFactory(ds);

    ds.getRoot.mockResolvedValue({
      UserPoolDefaults: {
        UsernameAttributes: ["phone_number"],
      },
    });

    const config = await loadConfig(TestContext, mockDataStoreFactory);

    expect(config).toEqual({
      ...DefaultConfig,
      UserPoolDefaults: {
        UsernameAttributes: ["phone_number"],
      },
    });
  });

  it("can set an arrays to empty when merging", async () => {
    const ds = newMockDataStore();
    const mockDataStoreFactory = newMockDataStoreFactory(ds);

    ds.getRoot.mockResolvedValue({
      UserPoolDefaults: {
        UsernameAttributes: [],
      },
    });

    const config = await loadConfig(TestContext, mockDataStoreFactory);

    expect(config).toEqual({
      ...DefaultConfig,
      UserPoolDefaults: {
        UsernameAttributes: [],
      },
    });
  });

  it("applies command line overrides and derives the issuer from them", async () => {
    const config = await loadConfig(TestContext, newMockDataStoreFactory(), {
      port: 9330,
      hostname: "127.0.0.1",
      adminUi: false,
    });

    expect(config.ServerConfig).toMatchObject({
      port: 9330,
      hostname: "127.0.0.1",
    });
    expect(config.AdminUIConfig.Enabled).toBe(false);
    expect(config.TokenConfig.IssuerDomain).toBe("http://127.0.0.1:9330");
  });

  it.each(["0.0.0.0", "::"])(
    "maps a wildcard --host %s to localhost in the issuer",
    async (host) => {
      const config = await loadConfig(TestContext, newMockDataStoreFactory(), {
        port: 9330,
        hostname: host,
      });

      expect(config.ServerConfig.hostname).toBe(host);
      expect(config.TokenConfig.IssuerDomain).toBe("http://localhost:9330");
    },
  );

  it("keeps an issuer set in the config file", async () => {
    const ds = newMockDataStore();
    ds.getRoot.mockResolvedValue({
      TokenConfig: { IssuerDomain: "https://issuer.example.test" },
    });

    const config = await loadConfig(TestContext, newMockDataStoreFactory(ds), {
      port: 9330,
    });

    expect(config.TokenConfig.IssuerDomain).toBe("https://issuer.example.test");
  });
});

describe("DefaultConfig", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
    vi.resetModules();
  });

  it.each([
    ["0.0.0.0", "http://localhost:9300"],
    ["::", "http://localhost:9300"],
    ["cognito", "http://cognito:9300"],
  ])("derives the issuer for HOST=%s", async (host, issuer) => {
    vi.stubEnv("HOST", host);
    vi.stubEnv("PORT", "9300");
    vi.resetModules();
    const { DefaultConfig: config } = await import("./config");

    expect(config.ServerConfig.hostname).toBe(host);
    expect(config.TokenConfig.IssuerDomain).toBe(issuer);
  });

  it("validates requests unless COGNITO_LOCAL_VALIDATION turns it off", async () => {
    expect(DefaultConfig.ValidationConfig.Enabled).toBe(true);

    vi.stubEnv("COGNITO_LOCAL_VALIDATION", "off");
    vi.resetModules();
    const { DefaultConfig: config } = await import("./config");

    expect(config.ValidationConfig.Enabled).toBe(false);
  });
  it("keeps federation on the mock IdP by default and reads per-provider modes", async () => {
    expect(DefaultConfig.FederationConfig).toEqual({
      Mode: "mock",
      Providers: {},
    });
    const ds = newMockDataStore();
    ds.getRoot.mockResolvedValue({
      FederationConfig: {
        Mode: "real",
        Providers: { CorpIdP: { Mode: "mock" } },
      },
    });
    const config = await loadConfig(TestContext, newMockDataStoreFactory(ds));
    expect(config.FederationConfig).toEqual({
      Mode: "real",
      Providers: { CorpIdP: { Mode: "mock" } },
    });
  });

  it("reads MockAccounts and MockView, globally and per provider", async () => {
    const FederationConfig = {
      MockAccounts: [{ email: "everyone@example.test" }],
      MockView: "developer",
      Providers: {
        Google: {
          MockView: "signin",
          MockAccounts: [
            {
              email: "jane@example.test",
              name: "Jane Doe",
              sub: "100000000000000000001",
              claims: { locale: "en" },
            },
          ],
        },
      },
    };
    const ds = newMockDataStore();
    ds.getRoot.mockResolvedValue({ FederationConfig });
    const config = await loadConfig(TestContext, newMockDataStoreFactory(ds));
    expect(config.FederationConfig).toEqual({
      Mode: "mock",
      ...FederationConfig,
    });
  });

  it.each([
    [
      { Mode: "live" },
      'FederationConfig.Mode must be "mock" or "real", got "live"',
    ],
    [
      { Providers: { CorpIdP: { Mode: "REAL" } } },
      'FederationConfig.Providers.CorpIdP.Mode must be "mock" or "real", got "REAL"',
    ],
    [
      { MockView: "pretty" },
      'FederationConfig.MockView must be "signin" or "developer", got "pretty"',
    ],
    [
      { Providers: { Google: { MockView: "dev" } } },
      'FederationConfig.Providers.Google.MockView must be "signin" or "developer", got "dev"',
    ],
    [
      { MockAccounts: { email: "a@example.test" } },
      "FederationConfig.MockAccounts must be a list of accounts",
    ],
    [
      { MockAccounts: ["a@example.test"] },
      "FederationConfig.MockAccounts[0] must be an object with an email",
    ],
    [
      { Providers: { Google: { MockAccounts: [{ email: "nobody" }] } } },
      'FederationConfig.Providers.Google.MockAccounts[0].email must be an email address, got "nobody"',
    ],
    [
      { MockAccounts: [{ email: "a@example.test", Name: "A" }] },
      "FederationConfig.MockAccounts[0].Name is not a mock account key (email, name, sub, claims)",
    ],
    [
      {
        MockAccounts: [
          { email: "a@example.test" },
          { email: "A@example.test" },
        ],
      },
      'FederationConfig.MockAccounts[1].email "A@example.test" is listed twice',
    ],
    [
      { MockAccounts: [{ email: "a@example.test", sub: "" }] },
      "FederationConfig.MockAccounts[0].sub must be a non-empty string",
    ],
    [
      { MockAccounts: [{ email: "a@example.test", name: 7 }] },
      "FederationConfig.MockAccounts[0].name must be a string",
    ],
    [
      { MockAccounts: [{ email: "a@example.test", claims: { age: 30 } }] },
      "FederationConfig.MockAccounts[0].claims.age must be a string",
    ],
  ])("rejects the federation config %j", async (FederationConfig, message) => {
    const ds = newMockDataStore();
    ds.getRoot.mockResolvedValue({ FederationConfig });
    await expect(
      loadConfig(TestContext, newMockDataStoreFactory(ds)),
    ).rejects.toThrow(message);
  });
});
