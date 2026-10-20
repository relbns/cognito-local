import { describe, expect, it } from "vitest";
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
