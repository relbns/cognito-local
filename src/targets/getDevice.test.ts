import jwt from "jsonwebtoken";
import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { newDecodingTokenVerifier } from "../__tests__/mockTokenVerifier";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { ResourceNotFoundError } from "../errors";
import PrivateKey from "../keys/cognitoLocal.private.json";
import type { UserPoolService } from "../services";
import { GetDevice, type GetDeviceTarget } from "./getDevice";

const validToken = jwt.sign(
  {
    sub: "user-sub",
    client_id: "testClient",
    token_use: "access",
    username: "testuser",
  },
  PrivateKey.pem,
  { algorithm: "RS256", keyid: "CognitoLocal" },
);

const now = new Date();

describe("GetDevice target", () => {
  let getDevice: GetDeviceTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService({ Id: "test-pool" });
    getDevice = GetDevice({
      tokenVerifier: newDecodingTokenVerifier(mockUserPoolService),
    });
  });

  it("returns the device", async () => {
    const existingUser = TDB.user({ Username: "user-sub" });
    existingUser.Devices = [
      {
        DeviceKey: "device-key-1",
        DeviceAttributes: [{ Name: "device_name", Value: "My Phone" }],
        DeviceCreateDate: now,
        DeviceLastModifiedDate: now,
        DeviceLastAuthenticatedDate: now,
      },
    ];
    mockUserPoolService.getUserByUsername.mockResolvedValue(existingUser);

    const result = await getDevice(TestContext, {
      AccessToken: validToken,
      DeviceKey: "device-key-1",
    });

    expect(result.Device).toEqual({
      DeviceKey: "device-key-1",
      DeviceAttributes: [{ Name: "device_name", Value: "My Phone" }],
      DeviceCreateDate: now,
      DeviceLastModifiedDate: now,
      DeviceLastAuthenticatedDate: now,
    });
  });

  it("hides a key that was issued but never confirmed, and the stored verifier", async () => {
    const existingUser = TDB.user({ Username: "user-sub" });
    existingUser.Devices = [
      { DeviceKey: "pending", DeviceGroupKey: "-group", Confirmed: false },
      {
        DeviceKey: "confirmed",
        DeviceGroupKey: "-group",
        DeviceSecretVerifierConfig: { PasswordVerifier: "AA==", Salt: "AA==" },
        Confirmed: true,
      },
    ];
    mockUserPoolService.getUserByUsername.mockResolvedValue(existingUser);

    await expect(
      getDevice(TestContext, { AccessToken: validToken, DeviceKey: "pending" }),
    ).rejects.toEqual(new ResourceNotFoundError("Device does not exist."));
    const result = await getDevice(TestContext, {
      AccessToken: validToken,
      DeviceKey: "confirmed",
    });
    expect(Object.keys(result.Device ?? {}).sort()).toEqual([
      "DeviceAttributes",
      "DeviceCreateDate",
      "DeviceKey",
      "DeviceLastAuthenticatedDate",
      "DeviceLastModifiedDate",
    ]);
  });

  it("throws if device not found", async () => {
    const existingUser = TDB.user({ Username: "user-sub" });
    existingUser.Devices = [];
    mockUserPoolService.getUserByUsername.mockResolvedValue(existingUser);

    await expect(
      getDevice(TestContext, {
        AccessToken: validToken,
        DeviceKey: "nonexistent-device",
      }),
    ).rejects.toEqual(new ResourceNotFoundError("Device does not exist."));
  });
});
