import jwt from "jsonwebtoken";
import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newDecodingTokenVerifier } from "../__tests__/mockTokenVerifier";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { InvalidParameterError, ResourceNotFoundError } from "../errors";
import PrivateKey from "../keys/cognitoLocal.private.json";
import type { UserPoolService } from "../services";
import { issueDevice } from "../services/devices";
import { ConfirmDevice, type ConfirmDeviceTarget } from "./confirmDevice";

const currentDate = new Date();

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

const verifier = { PasswordVerifier: "dmVyaWZpZXI=", Salt: "c2FsdA==" };

describe("ConfirmDevice target", () => {
  let confirmDevice: ConfirmDeviceTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;

  const setUp = (
    DeviceConfiguration?: UserPoolService["options"]["DeviceConfiguration"],
  ) => {
    mockUserPoolService = newMockUserPoolService({
      Id: "local_pool",
      DeviceConfiguration,
    });
    confirmDevice = ConfirmDevice({
      tokenVerifier: newDecodingTokenVerifier(mockUserPoolService),
      clock: new ClockFake(currentDate),
    });
    const { user, metadata } = issueDevice(
      "local_pool",
      TDB.user({ Username: "user-sub" }),
      currentDate,
    );
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);
    return metadata;
  };

  beforeEach(() => {
    setUp({ ChallengeRequiredOnNewDevice: true });
  });

  it("confirms an issued device key, stores its verifier and remembers it", async () => {
    const metadata = setUp({
      ChallengeRequiredOnNewDevice: true,
      DeviceOnlyRememberedOnUserPrompt: false,
    });

    const result = await confirmDevice(TestContext, {
      AccessToken: validToken,
      DeviceKey: metadata.DeviceKey,
      DeviceName: "My Phone",
      DeviceSecretVerifierConfig: verifier,
    });

    expect(result.UserConfirmationNecessary).toBe(false);
    expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(
      TestContext,
      expect.objectContaining({
        Devices: [
          {
            DeviceKey: metadata.DeviceKey,
            DeviceGroupKey: metadata.DeviceGroupKey,
            DeviceAttributes: [
              { Name: "device_status", Value: "valid" },
              { Name: "device_name", Value: "My Phone" },
              { Name: "dev:device_remembered_status", Value: "remembered" },
            ],
            DeviceSecretVerifierConfig: verifier,
            DeviceCreateDate: currentDate,
            DeviceLastModifiedDate: currentDate,
            DeviceLastAuthenticatedDate: currentDate,
            Confirmed: true,
          },
        ],
      }),
    );
  });

  it("asks for the user's confirmation when the pool remembers devices only on prompt", async () => {
    const metadata = setUp({ DeviceOnlyRememberedOnUserPrompt: true });

    const result = await confirmDevice(TestContext, {
      AccessToken: validToken,
      DeviceKey: metadata.DeviceKey,
      DeviceSecretVerifierConfig: verifier,
    });

    expect(result.UserConfirmationNecessary).toBe(true);
    expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(
      TestContext,
      expect.objectContaining({
        Devices: [
          expect.objectContaining({
            DeviceAttributes: expect.arrayContaining([
              { Name: "dev:device_remembered_status", Value: "not_remembered" },
            ]),
          }),
        ],
      }),
    );
  });

  it("refuses a device key that was never issued to the user", async () => {
    await expect(
      confirmDevice(TestContext, {
        AccessToken: validToken,
        DeviceKey: "local_00000000-0000-0000-0000-000000000000",
        DeviceSecretVerifierConfig: verifier,
      }),
    ).rejects.toEqual(new ResourceNotFoundError("Device does not exist."));
  });

  it("refuses a verifier that is not base64", async () => {
    const metadata = setUp({ ChallengeRequiredOnNewDevice: true });

    await expect(
      confirmDevice(TestContext, {
        AccessToken: validToken,
        DeviceKey: metadata.DeviceKey,
        DeviceSecretVerifierConfig: {
          PasswordVerifier: "not base64!",
          Salt: "c2FsdA==",
        },
      }),
    ).rejects.toBeInstanceOf(InvalidParameterError);
  });
});
