import jwt from "jsonwebtoken";
import { beforeEach, describe, expect, it, type MockedObject } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newDecodingTokenVerifier } from "../__tests__/mockTokenVerifier";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import { NotAuthorizedError, UserNotFoundError } from "../errors";
import PrivateKey from "../keys/cognitoLocal.private.json";
import type { UserPoolService } from "../services";
import { SetUserSettings, type SetUserSettingsTarget } from "./setUserSettings";

const currentDate = new Date();

describe("SetUserSettings target", () => {
  let setUserSettings: SetUserSettingsTarget;
  let mockUserPoolService: MockedObject<UserPoolService>;

  const user = TDB.user({ Username: "testuser" });
  const validToken = jwt.sign(
    {
      sub: user.Username,
      client_id: "test",
      token_use: "access",
      username: user.Username,
    },
    PrivateKey.pem,
    { algorithm: "RS256", keyid: "CognitoLocal" },
  );

  beforeEach(() => {
    mockUserPoolService = newMockUserPoolService();
    setUserSettings = SetUserSettings({
      tokenVerifier: newDecodingTokenVerifier(mockUserPoolService),
      clock: new ClockFake(currentDate),
    });
  });

  it("sets MFA options on user", async () => {
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    const mfaOptions = [
      { DeliveryMedium: "SMS" as const, AttributeName: "phone_number" },
    ];

    const result = await setUserSettings(TestContext, {
      AccessToken: validToken,
      MFAOptions: mfaOptions,
    });

    expect(result).toEqual({});
    expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(TestContext, {
      ...user,
      MFAOptions: mfaOptions,
      UserMFASettingList: ["SMS_MFA"],
      UserLastModifiedDate: currentDate,
    });
  });

  it("clears MFA settings when no MFAOptions provided", async () => {
    mockUserPoolService.getUserByUsername.mockResolvedValue(user);

    await setUserSettings(TestContext, {
      AccessToken: validToken,
      MFAOptions: [],
    });

    expect(mockUserPoolService.saveUser).toHaveBeenCalledWith(TestContext, {
      ...user,
      MFAOptions: [],
      UserMFASettingList: [],
      UserLastModifiedDate: currentDate,
    });
  });

  it("throws if token is invalid", async () => {
    await expect(
      setUserSettings(TestContext, {
        AccessToken: "invalid",
        MFAOptions: [],
      }),
    ).rejects.toEqual(new NotAuthorizedError("Invalid Access Token"));
  });

  it("throws if user not found", async () => {
    mockUserPoolService.getUserByUsername.mockResolvedValue(null);

    await expect(
      setUserSettings(TestContext, {
        AccessToken: validToken,
        MFAOptions: [],
      }),
    ).rejects.toEqual(new UserNotFoundError("User does not exist."));
  });
});
