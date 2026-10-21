import { describe, expect, it } from "vitest";
import * as TDB from "../__tests__/testDataBuilder";
import { InvalidParameterError, ResourceNotFoundError } from "../errors";
import {
  confirmedDevices,
  confirmIssuedDevice,
  deviceTrackingEnabled,
  isRemembered,
  issueDevice,
  toDeviceType,
  withoutDevice,
  withRememberedStatus,
} from "./devices";

const now = new Date("2026-10-21T09:00:00Z");
const later = new Date("2026-10-21T10:00:00Z");
const verifier = { PasswordVerifier: "dmVyaWZpZXI=", Salt: "c2FsdA==" };

describe("devices", () => {
  it("turns device tracking on when any DeviceConfiguration property is set", () => {
    expect(deviceTrackingEnabled({})).toBe(false);
    expect(deviceTrackingEnabled({ DeviceConfiguration: {} })).toBe(false);
    expect(
      deviceTrackingEnabled({
        DeviceConfiguration: { ChallengeRequiredOnNewDevice: false },
      }),
    ).toBe(true);
    expect(
      deviceTrackingEnabled({
        DeviceConfiguration: { DeviceOnlyRememberedOnUserPrompt: true },
      }),
    ).toBe(true);
  });

  it("issues region-prefixed device keys that share the user's device group", () => {
    const first = issueDevice("eu-west-1_pool", TDB.user(), now);
    const second = issueDevice("eu-west-1_pool", first.user, now);

    expect(first.metadata.DeviceKey).toMatch(
      /^eu-west-1_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/,
    );
    expect(second.metadata.DeviceGroupKey).toEqual(
      first.metadata.DeviceGroupKey,
    );
    expect(second.metadata.DeviceKey).not.toEqual(first.metadata.DeviceKey);
    expect(confirmedDevices(second.user)).toEqual([]);
  });

  it("confirms an issued device with Cognito's device attributes", () => {
    const { user, metadata } = issueDevice("local_pool", TDB.user(), now);
    const confirmed = confirmIssuedDevice(user, {
      deviceKey: metadata.DeviceKey,
      deviceName: "Laptop",
      verifier,
      rememberOnConfirm: true,
      now: later,
    });
    const [device] = confirmedDevices(confirmed);

    expect(isRemembered(device)).toBe(true);
    expect(toDeviceType(device)).toEqual({
      DeviceKey: metadata.DeviceKey,
      DeviceAttributes: [
        { Name: "device_status", Value: "valid" },
        { Name: "device_name", Value: "Laptop" },
        { Name: "dev:device_remembered_status", Value: "remembered" },
      ],
      DeviceCreateDate: now,
      DeviceLastModifiedDate: later,
      DeviceLastAuthenticatedDate: now,
    });
  });

  it("refuses to confirm an unknown key or a verifier that is not base64", () => {
    const { user, metadata } = issueDevice("local_pool", TDB.user(), now);
    expect(() =>
      confirmIssuedDevice(user, {
        deviceKey: "local_unknown",
        rememberOnConfirm: true,
        now,
      }),
    ).toThrow(new ResourceNotFoundError("Device does not exist."));
    expect(() =>
      confirmIssuedDevice(user, {
        deviceKey: metadata.DeviceKey,
        verifier: { PasswordVerifier: "%%%", Salt: "c2FsdA==" },
        rememberOnConfirm: true,
        now,
      }),
    ).toThrow(InvalidParameterError);
  });

  it("changes the remembered status and forgets confirmed devices only", () => {
    const { user, metadata } = issueDevice("local_pool", TDB.user(), now);
    expect(() =>
      withRememberedStatus(user, metadata.DeviceKey, "remembered", later),
    ).toThrow(new ResourceNotFoundError("Device does not exist."));

    const confirmed = confirmIssuedDevice(user, {
      deviceKey: metadata.DeviceKey,
      verifier,
      rememberOnConfirm: false,
      now,
    });
    expect(isRemembered(confirmedDevices(confirmed)[0])).toBe(false);

    const remembered = withRememberedStatus(
      confirmed,
      metadata.DeviceKey,
      "remembered",
      later,
    );
    expect(isRemembered(confirmedDevices(remembered)[0])).toBe(true);
    expect(confirmedDevices(remembered)[0].DeviceLastModifiedDate).toEqual(
      later,
    );

    expect(
      confirmedDevices(withoutDevice(remembered, metadata.DeviceKey)),
    ).toEqual([]);
  });
});
