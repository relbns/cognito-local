import * as crypto from "node:crypto";
import type {
  DeviceRememberedStatusType,
  DeviceType,
} from "@aws-sdk/client-cognito-identity-provider";
import { v4 } from "uuid";
import { InvalidParameterError, ResourceNotFoundError } from "../errors";
import type { Attribute } from "./sdkTypes";
import type { User, UserPool } from "./userPoolService";

export const DEVICE_NOT_FOUND = "Device does not exist.";
export const REMEMBERED_STATUS_ATTRIBUTE = "dev:device_remembered_status";

export interface DeviceSecretVerifier {
  PasswordVerifier: string;
  Salt: string;
}

export interface UserDevice {
  DeviceKey: string;
  DeviceAttributes?: Attribute[];
  DeviceCreateDate?: Date;
  DeviceLastModifiedDate?: Date;
  DeviceLastAuthenticatedDate?: Date;

  // internal only, never returned by the device operations
  DeviceGroupKey?: string;
  DeviceSecretVerifierConfig?: DeviceSecretVerifier;
  /** False while a key from NewDeviceMetadata waits for ConfirmDevice. */
  Confirmed?: boolean;
}

export interface NewDeviceMetadata {
  DeviceKey: string;
  DeviceGroupKey: string;
}

// Any DeviceConfiguration property turns device remembering on (DeviceConfigurationType).
export const deviceTrackingEnabled = (
  userPool: Pick<UserPool, "DeviceConfiguration">,
): boolean => {
  const config = userPool.DeviceConfiguration;
  return (
    !!config &&
    (config.ChallengeRequiredOnNewDevice !== undefined ||
      config.DeviceOnlyRememberedOnUserPrompt !== undefined)
  );
};

export const userDevices = (user: User): UserDevice[] =>
  (user.Devices ?? []) as UserDevice[];

/** Devices that ConfirmDevice registered; keys only issued in NewDeviceMetadata are left out. */
export const confirmedDevices = (user: User): UserDevice[] =>
  userDevices(user).filter((d) => d.Confirmed !== false);

export const findConfirmedDevice = (
  user: User,
  deviceKey: string,
): UserDevice | undefined =>
  confirmedDevices(user).find((d) => d.DeviceKey === deviceKey);

export const requireConfirmedDevice = (
  user: User,
  deviceKey: string | undefined,
): UserDevice => {
  const device = deviceKey ? findConfirmedDevice(user, deviceKey) : undefined;
  if (!device) {
    throw new ResourceNotFoundError(DEVICE_NOT_FOUND);
  }
  return device;
};

export const deviceAttribute = (
  device: UserDevice,
  name: string,
): string | undefined =>
  device.DeviceAttributes?.find((a) => a.Name === name)?.Value;

export const isRemembered = (device: UserDevice): boolean =>
  deviceAttribute(device, REMEMBERED_STATUS_ATTRIBUTE) === "remembered";

const setAttribute = (
  attributes: Attribute[] | undefined,
  name: string,
  value: string,
): Attribute[] => [
  ...(attributes ?? []).filter((a) => a.Name !== name),
  { Name: name, Value: value },
];

export const toDeviceType = (device: UserDevice): DeviceType => ({
  DeviceKey: device.DeviceKey,
  DeviceAttributes: device.DeviceAttributes ?? [],
  DeviceCreateDate: device.DeviceCreateDate,
  DeviceLastModifiedDate: device.DeviceLastModifiedDate,
  DeviceLastAuthenticatedDate: device.DeviceLastAuthenticatedDate,
});

const regionOf = (userPoolId: string): string =>
  userPoolId.split("_")[0] || "local";

const newDeviceGroupKey = (): string =>
  `-${crypto.randomBytes(7).toString("base64url").slice(0, 9)}`;

/** Issues a device key for NewDeviceMetadata and records it as unconfirmed on the user. */
export const issueDevice = (
  userPoolId: string,
  user: User,
  now: Date,
): { user: User; metadata: NewDeviceMetadata } => {
  const existingGroup = userDevices(user).find(
    (d) => d.DeviceGroupKey,
  )?.DeviceGroupKey;
  const metadata = {
    DeviceKey: `${regionOf(userPoolId)}_${v4()}`,
    DeviceGroupKey: existingGroup ?? newDeviceGroupKey(),
  };
  const pending: UserDevice = {
    DeviceKey: metadata.DeviceKey,
    DeviceGroupKey: metadata.DeviceGroupKey,
    DeviceCreateDate: now,
    DeviceLastModifiedDate: now,
    DeviceLastAuthenticatedDate: now,
    Confirmed: false,
  };
  return {
    user: { ...user, Devices: [...userDevices(user), pending] },
    metadata,
  };
};

const isBase64 = (value: string) =>
  value.length > 0 && /^[A-Za-z0-9+/]+={0,2}$/.test(value);

export const confirmIssuedDevice = (
  user: User,
  {
    deviceKey,
    deviceName,
    verifier,
    rememberOnConfirm,
    now,
  }: {
    deviceKey: string;
    deviceName?: string;
    verifier?: DeviceSecretVerifier;
    rememberOnConfirm: boolean;
    now: Date;
  },
): User => {
  const device = userDevices(user).find((d) => d.DeviceKey === deviceKey);
  if (!device) {
    throw new ResourceNotFoundError(DEVICE_NOT_FOUND);
  }
  if (
    verifier &&
    (!isBase64(verifier.PasswordVerifier) || !isBase64(verifier.Salt))
  ) {
    throw new InvalidParameterError(
      "DeviceSecretVerifierConfig PasswordVerifier and Salt must be base64",
    );
  }

  let attributes = setAttribute(
    device.DeviceAttributes,
    "device_status",
    "valid",
  );
  if (deviceName) {
    attributes = setAttribute(attributes, "device_name", deviceName);
  }
  attributes = setAttribute(
    attributes,
    REMEMBERED_STATUS_ATTRIBUTE,
    rememberOnConfirm ? "remembered" : "not_remembered",
  );

  const confirmed: UserDevice = {
    ...device,
    DeviceAttributes: attributes,
    DeviceSecretVerifierConfig: verifier ?? device.DeviceSecretVerifierConfig,
    DeviceLastModifiedDate: now,
    Confirmed: true,
  };
  return {
    ...user,
    Devices: userDevices(user).map((d) =>
      d.DeviceKey === deviceKey ? confirmed : d,
    ),
  };
};

export const updateDevice = (
  user: User,
  deviceKey: string,
  update: (device: UserDevice) => UserDevice,
): User => {
  requireConfirmedDevice(user, deviceKey);
  return {
    ...user,
    Devices: userDevices(user).map((d) =>
      d.DeviceKey === deviceKey ? update(d) : d,
    ),
  };
};

export const withRememberedStatus = (
  user: User,
  deviceKey: string,
  status: DeviceRememberedStatusType | undefined,
  now: Date,
): User =>
  updateDevice(user, deviceKey, (device) => ({
    ...device,
    DeviceAttributes: status
      ? setAttribute(
          device.DeviceAttributes,
          REMEMBERED_STATUS_ATTRIBUTE,
          status,
        )
      : device.DeviceAttributes,
    DeviceLastModifiedDate: now,
  }));

export const withoutDevice = (user: User, deviceKey: string): User => {
  requireConfirmedDevice(user, deviceKey);
  return {
    ...user,
    Devices: userDevices(user).filter((d) => d.DeviceKey !== deviceKey),
  };
};
