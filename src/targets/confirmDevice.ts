import type {
  ConfirmDeviceRequest,
  ConfirmDeviceResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import type { Services } from "../services";
import { confirmIssuedDevice } from "../services/devices";
import type { Target } from "./Target";

export type ConfirmDeviceTarget = Target<
  ConfirmDeviceRequest,
  ConfirmDeviceResponse
>;

type ConfirmDeviceServices = Pick<Services, "clock" | "tokenVerifier">;

export const ConfirmDevice =
  ({ clock, tokenVerifier }: ConfirmDeviceServices): ConfirmDeviceTarget =>
  async (ctx, req) => {
    const { user, userPool } = await tokenVerifier.verifyAccessToken(
      ctx,
      req.AccessToken,
    );

    const now = clock.get();
    const rememberOnConfirm =
      userPool.options.DeviceConfiguration?.DeviceOnlyRememberedOnUserPrompt !==
      true;
    const verifier = req.DeviceSecretVerifierConfig;

    await userPool.updateUser(ctx, user, (latest) => ({
      ...confirmIssuedDevice(latest, {
        deviceKey: req.DeviceKey,
        deviceName: req.DeviceName,
        verifier:
          verifier?.PasswordVerifier && verifier.Salt
            ? {
                PasswordVerifier: verifier.PasswordVerifier,
                Salt: verifier.Salt,
              }
            : undefined,
        rememberOnConfirm,
        now,
      }),
      UserLastModifiedDate: now,
    }));

    return {
      UserConfirmationNecessary: !rememberOnConfirm,
    };
  };
