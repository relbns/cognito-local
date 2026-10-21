import type { AppClient } from "../appClient";
import type { Context } from "../context";
import type { Lambda } from "../lambda";
import type { Attribute } from "../sdkTypes";
import { attributesToRecord, type User } from "../userPoolService";
import type { Trigger } from "./trigger";
import type { Triggers } from "./triggers";

export type PreAuthenticationTrigger = Trigger<
  {
    clientId: string;
    source: "PreAuthentication_Authentication";
    userAttributes: Attribute[];
    username: string;
    userPoolId: string;

    /**
     * Set only when the app client has PreventUserExistenceErrors ENABLED.
     *
     * Source: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-authentication.html
     */
    userNotFound: boolean | undefined;

    /**
     * The ClientMetadata of the InitiateAuth or AdminInitiateAuth request.
     *
     * Source: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-authentication.html
     */
    validationData: Record<string, string> | undefined;
  },
  void
>;

type PreAuthenticationServices = {
  lambda: Lambda;
};

export const PreAuthentication =
  ({ lambda }: PreAuthenticationServices): PreAuthenticationTrigger =>
  async (
    ctx,
    {
      clientId,
      source,
      userAttributes,
      username,
      userNotFound,
      userPoolId,
      validationData,
    },
  ) => {
    await lambda.invoke(ctx, "PreAuthentication", {
      clientId,
      triggerSource: source,
      userAttributes: attributesToRecord(userAttributes),
      userNotFound,
      username,
      userPoolId,
      validationData,
    });
  };

/**
 * Runs PreAuthentication before a sign-in is checked. An unknown user only triggers it when the client
 * has PreventUserExistenceErrors ENABLED; a thrown error rejects the sign-in.
 */
export const runPreAuthentication = async (
  ctx: Context,
  triggers: Triggers,
  {
    client,
    user,
    username,
    userPoolId,
    validationData,
  }: {
    client: AppClient | null | undefined;
    user: User | null | undefined;
    username: string;
    userPoolId: string;
    validationData: Record<string, string> | undefined;
  },
): Promise<void> => {
  if (!client || !triggers.enabled("PreAuthentication", userPoolId)) return;
  const preventsUserExistenceErrors =
    client.PreventUserExistenceErrors === "ENABLED";
  if (!user && !preventsUserExistenceErrors) return;

  await triggers.preAuthentication(ctx, {
    clientId: client.ClientId,
    source: "PreAuthentication_Authentication",
    userAttributes: user?.Attributes ?? [],
    username: user?.Username ?? username,
    userNotFound: preventsUserExistenceErrors ? !user : undefined,
    userPoolId,
    validationData,
  });
};
