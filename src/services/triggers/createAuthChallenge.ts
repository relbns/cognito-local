import type { CreateAuthChallengeTriggerEvent } from "aws-lambda";
import type { Lambda } from "../lambda";
import type { Attribute } from "../sdkTypes";
import { attributesToRecord } from "../userPoolService";
import type { Trigger } from "./trigger";

export type CreateAuthChallengeTriggerResponse =
  CreateAuthChallengeTriggerEvent["response"];

export type CreateAuthChallengeTrigger = Trigger<
  {
    clientId: string;
    userAttributes: Attribute[];
    username: string;
    userPoolId: string;
    challengeName: string;
    session: Array<{
      challengeName: string;
      challengeResult: boolean;
      challengeMetadata?: string;
    }>;
    clientMetadata?: Record<string, string>;
    userNotFound?: boolean;
  },
  CreateAuthChallengeTriggerResponse
>;

type CreateAuthChallengeServices = {
  lambda: Lambda;
};

export const CreateAuthChallenge =
  ({ lambda }: CreateAuthChallengeServices): CreateAuthChallengeTrigger =>
  async (
    ctx,
    {
      clientId,
      userAttributes,
      username,
      userPoolId,
      challengeName,
      session,
      clientMetadata,
      userNotFound,
    },
  ) =>
    lambda.invoke(ctx, "CreateAuthChallenge", {
      clientId,
      clientMetadata,
      triggerSource: "CreateAuthChallenge_Authentication",
      userAttributes: attributesToRecord(userAttributes),
      username,
      userPoolId,
      challengeName,
      session,
      userNotFound,
    });
