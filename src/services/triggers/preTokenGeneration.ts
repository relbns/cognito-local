import type { Lambda } from "../lambda";
import type { Attribute } from "../sdkTypes";
import type {
  GroupConfiguration,
  PreTokenGenerationResponse,
  PreTokenGenerationVersion,
} from "../tokenCustomization";
import { attributesToRecord } from "../userPoolService";
import type { Trigger } from "./trigger";

export type Source =
  | "AuthenticateDevice"
  | "Authentication"
  | "ClientCredentials"
  | "HostedAuth"
  | "NewPasswordChallenge"
  | "RefreshTokens";

export type PreTokenGenerationTrigger = Trigger<
  {
    clientId: string;
    userAttributes: Attribute[];
    username: string;
    userPoolId: string;

    /**
     * One or more key-value pairs that you can provide as custom input to the Lambda function that you specify for the
     * pre token generation trigger. You can pass this data to your Lambda function by using the ClientMetadata
     * parameter in the AdminRespondToAuthChallenge and RespondToAuthChallenge API actions.
     *
     * Source: https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-pre-token-generation.html#cognito-user-pools-lambda-trigger-syntax-pre-token-generation
     */
    clientMetadata: Record<string, string> | undefined;

    source: Source;

    /** The event version from LambdaConfig.PreTokenGenerationConfig.LambdaVersion. */
    version: PreTokenGenerationVersion;

    /** The user's groups and their IAM roles; null for client credentials. */
    groupConfiguration: GroupConfiguration | null;

    /** The scopes of the access token, sent from event version 2. */
    scopes: readonly string[];
  },
  PreTokenGenerationResponse
>;

type PreTokenGenerationServices = {
  lambda: Lambda;
};

export const PreTokenGeneration =
  ({ lambda }: PreTokenGenerationServices): PreTokenGenerationTrigger =>
  async (
    ctx,
    {
      clientId,
      clientMetadata,
      groupConfiguration,
      scopes,
      source,
      userAttributes,
      username,
      userPoolId,
      version,
    },
  ) =>
    lambda.invoke(ctx, "PreTokenGeneration", {
      clientId,
      clientMetadata,
      groupConfiguration,
      scopes,
      triggerSource: `TokenGeneration_${source}`,
      userAttributes: attributesToRecord(userAttributes),
      username,
      userPoolId,
      version,
    });
