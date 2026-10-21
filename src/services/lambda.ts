import type {
  InvokeCommandOutput,
  Lambda as LambdaSdkClient,
} from "@aws-sdk/client-lambda";
import type {
  CreateAuthChallengeTriggerEvent,
  CustomEmailSenderTriggerEvent,
  CustomMessageTriggerEvent,
  DefineAuthChallengeTriggerEvent,
  PostAuthenticationTriggerEvent,
  PostConfirmationTriggerEvent,
  PreAuthenticationTriggerEvent,
  PreSignUpTriggerEvent,
  PreTokenGenerationTriggerEvent,
  UserMigrationTriggerEvent,
  VerifyAuthChallengeResponseTriggerEvent,
} from "aws-lambda";
import {
  InvalidLambdaResponseError,
  UnexpectedLambdaExceptionError,
  UserLambdaValidationError,
} from "../errors";
import type { Context } from "./context";
import {
  FileTriggerError,
  FileTriggerInvoker,
  isFileTarget,
  parseFileTarget,
} from "./fileTrigger";
import type {
  GroupConfiguration,
  PreTokenGenerationResponse,
  PreTokenGenerationVersion,
} from "./tokenCustomization";

type CognitoUserPoolEvent =
  | CreateAuthChallengeTriggerEvent
  | CustomEmailSenderTriggerEvent
  | CustomMessageTriggerEvent
  | DefineAuthChallengeTriggerEvent
  | PostAuthenticationTriggerEvent
  | PostConfirmationTriggerEvent
  | PreAuthenticationTriggerEvent
  | PreSignUpTriggerEvent
  | PreTokenGenerationLambdaEvent
  | UserMigrationTriggerEvent
  | VerifyAuthChallengeResponseTriggerEvent;

type PreTokenGenerationLambdaEvent = Omit<
  PreTokenGenerationTriggerEvent,
  "triggerSource" | "request" | "response"
> & {
  triggerSource: PreTokenGenerationEvent["triggerSource"];
  request: {
    userAttributes: Record<string, string>;
    groupConfiguration: GroupConfiguration | null;
    clientMetadata: Record<string, string> | undefined;
    scopes?: readonly string[];
  };
  response: PreTokenGenerationResponse;
};

interface EventCommonParameters {
  clientId: string;
  userAttributes: Record<string, string>;
  username: string;
  userPoolId: string;
}

interface CustomEmailSenderEvent
  extends Omit<EventCommonParameters, "clientId"> {
  clientId: string | null;
  code: string;
  clientMetadata: Record<string, string> | undefined;
  triggerSource:
    | "CustomEmailSender_AdminCreateUser"
    | "CustomEmailSender_ForgotPassword"
    | "CustomEmailSender_ResendCode"
    | "CustomEmailSender_SignUp"
    | "CustomEmailSender_UpdateUserAttribute"
    | "CustomEmailSender_VerifyUserAttribute";
}

interface CustomMessageEvent extends Omit<EventCommonParameters, "clientId"> {
  clientId: string | null;
  clientMetadata: Record<string, string> | undefined;
  codeParameter: string;
  triggerSource:
    | "CustomMessage_AdminCreateUser"
    | "CustomMessage_Authentication"
    | "CustomMessage_ForgotPassword"
    | "CustomMessage_ResendCode"
    | "CustomMessage_SignUp"
    | "CustomMessage_UpdateUserAttribute"
    | "CustomMessage_VerifyUserAttribute";
  usernameParameter: string;
}

interface UserMigrationEvent extends EventCommonParameters {
  clientMetadata: Record<string, string> | undefined;
  password: string;
  triggerSource: "UserMigration_Authentication";
  validationData: Record<string, string> | undefined;
}

interface PreSignUpEvent extends EventCommonParameters {
  clientMetadata: Record<string, string> | undefined;
  triggerSource:
    | "PreSignUp_AdminCreateUser"
    | "PreSignUp_ExternalProvider"
    | "PreSignUp_SignUp";
  validationData: Record<string, string> | undefined;
}

interface PreTokenGenerationEvent extends EventCommonParameters {
  /**
   * One or more key-value pairs that you can provide as custom input to the Lambda function that you specify for the
   * pre token generation trigger. You can pass this data to your Lambda function by using the ClientMetadata parameter
   * in the AdminRespondToAuthChallenge and RespondToAuthChallenge API actions.
   */
  clientMetadata: Record<string, string> | undefined;

  triggerSource:
    | "TokenGeneration_AuthenticateDevice"
    | "TokenGeneration_Authentication"
    | "TokenGeneration_ClientCredentials"
    | "TokenGeneration_HostedAuth"
    | "TokenGeneration_NewPasswordChallenge"
    | "TokenGeneration_RefreshTokens";

  groupConfiguration: GroupConfiguration | null;

  /** Sent in event version 2 and later. */
  scopes: readonly string[];

  version: PreTokenGenerationVersion;
}

interface PostAuthenticationEvent extends EventCommonParameters {
  clientMetadata: Record<string, string> | undefined;
  triggerSource: "PostAuthentication_Authentication";
}

interface PostConfirmationEvent
  extends Omit<EventCommonParameters, "clientId"> {
  triggerSource:
    | "PostConfirmation_ConfirmSignUp"
    | "PostConfirmation_ConfirmForgotPassword";
  clientMetadata: Record<string, string> | undefined;
  clientId: string | null;
}

export interface FunctionConfig {
  CreateAuthChallenge?: string;
  CustomEmailSender?: string;
  CustomMessage?: string;
  DefineAuthChallenge?: string;
  PostAuthentication?: string;
  PostConfirmation?: string;
  PreSignUp?: string;
  PreTokenGeneration?: string;
  UserMigration?: string;
  VerifyAuthChallengeResponse?: string;
}

export type DefineAuthChallengeTriggerResponse =
  DefineAuthChallengeTriggerEvent["response"];
export type CreateAuthChallengeTriggerResponse =
  CreateAuthChallengeTriggerEvent["response"];
export type VerifyAuthChallengeResponseTriggerResponse =
  VerifyAuthChallengeResponseTriggerEvent["response"];
export type CustomMessageTriggerResponse =
  CustomMessageTriggerEvent["response"];
export type UserMigrationTriggerResponse =
  UserMigrationTriggerEvent["response"];
export type PreSignUpTriggerResponse = PreSignUpTriggerEvent["response"];
export type PreTokenGenerationTriggerResponse = PreTokenGenerationResponse;
export type PostAuthenticationTriggerResponse =
  PostAuthenticationTriggerEvent["response"];
export type PostConfirmationTriggerResponse =
  PostConfirmationTriggerEvent["response"];
export type CustomEmailSenderTriggerResponse =
  CustomEmailSenderTriggerEvent["response"];

interface DefineAuthChallengeEvent extends EventCommonParameters {
  clientMetadata: Record<string, string> | undefined;
  triggerSource: "DefineAuthChallenge_Authentication";
  session: Array<{
    challengeName: string;
    challengeResult: boolean;
    challengeMetadata?: string;
  }>;
  userNotFound?: boolean;
}

interface CreateAuthChallengeEvent extends EventCommonParameters {
  clientMetadata: Record<string, string> | undefined;
  triggerSource: "CreateAuthChallenge_Authentication";
  challengeName: string;
  session: Array<{
    challengeName: string;
    challengeResult: boolean;
    challengeMetadata?: string;
  }>;
}

interface VerifyAuthChallengeResponseEvent extends EventCommonParameters {
  clientMetadata: Record<string, string> | undefined;
  triggerSource: "VerifyAuthChallengeResponse_Authentication";
  challengeAnswer: string;
  privateChallengeParameters?: Record<string, string>;
}

export type LambdaClient = Pick<LambdaSdkClient, "invoke">;

// The value Cognito itself sends in callerContext.
export const COGNITO_AWS_SDK_VERSION = "aws-sdk-unknown-unknown";

const decodePayload = (payload: Uint8Array | undefined): string =>
  payload ? new TextDecoder().decode(payload) : "";

export type PoolLambdaConfigLookup = (
  userPoolId: string,
) => Record<string, unknown> | undefined;

export interface LambdaServiceOptions {
  /** Returns the LambdaConfig of a user pool; its file: entries take precedence over FunctionConfig. */
  poolLambdaConfig?: PoolLambdaConfigLookup;
  /** Resolves relative file: targets in FunctionConfig. */
  baseDir?: string;
  files?: FileTriggerInvoker;
}

const poolTarget = (
  lambdaConfig: Record<string, unknown> | undefined,
  trigger: keyof FunctionConfig,
): string | undefined => {
  if (!lambdaConfig) return undefined;
  const entry =
    lambdaConfig[trigger] ??
    (trigger === "PreTokenGeneration"
      ? lambdaConfig.PreTokenGenerationConfig
      : undefined);
  const value =
    entry && typeof entry === "object"
      ? (entry as { LambdaArn?: unknown }).LambdaArn
      : entry;
  return isFileTarget(value) ? value : undefined;
};

export interface Lambda {
  enabled(lambda: keyof FunctionConfig, userPoolId?: string): boolean;
  invoke(
    ctx: Context,
    lambda: "DefineAuthChallenge",
    event: DefineAuthChallengeEvent,
  ): Promise<DefineAuthChallengeTriggerResponse>;
  invoke(
    ctx: Context,
    lambda: "CreateAuthChallenge",
    event: CreateAuthChallengeEvent,
  ): Promise<CreateAuthChallengeTriggerResponse>;
  invoke(
    ctx: Context,
    lambda: "VerifyAuthChallengeResponse",
    event: VerifyAuthChallengeResponseEvent,
  ): Promise<VerifyAuthChallengeResponseTriggerResponse>;
  invoke(
    ctx: Context,
    lambda: "CustomMessage",
    event: CustomMessageEvent,
  ): Promise<CustomMessageTriggerResponse>;
  invoke(
    ctx: Context,
    lambda: "UserMigration",
    event: UserMigrationEvent,
  ): Promise<UserMigrationTriggerResponse>;
  invoke(
    ctx: Context,
    lambda: "PreSignUp",
    event: PreSignUpEvent,
  ): Promise<PreSignUpTriggerResponse>;
  invoke(
    ctx: Context,
    lambda: "PreTokenGeneration",
    event: PreTokenGenerationEvent,
  ): Promise<PreTokenGenerationTriggerResponse>;
  invoke(
    ctx: Context,
    lambda: "PostAuthentication",
    event: PostAuthenticationEvent,
  ): Promise<PostAuthenticationTriggerResponse>;
  invoke(
    ctx: Context,
    lambda: "PostConfirmation",
    event: PostConfirmationEvent,
  ): Promise<PostConfirmationTriggerResponse>;
  invoke(
    ctx: Context,
    lambda: "CustomEmailSender",
    event: CustomEmailSenderEvent,
  ): Promise<CustomEmailSenderTriggerResponse>;
}

export class LambdaService implements Lambda {
  private readonly config: FunctionConfig;
  private readonly lambdaClient: LambdaClient;
  private readonly options: LambdaServiceOptions;
  private readonly files: FileTriggerInvoker;

  public constructor(
    config: FunctionConfig,
    lambdaClient: LambdaClient,
    options: LambdaServiceOptions = {},
  ) {
    this.config = config;
    this.lambdaClient = lambdaClient;
    this.options = options;
    this.files = options.files ?? new FileTriggerInvoker();
  }

  private target(
    trigger: keyof FunctionConfig,
    userPoolId: string | undefined,
  ): string | undefined {
    const fromPool = userPoolId
      ? poolTarget(this.options.poolLambdaConfig?.(userPoolId), trigger)
      : undefined;
    return fromPool ?? this.config[trigger];
  }

  public enabled(lambda: keyof FunctionConfig, userPoolId?: string): boolean {
    return !!this.target(lambda, userPoolId);
  }

  public async invoke(
    ctx: Context,
    trigger: keyof FunctionConfig,
    event:
      | CreateAuthChallengeEvent
      | CustomEmailSenderEvent
      | CustomMessageEvent
      | DefineAuthChallengeEvent
      | PostAuthenticationEvent
      | PostConfirmationEvent
      | PreSignUpEvent
      | PreTokenGenerationEvent
      | UserMigrationEvent
      | VerifyAuthChallengeResponseEvent,
  ) {
    const functionName = this.target(trigger, event.userPoolId);
    if (!functionName) {
      throw new Error(`${trigger} trigger not configured`);
    }

    const lambdaEvent = this.createLambdaEvent(event);

    if (isFileTarget(functionName)) {
      return this.invokeFile(ctx, trigger, functionName, lambdaEvent);
    }

    ctx.logger.debug(
      {
        functionName,
        event: JSON.stringify(lambdaEvent, undefined, 2),
      },
      `Invoking "${functionName}" with event`,
    );
    let result: InvokeCommandOutput;
    try {
      result = await this.lambdaClient.invoke({
        FunctionName: functionName,
        InvocationType: "RequestResponse",
        Payload: new TextEncoder().encode(JSON.stringify(lambdaEvent)),
      });
    } catch (ex) {
      ctx.logger.error(ex);
      throw new UnexpectedLambdaExceptionError();
    }

    ctx.logger.debug(
      `Lambda completed with StatusCode=${result.StatusCode} and FunctionError=${result.FunctionError}`,
    );
    const payload = decodePayload(result.Payload);
    if (!result.FunctionError) {
      try {
        const parsedPayload = JSON.parse(payload);

        return parsedPayload.response;
      } catch (err) {
        ctx.logger.error(err);
        throw new InvalidLambdaResponseError();
      }
    } else {
      ctx.logger.error({ result }, result.FunctionError);

      if (result.FunctionError === "Unhandled" && payload) {
        const parsedPayload = JSON.parse(payload);

        if (parsedPayload.errorMessage) {
          throw new UserLambdaValidationError(
            `${trigger} failed with error ${parsedPayload.errorMessage}.`,
          );
        }
      }

      throw new UserLambdaValidationError(result.FunctionError);
    }
  }

  private async invokeFile(
    ctx: Context,
    trigger: keyof FunctionConfig,
    functionName: string,
    lambdaEvent: CognitoUserPoolEvent,
  ) {
    const target = parseFileTarget(functionName, this.options.baseDir);
    ctx.logger.debug(
      { target, event: JSON.stringify(lambdaEvent, undefined, 2) },
      `Invoking local trigger ${target.file}#${target.exportName}`,
    );
    let result: unknown;
    try {
      result = await this.files.invoke(
        target,
        trigger,
        JSON.parse(JSON.stringify(lambdaEvent)),
      );
    } catch (e) {
      ctx.logger.error(e, `Local ${trigger} trigger failed`);
      if (e instanceof FileTriggerError && e.kind === "handler") {
        throw new UserLambdaValidationError(
          `${trigger} failed with error ${e.message}.`,
        );
      }
      if (e instanceof FileTriggerError && e.kind === "timeout") {
        throw new UnexpectedLambdaExceptionError(
          `${trigger} invocation failed due to error ${e.message}.`,
        );
      }
      throw new UnexpectedLambdaExceptionError(
        `${trigger} invocation failed due to error ${(e as Error).message}`,
      );
    }

    let response: unknown;
    try {
      response = JSON.parse(JSON.stringify(result ?? null))?.response;
    } catch {
      response = undefined;
    }
    if (!response || typeof response !== "object") {
      ctx.logger.error(
        { result },
        `Local ${trigger} trigger did not return the event with a response object`,
      );
      throw new InvalidLambdaResponseError();
    }
    return response;
  }

  private createLambdaEvent(
    event:
      | CreateAuthChallengeEvent
      | CustomEmailSenderEvent
      | CustomMessageEvent
      | DefineAuthChallengeEvent
      | PostAuthenticationEvent
      | PostConfirmationEvent
      | PreSignUpEvent
      | PreTokenGenerationEvent
      | UserMigrationEvent
      | VerifyAuthChallengeResponseEvent,
  ): CognitoUserPoolEvent {
    const version = "0"; // TODO: how do we know what this is?
    const callerContext = {
      awsSdkVersion: COGNITO_AWS_SDK_VERSION,

      // client id can be null, even though the types don't allow it
      clientId: event.clientId as string,
    };
    const region = "local"; // TODO: pull from above,

    switch (event.triggerSource) {
      case "PostAuthentication_Authentication": {
        return {
          version,
          callerContext,
          region,
          userPoolId: event.userPoolId,
          triggerSource: event.triggerSource,
          userName: event.username,
          request: {
            userAttributes: event.userAttributes,
            clientMetadata: event.clientMetadata,
            newDeviceUsed: false,
          },
          response: {},
        };
      }

      case "PostConfirmation_ConfirmForgotPassword":
      case "PostConfirmation_ConfirmSignUp": {
        return {
          version,
          callerContext,
          region,
          userPoolId: event.userPoolId,
          triggerSource: event.triggerSource,
          userName: event.username,
          request: {
            userAttributes: event.userAttributes,
            clientMetadata: event.clientMetadata,
          },
          response: {},
        };
      }

      case "PreSignUp_AdminCreateUser":
      case "PreSignUp_ExternalProvider":
      case "PreSignUp_SignUp": {
        return {
          version,
          callerContext,
          region,
          userPoolId: event.userPoolId,
          triggerSource: event.triggerSource,
          userName: event.username,
          request: {
            userAttributes: event.userAttributes,
            clientMetadata: event.clientMetadata,
            validationData: event.validationData,
          },
          response: {
            autoConfirmUser: false,
            autoVerifyEmail: false,
            autoVerifyPhone: false,
          },
        };
      }

      case "TokenGeneration_AuthenticateDevice":
      case "TokenGeneration_Authentication":
      case "TokenGeneration_ClientCredentials":
      case "TokenGeneration_HostedAuth":
      case "TokenGeneration_NewPasswordChallenge":
      case "TokenGeneration_RefreshTokens": {
        const v1 = event.version === "1";
        return {
          version: event.version,
          callerContext,
          region,
          userPoolId: event.userPoolId,
          triggerSource: event.triggerSource,
          userName: event.username,
          request: {
            userAttributes: event.userAttributes,
            groupConfiguration: event.groupConfiguration,
            ...(v1 ? {} : { scopes: event.scopes }),
            clientMetadata: event.clientMetadata,
          },
          response: v1
            ? { claimsOverrideDetails: {} }
            : { claimsAndScopeOverrideDetails: null },
        };
      }

      case "UserMigration_Authentication": {
        return {
          version,
          callerContext,
          region,
          userPoolId: event.userPoolId,
          triggerSource: event.triggerSource,
          userName: event.username,
          request: {
            clientMetadata: event.clientMetadata,
            password: event.password,
            validationData: event.validationData,
          },
          response: {
            desiredDeliveryMediums: [],
            finalUserStatus: undefined,
            forceAliasCreation: undefined,
            messageAction: undefined,
            userAttributes: {},
          },
        };
      }

      case "CustomMessage_SignUp":
      case "CustomMessage_AdminCreateUser":
      case "CustomMessage_ResendCode":
      case "CustomMessage_ForgotPassword":
      case "CustomMessage_UpdateUserAttribute":
      case "CustomMessage_VerifyUserAttribute":
      case "CustomMessage_Authentication": {
        return {
          version,
          callerContext,
          region,
          userPoolId: event.userPoolId,
          triggerSource: event.triggerSource,
          userName: event.username,
          request: {
            clientMetadata: event.clientMetadata,
            codeParameter: event.codeParameter,
            usernameParameter: event.usernameParameter,
            userAttributes: event.userAttributes,
          },
          response: {
            smsMessage: "",
            emailMessage: "",
            emailSubject: "",
          },
        };
      }

      case "CustomEmailSender_SignUp":
      case "CustomEmailSender_ResendCode":
      case "CustomEmailSender_ForgotPassword":
      case "CustomEmailSender_UpdateUserAttribute":
      case "CustomEmailSender_VerifyUserAttribute":
      case "CustomEmailSender_AdminCreateUser":
        return {
          version,
          region,
          userPoolId: event.userPoolId,
          triggerSource: event.triggerSource,
          userName: event.username,
          callerContext,
          request: {
            type: "customEmailSenderRequestV1",
            code: event.code,
            userAttributes: event.userAttributes,
            clientMetadata: event.clientMetadata,
          },
          response: {},
        };
      case "DefineAuthChallenge_Authentication": {
        return {
          version,
          callerContext,
          region,
          userPoolId: event.userPoolId,
          triggerSource: event.triggerSource,
          userName: event.username,
          request: {
            userAttributes: event.userAttributes,
            session:
              event.session as DefineAuthChallengeTriggerEvent["request"]["session"],
            clientMetadata: event.clientMetadata,
            userNotFound: event.userNotFound,
          },
          response: {
            challengeName: "",
            issueTokens: false,
            failAuthentication: false,
          },
        };
      }

      case "CreateAuthChallenge_Authentication": {
        return {
          version,
          callerContext,
          region,
          userPoolId: event.userPoolId,
          triggerSource: event.triggerSource,
          userName: event.username,
          request: {
            userAttributes: event.userAttributes,
            challengeName: event.challengeName,
            session:
              event.session as CreateAuthChallengeTriggerEvent["request"]["session"],
            clientMetadata: event.clientMetadata,
          },
          response: {
            publicChallengeParameters: {},
            privateChallengeParameters: {},
            challengeMetadata: "",
          },
        };
      }

      case "VerifyAuthChallengeResponse_Authentication": {
        return {
          version,
          callerContext,
          region,
          userPoolId: event.userPoolId,
          triggerSource: event.triggerSource,
          userName: event.username,
          request: {
            userAttributes: event.userAttributes,
            challengeAnswer: event.challengeAnswer,
            privateChallengeParameters: event.privateChallengeParameters ?? {},
            clientMetadata: event.clientMetadata,
          },
          response: {
            answerCorrect: false,
          },
        };
      }

      default: {
        throw new Error("Unsupported Trigger Source");
      }
    }
  }
}
