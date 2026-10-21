import type { Clock } from "../clock";
import type { CognitoService } from "../cognitoService";
import type { CryptoService } from "../crypto";
import type { Lambda } from "../lambda";
import {
  type PreTokenGenerationVersion,
  preTokenGenerationVersion,
} from "../tokenCustomization";
import {
  CreateAuthChallenge,
  type CreateAuthChallengeTrigger,
} from "./createAuthChallenge";
import {
  CustomEmailSender,
  type CustomEmailSenderTrigger,
} from "./customEmailSender";
import { CustomMessage, type CustomMessageTrigger } from "./customMessage";
import {
  CustomSMSSender,
  type CustomSMSSenderTrigger,
} from "./customSmsSender";
import {
  DefineAuthChallenge,
  type DefineAuthChallengeTrigger,
} from "./defineAuthChallenge";
import {
  PostAuthentication,
  type PostAuthenticationTrigger,
} from "./postAuthentication";
import {
  PostConfirmation,
  type PostConfirmationTrigger,
} from "./postConfirmation";
import {
  PreAuthentication,
  type PreAuthenticationTrigger,
} from "./preAuthentication";
import { PreSignUp, type PreSignUpTrigger } from "./preSignUp";
import {
  PreTokenGeneration,
  type PreTokenGenerationTrigger,
} from "./preTokenGeneration";
import { UserMigration, type UserMigrationTrigger } from "./userMigration";
import {
  VerifyAuthChallengeResponse,
  type VerifyAuthChallengeResponseTrigger,
} from "./verifyAuthChallengeResponse";

type SupportedTriggers =
  | "CreateAuthChallenge"
  | "CustomEmailSender"
  | "CustomMessage"
  | "CustomSMSSender"
  | "DefineAuthChallenge"
  | "PostAuthentication"
  | "PostConfirmation"
  | "PreAuthentication"
  | "PreSignUp"
  | "PreTokenGeneration"
  | "UserMigration"
  | "VerifyAuthChallengeResponse";

export interface Triggers {
  enabled(trigger: SupportedTriggers, userPoolId?: string): boolean;
  createAuthChallenge: CreateAuthChallengeTrigger;
  customMessage: CustomMessageTrigger;
  customEmailSender: CustomEmailSenderTrigger;
  customSmsSender: CustomSMSSenderTrigger;
  defineAuthChallenge: DefineAuthChallengeTrigger;
  postAuthentication: PostAuthenticationTrigger;
  postConfirmation: PostConfirmationTrigger;
  preAuthentication: PreAuthenticationTrigger;
  preSignUp: PreSignUpTrigger;
  preTokenGeneration: PreTokenGenerationTrigger;
  /** The pre token generation event version that the user pool is configured for. */
  preTokenGenerationVersion(userPoolId: string): PreTokenGenerationVersion;
  userMigration: UserMigrationTrigger;
  verifyAuthChallengeResponse: VerifyAuthChallengeResponseTrigger;
}

export class TriggersService implements Triggers {
  private readonly lambda: Lambda;
  private readonly cognitoClient: CognitoService;

  public readonly createAuthChallenge: CreateAuthChallengeTrigger;
  public readonly customMessage: CustomMessageTrigger;
  public readonly customEmailSender: CustomEmailSenderTrigger;
  public readonly customSmsSender: CustomSMSSenderTrigger;
  public readonly defineAuthChallenge: DefineAuthChallengeTrigger;
  public readonly postAuthentication: PostAuthenticationTrigger;
  public readonly postConfirmation: PostConfirmationTrigger;
  public readonly preAuthentication: PreAuthenticationTrigger;
  public readonly preSignUp: PreSignUpTrigger;
  public readonly preTokenGeneration: PreTokenGenerationTrigger;
  public readonly userMigration: UserMigrationTrigger;
  public readonly verifyAuthChallengeResponse: VerifyAuthChallengeResponseTrigger;

  public constructor(
    clock: Clock,
    cognitoClient: CognitoService,
    lambda: Lambda,
    crypto: CryptoService,
  ) {
    this.lambda = lambda;
    this.cognitoClient = cognitoClient;

    this.createAuthChallenge = CreateAuthChallenge({ lambda });
    this.customEmailSender = CustomEmailSender({ lambda, crypto });
    this.customMessage = CustomMessage({ lambda });
    this.customSmsSender = CustomSMSSender({ lambda, crypto });
    this.defineAuthChallenge = DefineAuthChallenge({ lambda });
    this.postAuthentication = PostAuthentication({ lambda });
    this.postConfirmation = PostConfirmation({ lambda });
    this.preAuthentication = PreAuthentication({ lambda });
    this.preSignUp = PreSignUp({ lambda });
    this.preTokenGeneration = PreTokenGeneration({ lambda });
    this.userMigration = UserMigration({ clock, lambda, cognitoClient });
    this.verifyAuthChallengeResponse = VerifyAuthChallengeResponse({ lambda });
  }

  public enabled(trigger: SupportedTriggers, userPoolId?: string): boolean {
    return this.lambda.enabled(trigger, userPoolId);
  }

  public preTokenGenerationVersion(
    userPoolId: string,
  ): PreTokenGenerationVersion {
    return preTokenGenerationVersion(
      this.cognitoClient.peekUserPool(userPoolId)?.LambdaConfig,
    );
  }
}
