import type { Config } from "../server/config";
import type { AuthSessions } from "./authSessions";
import type { Clock } from "./clock";
import type { CodeLog } from "./codeLog";
import type { CognitoService } from "./cognitoService";
import type { Messages } from "./messages";
import type { TokenGenerator } from "./tokenGenerator";
import type { Triggers } from "./triggers";

export { AuthSessions, InMemoryAuthSessions } from "./authSessions";
export { Clock, DateClock } from "./clock";
export { CodeLog, InMemoryCodeLog } from "./codeLog";
export { CognitoService, CognitoServiceImpl } from "./cognitoService";
export { Lambda, LambdaService } from "./lambda";
export { Messages, MessagesService } from "./messages";
export { Triggers, TriggersService } from "./triggers";
export { UserPoolService, UserPoolServiceImpl } from "./userPoolService";

export interface Services {
  authSessions: AuthSessions;
  clock: Clock;
  codeLog?: CodeLog;
  cognito: CognitoService;
  config: Config;
  messages: Messages;
  otp: () => string;
  tokenGenerator: TokenGenerator;
  triggers: Triggers;
}
