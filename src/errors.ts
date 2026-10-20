export class UnsupportedError extends Error {}

export class CognitoError extends Error {
  public readonly code: string;

  public constructor(code: string, message: string) {
    super(message);
    this.code = `${code}`;
  }
}

export class NotAuthorizedError extends CognitoError {
  public constructor(message = "User not authorized") {
    super("NotAuthorizedException", message);
  }
}

export class UserNotFoundError extends CognitoError {
  public constructor(message = "User not found.") {
    super("UserNotFoundException", message);
  }
}

export class UsernameExistsError extends CognitoError {
  public constructor(message = "User already exists") {
    super("UsernameExistsException", message);
  }
}

export class CodeMismatchError extends CognitoError {
  public constructor() {
    super("CodeMismatchException", "Incorrect confirmation code");
  }
}

export class ExpiredCodeError extends CognitoError {
  public constructor() {
    super(
      "ExpiredCodeException",
      "Invalid code provided, please request a code again.",
    );
  }
}

export class InvalidPasswordError extends CognitoError {
  public constructor(message = "Invalid password") {
    super("InvalidPasswordException", message);
  }
}

export class PasswordResetRequiredError extends CognitoError {
  public constructor() {
    super("PasswordResetRequiredException", "Password reset required");
  }
}

export class UserNotConfirmedException extends CognitoError {
  public constructor() {
    super("UserNotConfirmedException", "User is not confirmed.");
  }
}

export class ResourceNotFoundError extends CognitoError {
  public constructor(message?: string) {
    super("ResourceNotFoundException", message ?? "Resource not found");
  }
}

export class GroupNotFoundError extends ResourceNotFoundError {
  public constructor() {
    super("Group not found");
  }
}

export class UnexpectedLambdaExceptionError extends CognitoError {
  public constructor(message?: string) {
    super(
      "UnexpectedLambdaExceptionException",
      message ?? "Unexpected error when invoking lambda",
    );
  }
}

export class UserLambdaValidationError extends CognitoError {
  public constructor(message?: string) {
    super(
      "UserLambdaValidationException",
      message ?? "Lambda threw an exception",
    );
  }
}

export class InvalidLambdaResponseError extends CognitoError {
  public constructor() {
    super("InvalidLambdaResponseException", "Invalid Lambda response");
  }
}

export class AliasExistsError extends CognitoError {
  public constructor(attributeName = "email") {
    super(
      "AliasExistsException",
      `An account with the given ${attributeName} already exists.`,
    );
  }
}

export class GroupExistsError extends CognitoError {
  public constructor(groupName: string) {
    super(
      "GroupExistsException",
      `A group with the name ${groupName} already exists.`,
    );
  }
}

export class InvalidParameterError extends CognitoError {
  public constructor(message = "Invalid parameter") {
    super("InvalidParameterException", message);
  }
}

export class UnsupportedOperationError extends CognitoError {
  public constructor(message: string) {
    super("UnsupportedOperationException", message);
  }
}

export class UnsupportedTokenTypeError extends CognitoError {
  public constructor(message = "Unsupported token type") {
    super("UnsupportedTokenTypeException", message);
  }
}

export class UnknownOperationError extends CognitoError {
  public constructor(message: string) {
    super("UnknownOperationException", message);
  }
}

export const TokenErrorMessages = {
  invalidAccessToken: "Invalid Access Token",
  expiredAccessToken: "Access Token has expired",
  revokedAccessToken: "Access Token has been revoked",
  missingScope: "Access Token does not have required scopes",
  invalidRefreshToken: "Invalid Refresh Token",
  expiredRefreshToken: "Refresh Token has expired",
  revokedRefreshToken: "Refresh Token has been revoked",
  userDisabled: "User is disabled.",
  userDoesNotExist: "User does not exist.",
} as const;
