import type { HostedLoginStep } from "./hostedLoginStore";
import { escapeHtml, hiddenInput } from "./html";

export interface LoginFormParams {
  clientId: string;
  redirectUri: string;
  responseType: string;
  codeChallenge: string | undefined;
  codeChallengeMethod: string | undefined;
  scope: string;
  state: string;
  error?: string;
}

const page = (title: string, error: string | undefined, body: string) =>
  `<!DOCTYPE html>
<html>
<head><title>${escapeHtml(title)}</title></head>
<body>
${error ? `<p style="color:red">${escapeHtml(error)}</p>` : ""}
${body}
</body>
</html>`;

export const loginForm = (params: LoginFormParams): string =>
  page(
    "Sign in",
    params.error,
    `<form method="POST" action="/oauth2/authorize">
${hiddenInput("client_id", params.clientId)}${hiddenInput("redirect_uri", params.redirectUri)}${hiddenInput("response_type", params.responseType)}${hiddenInput("code_challenge", params.codeChallenge)}${hiddenInput("code_challenge_method", params.codeChallengeMethod)}${hiddenInput("scope", params.scope)}${hiddenInput("state", params.state)}  <label>Username: <input type="text" name="username" /></label><br />
  <label>Password: <input type="password" name="password" /></label><br />
  <button type="submit">Sign in</button>
</form>`,
  );

const stepForm = (sessionId: string, fields: string) =>
  `<form method="POST" action="/oauth2/authorize">
${hiddenInput("login_session", sessionId)}${fields}
</form>`;

const maskDestination = (destination: string): string =>
  destination.length <= 4
    ? destination
    : `${destination.startsWith("+") ? "+" : ""}${"*".repeat(
        destination.length - 4 - (destination.startsWith("+") ? 1 : 0),
      )}${destination.slice(-4)}`;

const MFA_LABELS = {
  SMS_MFA: "Text message (SMS)",
  SOFTWARE_TOKEN_MFA: "Authenticator app",
} as const;

export const stepPage = (
  sessionId: string,
  step: HostedLoginStep,
  error?: string,
): string => {
  switch (step.kind) {
    case "newPassword":
      return page(
        "Change password",
        error,
        `<p>Please enter a new password.</p>
${stepForm(
  sessionId,
  `  <label>New password: <input type="password" name="new_password" /></label><br />
  <label>Enter new password again: <input type="password" name="confirm_password" /></label><br />
  <button type="submit">Send</button>`,
)}`,
      );
    case "selectMfa":
      return page(
        "Choose a sign-in method",
        error,
        stepForm(
          sessionId,
          step.methods
            .map(
              (method) =>
                `  <button type="submit" name="mfa_method" value="${method}">${MFA_LABELS[method]}</button>`,
            )
            .join("\n"),
        ),
      );
    case "smsMfa":
      return page(
        "Verify your identity",
        error,
        `<p>We have sent a code by SMS to ${escapeHtml(maskDestination(step.destination))}. Enter it below to complete sign-in.</p>
${stepForm(
  sessionId,
  `  <label>Code: <input type="text" name="code" autocomplete="one-time-code" /></label><br />
  <button type="submit">Sign in</button>`,
)}`,
      );
    case "totpMfa":
      return page(
        "Verify your identity",
        error,
        `<p>Enter the code from your authenticator app.</p>
${stepForm(
  sessionId,
  `  <label>Code: <input type="text" name="code" autocomplete="one-time-code" /></label><br />
  <button type="submit">Sign in</button>`,
)}`,
      );
  }
};

export const noticePage = (message: string): string =>
  page("Sign in", message, "");
