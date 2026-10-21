import {
  emulatorBanner,
  emulatorBannerStyle,
  PRODUCT_NAME,
} from "../server/emulatorBanner";
import type { HostedLoginContext } from "./hostedLogin";
import type { HostedLoginStep } from "./hostedLoginStore";
import { type FormField, maskDestination } from "./hostedPages";
import { escapeHtml, hiddenInput } from "./html";

export interface OAuthPageParams {
  clientId: string;
  redirectUri: string;
  responseType: string;
  codeChallenge: string | undefined;
  codeChallengeMethod: string | undefined;
  scope: string;
  state: string;
}

export interface LoginFormParams extends OAuthPageParams {
  error?: string;
  notice?: string;
  signUpAllowed?: boolean;
  passkeyAllowed?: boolean;
}

export const oauthParamsOf = (login: HostedLoginContext): OAuthPageParams => ({
  clientId: login.appClient.ClientId,
  redirectUri: login.redirectUri,
  responseType: login.flow.responseType,
  codeChallenge: login.flow.codeChallenge,
  codeChallengeMethod: login.flow.codeChallengeMethod,
  scope: login.scope,
  state: login.state ?? "",
});

const page = (
  title: string,
  error: string | undefined,
  body: string,
  notice?: string,
) =>
  `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" /><title>${escapeHtml(title)} · ${PRODUCT_NAME}</title>${emulatorBannerStyle()}</head>
<body style="margin:0">
${emulatorBanner()}
<main style="padding:16px">
${error ? `<p role="alert" style="color:red">${escapeHtml(error)}</p>` : ""}
${notice ? `<p role="status">${escapeHtml(notice)}</p>` : ""}
${body}
</main>
</body>
</html>`;

const oauthHiddenInputs = (params: OAuthPageParams) =>
  `${hiddenInput("client_id", params.clientId)}${hiddenInput("redirect_uri", params.redirectUri)}${hiddenInput("response_type", params.responseType)}${hiddenInput("code_challenge", params.codeChallenge)}${hiddenInput("code_challenge_method", params.codeChallengeMethod)}${hiddenInput("scope", params.scope)}${hiddenInput("state", params.state)}`;

/** A hosted page path with the authorize parameters in its query, as managed login links its pages. */
export const hostedPageUrl = (
  path: string,
  params: OAuthPageParams,
): string => {
  const query = new URLSearchParams();
  const entries: [string, string | undefined][] = [
    ["client_id", params.clientId],
    ["response_type", params.responseType],
    ["scope", params.scope],
    ["redirect_uri", params.redirectUri],
    ["state", params.state],
    ["code_challenge", params.codeChallenge],
    ["code_challenge_method", params.codeChallengeMethod],
  ];
  for (const [name, value] of entries) {
    if (value) query.set(name, value);
  }
  return `${path}?${query}`;
};

const link = (href: string, text: string) =>
  `<a href="${escapeHtml(href)}">${escapeHtml(text)}</a>`;

const input = (
  field: FormField,
  value?: string,
  { required = true }: { required?: boolean } = {},
) =>
  `  <label>${escapeHtml(field.label)}: <input type="${field.type}" name="${escapeHtml(field.name)}" autocomplete="${field.autocomplete}"${value ? ` value="${escapeHtml(value)}"` : ""}${required ? " required" : ""} /></label><br />`;

const passwordInput = (name: string, label: string, autocomplete: string) =>
  `  <label>${label}: <input type="password" name="${name}" autocomplete="${autocomplete}" required /></label><br />`;

const codeInput = () =>
  `  <label>Code: <input type="text" name="code" autocomplete="one-time-code" inputmode="numeric" required /></label><br />`;

export const loginForm = (params: LoginFormParams): string =>
  page(
    "Sign in",
    params.error,
    `<form method="POST" action="/oauth2/authorize">
${oauthHiddenInputs(params)}  <label>Username: <input type="text" name="username" autocomplete="username" /></label><br />
  <label>Password: <input type="password" name="password" autocomplete="current-password" /></label><br />
  <button type="submit">Sign in</button>
${
  params.passkeyAllowed
    ? `  <button type="submit" name="passkey" value="true">Sign in with passkey</button>
`
    : ""
}</form>
<p>${link(hostedPageUrl("/forgotPassword", params), "Forgot your password?")}</p>
${params.signUpAllowed === false ? "" : `<p>Need an account? ${link(hostedPageUrl("/signup", params), "Sign up")}</p>\n`}`,
    params.notice,
  );

export interface SignUpPageParams extends OAuthPageParams {
  usernameField: FormField;
  attributeFields: FormField[];
  values?: Record<string, string | undefined>;
  error?: string;
}

export const signUpPage = (params: SignUpPageParams): string =>
  page(
    "Sign up",
    params.error,
    `<form method="POST" action="/signup">
${oauthHiddenInputs(params)}${input(params.usernameField, params.values?.username)}
${params.attributeFields.map((field) => `${input(field, params.values?.[field.name])}\n`).join("")}${passwordInput("password", "Password", "new-password")}
  <button type="submit">Sign up</button>
</form>
<p>Already have an account? ${link(hostedPageUrl("/login", params), "Sign in")}</p>
`,
  );

export interface ForgotPasswordPageParams extends OAuthPageParams {
  usernameField: FormField;
  username?: string;
  error?: string;
}

export const forgotPasswordPage = (params: ForgotPasswordPageParams): string =>
  page(
    "Forgot your password?",
    params.error,
    `<p>Enter your ${escapeHtml(params.usernameField.label.toLowerCase())} below and we will send a message to reset your password.</p>
<form method="POST" action="/forgotPassword">
${oauthHiddenInputs(params)}${input(params.usernameField, params.username)}
  <button type="submit">Reset my password</button>
</form>
<p>${link(hostedPageUrl("/login", params), "Back to sign in")}</p>
`,
  );

const jsonScript = (id: string, value: unknown) =>
  `<script type="application/json" id="${id}">${JSON.stringify(value).replace(/</g, "\\u003c")}</script>`;

// Converts the JSON options to the ArrayBuffers navigator.credentials expects, and the result back to JSON.
const PASSKEY_SCRIPT = `<script>
(function () {
  function toBuffer(value) {
    var s = value.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var binary = atob(s);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
  }
  function toBase64url(buffer) {
    var bytes = new Uint8Array(buffer);
    var binary = "";
    for (var i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary).replace(/\\+/g, "-").replace(/\\//g, "_").replace(/=+$/, "");
  }
  function descriptors(list) {
    return (list || []).map(function (c) { return { type: c.type, id: toBuffer(c.id) }; });
  }
  var form = document.getElementById("passkey-form");
  var options = JSON.parse(document.getElementById("passkey-options").textContent);
  var mode = form.getAttribute("data-mode");
  document.getElementById("passkey-button").addEventListener("click", function () {
    var publicKey = Object.assign({}, options, { challenge: toBuffer(options.challenge) });
    var request;
    if (mode === "create") {
      publicKey.user = Object.assign({}, options.user, { id: toBuffer(options.user.id) });
      publicKey.excludeCredentials = descriptors(options.excludeCredentials);
      request = navigator.credentials.create({ publicKey: publicKey });
    } else {
      publicKey.allowCredentials = descriptors(options.allowCredentials);
      request = navigator.credentials.get({ publicKey: publicKey });
    }
    request.then(function (credential) {
      var r = credential.response;
      var response = { clientDataJSON: toBase64url(r.clientDataJSON) };
      if (mode === "create") {
        response.attestationObject = toBase64url(r.attestationObject);
        response.transports = r.getTransports ? r.getTransports() : [];
      } else {
        response.authenticatorData = toBase64url(r.authenticatorData);
        response.signature = toBase64url(r.signature);
        if (r.userHandle) response.userHandle = toBase64url(r.userHandle);
      }
      form.elements.credential.value = JSON.stringify({
        id: credential.id,
        rawId: toBase64url(credential.rawId),
        type: credential.type,
        authenticatorAttachment: credential.authenticatorAttachment,
        clientExtensionResults: credential.getClientExtensionResults(),
        response: response
      });
      form.submit();
    }).catch(function (error) {
      document.getElementById("passkey-error").textContent =
        "The passkey request did not complete: " + error.message;
    });
  });
})();
</script>`;

const passkeyForm = (
  mode: "create" | "get",
  action: string,
  hidden: string,
  options: unknown,
  button: string,
) =>
  `<form method="POST" action="${action}" id="passkey-form" data-mode="${mode}">
${hidden}  <input type="hidden" name="credential" value="" />
  <button type="button" id="passkey-button">${escapeHtml(button)}</button>
</form>
<p role="alert" id="passkey-error" style="color:red"></p>
${jsonScript("passkey-options", options)}
${PASSKEY_SCRIPT}`;

export interface PasskeyRegistrationPageParams {
  clientId: string;
  redirectUri: string;
  username: string;
  options: unknown;
  error?: string;
}

export const passkeyRegistrationPage = (
  params: PasskeyRegistrationPageParams,
): string =>
  page(
    "Add a passkey",
    params.error,
    `<p>Add a passkey to sign in as ${escapeHtml(params.username)} without a password.</p>
${passkeyForm(
  "create",
  "/passkeys/add",
  `${hiddenInput("client_id", params.clientId)}${hiddenInput("redirect_uri", params.redirectUri)}`,
  params.options,
  "Add passkey",
)}`,
  );

const stepForm = (
  sessionId: string,
  fields: string,
  action = "/oauth2/authorize",
) =>
  `<form method="POST" action="${action}">
${hiddenInput("login_session", sessionId)}${fields}
</form>`;

const MFA_LABELS = {
  SMS_MFA: "Text message (SMS)",
  SOFTWARE_TOKEN_MFA: "Authenticator app",
} as const;

const sentTo = (
  delivery: { DeliveryMedium?: string; Destination?: string } | null,
): string =>
  delivery?.Destination
    ? ` by ${delivery.DeliveryMedium === "SMS" ? "SMS" : "email"} to ${escapeHtml(maskDestination(delivery.Destination))}`
    : "";

export const stepPage = (
  sessionId: string,
  step: HostedLoginStep,
  error?: string,
  notice?: string,
): string => {
  switch (step.kind) {
    case "newPassword":
      return page(
        "Change password",
        error,
        `<p>Please enter a new password.</p>
${stepForm(
  sessionId,
  `${passwordInput("new_password", "New password", "new-password")}
${passwordInput("confirm_password", "Enter new password again", "new-password")}
  <button type="submit">Send</button>`,
)}`,
        notice,
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
        notice,
      );
    case "smsMfa":
      return page(
        "Verify your identity",
        error,
        `<p>We have sent a code by SMS to ${escapeHtml(maskDestination(step.destination))}. Enter it below to complete sign-in.</p>
${stepForm(sessionId, `${codeInput()}\n  <button type="submit">Sign in</button>`)}`,
        notice,
      );
    case "totpMfa":
      return page(
        "Verify your identity",
        error,
        `<p>Enter the code from your authenticator app.</p>
${stepForm(sessionId, `${codeInput()}\n  <button type="submit">Sign in</button>`)}`,
        notice,
      );
    case "mfaSetup":
      return page(
        "Set up an authenticator app",
        error,
        `<p>Multi-factor authentication is required. Add this account to an authenticator app, then enter the code the app shows.</p>
<p>Secret key: <code>${escapeHtml(step.secret)}</code></p>
<p>Setup link: <a href="${escapeHtml(step.uri)}">${escapeHtml(step.uri)}</a></p>
${stepForm(sessionId, `${codeInput()}\n  <button type="submit">Verify and sign in</button>`)}`,
        notice,
      );
    case "passkey":
      return page(
        "Sign in with passkey",
        error,
        `<p>Use your passkey to sign in.</p>
${passkeyForm("get", "/oauth2/authorize", hiddenInput("login_session", sessionId), step.options, "Use passkey")}`,
        notice,
      );
    case "confirmSignUp":
      return page(
        "Confirm your account",
        error,
        `<p>${step.delivery ? `We have sent a code${sentTo(step.delivery)}.` : "Enter the confirmation code you received."} Enter it below to confirm your account.</p>
${stepForm(sessionId, `${codeInput()}\n  <button type="submit">Confirm account</button>`, "/confirm")}
${stepForm(sessionId, `  <p>Didn't receive a code? <button type="submit">Send a new code</button></p>`, "/resendcode")}`,
        notice,
      );
    case "confirmForgotPassword":
      return page(
        "Reset your password",
        error,
        `<p>${step.delivery ? `We have sent a password reset code${sentTo(step.delivery)}.` : "Enter the password reset code you received."} Enter it below to reset your password.</p>
${stepForm(
  sessionId,
  `${codeInput()}
${passwordInput("new_password", "New password", "new-password")}
${passwordInput("confirm_password", "Enter new password again", "new-password")}
  <button type="submit">Change password</button>`,
  "/confirmForgotPassword",
)}`,
        notice,
      );
  }
};

export const noticePage = (
  message: string,
  next?: { href: string; text: string },
): string =>
  page(
    "Sign in",
    message,
    next ? `<p>${link(next.href, next.text)}</p>\n` : "",
  );
