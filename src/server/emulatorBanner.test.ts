import { describe, expect, it } from "vitest";
import { layout, raw } from "../admin/html";
import {
  loginForm,
  noticePage,
  passkeyRegistrationPage,
  stepPage,
} from "../oauth2/hostedLoginPages";
import type { HostedLoginStep } from "../oauth2/hostedLoginStore";
import {
  emulatorBanner,
  emulatorNoticePage,
  PRODUCT_NAME,
  PRODUCT_TAGLINE,
} from "./emulatorBanner";

const OAUTH = {
  clientId: "client",
  redirectUri: "http://localhost:3000/cb",
  responseType: "code",
  codeChallenge: undefined,
  codeChallengeMethod: undefined,
  scope: "openid",
  state: "st",
};

const STEPS: HostedLoginStep[] = [
  { kind: "newPassword" },
  { kind: "selectMfa", methods: ["SMS_MFA", "SOFTWARE_TOKEN_MFA"] },
  { kind: "smsMfa", code: "123456", destination: "+15555550100" },
  { kind: "totpMfa" },
  { kind: "mfaSetup", secret: "SECRET", uri: "otpauth://totp/x?secret=S" },
  {
    kind: "passkey",
    challenge: "c",
    requireUserVerification: false,
    options: { challenge: "c" },
  },
  { kind: "confirmSignUp", delivery: null, signInAfter: false },
  { kind: "confirmForgotPassword", delivery: null },
];

const banner = emulatorBanner();

describe("emulatorBanner", () => {
  it("names the product, says it is not AWS and links the admin UI and codes", () => {
    expect(banner).toMatch(/^<header class="ce-banner"/);
    expect(banner).toContain(`>${PRODUCT_NAME}</a>`);
    expect(banner).toContain(PRODUCT_TAGLINE);
    expect(banner).toContain('href="/_admin"');
    expect(banner).toContain('href="/_admin/codes"');
  });

  it.each(STEPS.map((step) => [step.kind, step] as const))(
    "opens the %s step page",
    (_kind, step) => {
      expect(stepPage("session", step)).toContain(banner);
    },
  );

  it("opens the login, passkey registration, notice and admin pages", () => {
    expect(loginForm(OAUTH)).toContain(banner);
    expect(
      passkeyRegistrationPage({
        clientId: "client",
        redirectUri: OAUTH.redirectUri,
        username: "jane",
        options: {},
      }),
    ).toContain(banner);
    expect(noticePage("Expired")).toContain(banner);
    expect(
      layout({ title: "Codes", active: "codes", body: raw("<p>x</p>") }),
    ).toContain(banner);
    expect(emulatorNoticePage("Off", "<b>")).toContain(banner);
    expect(emulatorNoticePage("Off", "<b>")).toContain("&lt;b&gt;");
  });
});
