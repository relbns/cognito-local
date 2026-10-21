import { describe, expect, it } from "vitest";
import { computeSecretHash } from "../services/tokenVerifier";
import { loginForm, stepPage } from "./hostedLoginPages";
import {
  maskDestination,
  secretHashFor,
  signUpAllowed,
  signUpAttributeFields,
  signUpAttributes,
  usernameField,
} from "./hostedPages";

const required = (...names: string[]) => [
  { Name: "sub", Required: true },
  ...names.map((Name) => ({ Name, Required: true })),
];

const OAUTH = {
  clientId: "client-1",
  redirectUri: "http://localhost:9876/cb",
  responseType: "code",
  codeChallenge: undefined,
  codeChallengeMethod: undefined,
  scope: "openid email",
  state: "a&b",
};

describe("hosted page fields", () => {
  it.each`
    usernameAttributes           | label                      | type       | autocomplete
    ${["email"]}                 | ${"Email"}                 | ${"email"} | ${"email"}
    ${["phone_number"]}          | ${"Phone number"}          | ${"tel"}   | ${"tel"}
    ${["email", "phone_number"]} | ${"Email or phone number"} | ${"text"}  | ${"username"}
    ${[]}                        | ${"Username"}              | ${"text"}  | ${"username"}
  `(
    "asks sign-up for $label when the pool signs in with $usernameAttributes",
    ({ usernameAttributes, label, type, autocomplete }) => {
      expect(
        usernameField({ UsernameAttributes: usernameAttributes }, "signUp"),
      ).toEqual({ name: "username", label, type, autocomplete });
    },
  );

  it("fills the username for a password manager on the forgot-password page", () => {
    expect(
      usernameField({ UsernameAttributes: ["email"] }, "signIn").autocomplete,
    ).toBe("username");
  });

  it("lists required attributes except sub and the one the username holds", () => {
    expect(
      signUpAttributeFields({
        UsernameAttributes: ["email"],
        SchemaAttributes: [
          ...required("email", "given_name", "custom:team_name"),
          { Name: "nickname", Required: false },
        ],
      }),
    ).toEqual([
      {
        name: "requiredAttributes[given_name]",
        label: "Given name",
        type: "text",
        autocomplete: "given-name",
      },
      {
        name: "requiredAttributes[custom:team_name]",
        label: "Team name",
        type: "text",
        autocomplete: "off",
      },
    ]);
  });

  it("sends the filled attributes and the phone number a phone username stands for", () => {
    const pool = {
      UsernameAttributes: ["phone_number" as const],
      SchemaAttributes: required("name", "birthdate"),
    };
    expect(
      signUpAttributes(pool, "+15555550100", {
        "requiredAttributes[name]": " Jane ",
        "requiredAttributes[birthdate]": "",
        "requiredAttributes[role]": "admin",
      }),
    ).toEqual([
      { Name: "name", Value: "Jane" },
      { Name: "phone_number", Value: "+15555550100" },
    ]);
  });

  it("allows sign-up unless only administrators create users", () => {
    expect(signUpAllowed({})).toBe(true);
    expect(
      signUpAllowed({
        AdminCreateUserConfig: { AllowAdminCreateUserOnly: true },
      }),
    ).toBe(false);
  });

  it("computes the SecretHash only for a client with a secret", () => {
    expect(secretHashFor({ ClientId: "c" }, "jane")).toBeUndefined();
    expect(secretHashFor({ ClientId: "c", ClientSecret: "s" }, "jane")).toBe(
      computeSecretHash("jane", "c", "s"),
    );
  });

  it.each`
    destination            | masked
    ${"jane@example.test"} | ${"j***@e***"}
    ${"+15555550100"}      | ${"+*******0100"}
    ${"0100"}              | ${"0100"}
  `("masks $destination as $masked", ({ destination, masked }) => {
    expect(maskDestination(destination)).toBe(masked);
  });
});

describe("hosted page markup", () => {
  it("links sign-up and forgot password with escaped authorize parameters", () => {
    const html = loginForm(OAUTH);
    expect(html).toContain(
      'href="/signup?client_id=client-1&amp;response_type=code&amp;scope=openid+email&amp;redirect_uri=http%3A%2F%2Flocalhost%3A9876%2Fcb&amp;state=a%26b"',
    );
    expect(html).toContain("/forgotPassword?client_id=client-1");
  });

  it("drops the sign-up link when sign-up is not allowed", () => {
    const html = loginForm({ ...OAUTH, signUpAllowed: false });
    expect(html).not.toContain("/signup?");
    expect(html).toContain("/forgotPassword?");
  });

  it("shows a notice as status text and an error as an alert", () => {
    expect(loginForm({ ...OAUTH, notice: "Done." })).toContain(
      '<p role="status">Done.</p>',
    );
    expect(loginForm({ ...OAUTH, error: "<b>" })).toContain(
      '<p role="alert" style="color:red">&lt;b&gt;</p>',
    );
  });

  it("posts the confirm and resend forms with the session only", () => {
    const html = stepPage("s-1", {
      kind: "confirmSignUp",
      delivery: { DeliveryMedium: "SMS", Destination: "+15555550100" },
      signInAfter: true,
    });
    expect(html).toContain("We have sent a code by SMS to +*******0100.");
    expect(html).toContain('<form method="POST" action="/confirm">');
    expect(html).toContain('<form method="POST" action="/resendcode">');
    expect(html).not.toContain('name="username"');
  });

  it("asks for a code and the new password twice on the reset page", () => {
    const html = stepPage("s-1", {
      kind: "confirmForgotPassword",
      delivery: null,
    });
    expect(html).toContain('action="/confirmForgotPassword"');
    expect(html).toContain('name="new_password" autocomplete="new-password"');
    expect(html).toContain(
      'name="confirm_password" autocomplete="new-password"',
    );
    expect(html).toContain("Enter the password reset code you received.");
  });
});
