import { createHash } from "node:crypto";
import {
  emulatorBanner,
  emulatorBannerStyle,
  PRODUCT_NAME,
} from "../server/emulatorBanner";
import type { IdentityProviderConfig } from "./federation";
import { escapeHtml, hiddenInput } from "./html";
import type { MockAccount } from "./mockIdpAccounts";

// Logical properties only, so the page reads correctly right to left.
const STYLE = `
  *, *::before, *::after { box-sizing: border-box; }
  body { margin: 0; background: #f1f3f6; color: #1f2329; font: 14px/1.45 system-ui, -apple-system, "Segoe UI", Roboto, sans-serif; }
  .idp { max-width: 448px; margin: 40px auto 24px; padding-inline: 16px; }
  .card { background: #fff; border: 1px solid #dde1e7; border-radius: 12px; padding: 32px 32px 24px; }
  @media (max-width: 480px) { .idp { margin-block-start: 0; padding-inline: 0; } .card { border-radius: 0; border-inline: 0; padding-inline: 20px; } }
  .brand { display: flex; flex-direction: column; align-items: center; gap: 8px; text-align: center; }
  .mark { inline-size: 48px; block-size: 48px; border-radius: 50%; background: #3d4a5c; color: #fff; display: grid; place-items: center; font-size: 22px; font-weight: 600; }
  .provider { font-size: 15px; font-weight: 600; color: #3d4a5c; margin: 0; overflow-wrap: anywhere; }
  h1 { font-size: 24px; font-weight: 500; margin: 12px 0 4px; text-align: center; }
  .lead { margin: 0 0 24px; text-align: center; color: #4a5260; overflow-wrap: anywhere; }
  .lead strong { color: #1f2329; font-weight: 600; }
  .accounts { list-style: none; margin: 0; padding: 0; border-block-start: 1px solid #e3e6eb; }
  .accounts li { border-block-end: 1px solid #e3e6eb; }
  .accounts form { margin: 0; }
  .account, .another > summary { inline-size: 100%; display: flex; align-items: center; gap: 12px; padding: 12px 8px; background: none; border: 0; font: inherit; color: inherit; text-align: start; cursor: pointer; border-radius: 6px; }
  .account:hover, .another > summary:hover { background: #f4f6f9; }
  .account:focus-visible, .another > summary:focus-visible, .link:focus-visible, .primary:focus-visible, input:focus-visible { outline: 2px solid #2f5fb3; outline-offset: 2px; }
  .avatar { flex: none; inline-size: 32px; block-size: 32px; border-radius: 50%; display: grid; place-items: center; color: #fff; font-weight: 600; font-size: 14px; }
  .avatar.add { background: #fff; color: #4a5260; border: 1px solid #c9ced6; font-size: 18px; font-weight: 400; }
  .who { display: flex; flex-direction: column; min-inline-size: 0; }
  .who .name { font-weight: 600; overflow-wrap: anywhere; }
  .who .email { color: #5b6370; font-size: 13px; overflow-wrap: anywhere; }
  .another { border-block-end: 1px solid #e3e6eb; }
  .another > summary { list-style: none; }
  .another > summary::-webkit-details-marker { display: none; }
  .another[open] > summary { color: #5b6370; }
  .another .fields { padding: 4px 8px 16px; }
  label { display: block; font-weight: 600; font-size: 13px; margin: 14px 0 6px; }
  .optional { font-weight: 400; color: #5b6370; }
  input[type=email], input[type=text] { inline-size: 100%; padding: 11px 12px; border: 1px solid #b9bfc9; border-radius: 6px; font: inherit; color: inherit; background: #fff; }
  .hint { color: #5b6370; font-size: 12px; margin: 6px 0 0; }
  .error { background: #fdf0ef; border: 1px solid #f1c5c0; color: #8c1d13; border-radius: 6px; padding: 8px 12px; margin: 0 0 16px; }
  .row { display: flex; justify-content: flex-end; margin-block-start: 20px; }
  .primary { background: #2f5fb3; color: #fff; border: 0; border-radius: 6px; padding: 10px 22px; font: inherit; font-weight: 600; cursor: pointer; }
  .primary:hover { background: #274f97; }
  .foot { display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center; gap: 8px 16px; margin-block-start: 24px; }
  .foot form { margin: 0; }
  .link { background: none; border: 0; padding: 4px 0; font: inherit; color: #2f5fb3; cursor: pointer; text-decoration: none; font-weight: 600; }
  .link:hover { text-decoration: underline; }
  .fine { color: #5b6370; font-size: 12px; margin: 16px 4px 0; overflow-wrap: anywhere; }
  .fine p { margin: 4px 0; }
  .fine code { background: #e6e9ee; padding: 1px 4px; border-radius: 3px; }
  @media (max-width: 480px) { .fine { margin-inline: 20px; } }
`;

// Neutral tones, all readable with white text.
const AVATAR_COLORS = [
  "#5a6b85",
  "#6b5a85",
  "#856b5a",
  "#5a8577",
  "#85775a",
  "#7a5a6b",
  "#4f7090",
  "#6f7a52",
];

const initial = (value: string) =>
  Array.from(value.trim())[0]?.toUpperCase() ?? "?";

const avatarColor = (email: string) =>
  AVATAR_COLORS[
    createHash("sha256").update(email.trim().toLowerCase()).digest()[0] %
      AVATAR_COLORS.length
  ];

export interface MockIdpSignInPage {
  provider: IdentityProviderConfig;
  stateId: string;
  accounts: MockAccount[];
  appName: string;
  redirectUri: string;
  realUrl: string;
  developerHref: string;
  error?: string;
  email?: string;
  name?: string;
}

const accountItem = (
  stateId: string,
  account: MockAccount,
) => `    <li><form method="POST" action="/oauth2/idpresponse">
${hiddenInput("state", stateId)}${hiddenInput("account_email", account.email)}${hiddenInput("account_name", account.name)}      <button type="submit" class="account" aria-label="Sign in as ${escapeHtml(account.name)}, ${escapeHtml(account.email)}">
        <span class="avatar" aria-hidden="true" style="background:${avatarColor(account.email)}">${escapeHtml(initial(account.name))}</span>
        <span class="who"><span class="name" dir="auto">${escapeHtml(account.name)}</span><span class="email" dir="auto">${escapeHtml(account.email)}</span></span>
      </button>
    </form></li>
`;

const newAccountFields = (input: MockIdpSignInPage, providerName: string) => `
${hiddenInput("state", input.stateId)}    <label for="account_email">Email</label>
    <input type="email" id="account_email" name="account_email" value="${escapeHtml(input.email)}" required autocomplete="email" spellcheck="false" placeholder="name@example.test"${input.error ? ' aria-invalid="true" aria-describedby="account_error"' : ""} />
    <label for="account_name">Name <span class="optional">(optional)</span></label>
    <input type="text" id="account_name" name="account_name" value="${escapeHtml(input.name)}" autocomplete="name" dir="auto" aria-describedby="account_name_hint" />
    <p class="hint" id="account_name_hint">Left empty, ${providerName} uses a name made from the email.</p>
    <div class="row"><button type="submit" class="primary">Continue</button></div>
`;

/** The mock IdP as the end user meets it: the provider's sign-in page with an account chooser. */
export function mockIdpSignInPage(input: MockIdpSignInPage): string {
  const providerName = escapeHtml(input.provider.ProviderName);
  const hasAccounts = input.accounts.length > 0;
  const errorBlock = input.error
    ? `<p class="error" id="account_error" role="alert">${escapeHtml(input.error)}</p>\n`
    : "";
  const newAccountForm = `<form method="POST" action="/oauth2/idpresponse">${newAccountFields(input, providerName)}  </form>`;
  const body = hasAccounts
    ? `  <ul class="accounts" aria-label="Accounts">
${input.accounts.map((account) => accountItem(input.stateId, account)).join("")}  </ul>
  <details class="another"${input.error ? " open" : ""}>
    <summary><span class="avatar add" aria-hidden="true">+</span><span>Use another account</span></summary>
    <div class="fields">${newAccountForm}</div>
  </details>`
    : newAccountForm;
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8" /><meta name="viewport" content="width=device-width, initial-scale=1" /><meta name="robots" content="noindex" /><title>Sign in with ${providerName} · ${PRODUCT_NAME}</title>${emulatorBannerStyle()}<style>${STYLE}</style></head>
<body>
${emulatorBanner()}
<main class="idp">
<div class="card">
  <div class="brand">
    <span class="mark" aria-hidden="true">${escapeHtml(initial(input.provider.ProviderName))}</span>
    <p class="provider" dir="auto">${providerName}</p>
  </div>
  <h1>${hasAccounts ? "Choose an account" : `Sign in with ${providerName}`}</h1>
  <p class="lead">to continue to <strong dir="auto">${escapeHtml(input.appName)}</strong></p>
  ${errorBlock}${body}
  <div class="foot">
    <form method="POST" action="/oauth2/idpresponse">
${hiddenInput("state", input.stateId)}      <input type="hidden" name="error_description" value="User cancelled the sign-in" />
      <button type="submit" class="link" name="error" value="access_denied">Cancel</button>
    </form>
    <a class="link" href="${escapeHtml(input.developerHref)}">Developer options: set the subject and every claim</a>
  </div>
</div>
<div class="fine">
  <p>A mock ${providerName} sign-in served by ${PRODUCT_NAME}: no ${providerName} account is needed and nothing leaves this machine. The same email signs in as the same ${providerName} user every time.</p>
  <p>Returns to <code>${escapeHtml(input.redirectUri)}</code>.${input.realUrl ? ` With real Amazon Cognito the browser would go to <code>${escapeHtml(input.realUrl)}</code> instead.` : ""}</p>
</div>
</main>
</body>
</html>`;
}
