import type { AppClient } from "../services/appClient";
import type { ActiveAuthSession } from "../services/authSessions";
import type { CodeLogEntry, CodeType } from "../services/codeLog";
import { customAuthRound } from "../services/codeLog";
import {
  attributeValue,
  type Group,
  type User,
  type UserPool,
} from "../services/userPoolService";
import {
  ADMIN_UI_PATH,
  adminUrl,
  chips,
  copyButton,
  formatDate,
  html,
  type SafeHtml,
  statusBadge,
} from "./html";
import type { TokenInspection } from "./tokens";

export interface PoolSummary {
  pool: UserPool;
  users: number;
  clients: number;
  groups: number;
}

export interface EmulatorSummary {
  triggers: string[];
  issuerDomain?: string;
  authSessionValidityMinutes: number;
  codeLogSize: number;
}

const poolTitle = (pool: UserPool) => pool.Name ?? pool.Id;

const crumbs = (...items: (SafeHtml | string)[]) =>
  html`<div class="crumbs">${items.map((item, i) => html`${i ? " / " : ""}${item}`)}</div>`;

const poolCrumb = (pool: UserPool) =>
  html`<a href="${adminUrl("pools", pool.Id)}">${poolTitle(pool)}</a>`;

const poolsCrumb = html`<a href="${ADMIN_UI_PATH}">User pools</a>`;

const poolTabs = (
  pool: UserPool,
  active: "overview" | "users" | "groups",
  counts: { users?: number; groups?: number } = {},
) => html`<nav class="panel" style="padding:6px">
  <a href="${adminUrl("pools", pool.Id)}" class="${active === "overview" ? "active" : ""}">Overview</a>
  <a href="${adminUrl("pools", pool.Id, "users")}" class="${active === "users" ? "active" : ""}">Users${counts.users === undefined ? "" : ` (${counts.users})`}</a>
  <a href="${adminUrl("pools", pool.Id, "groups")}" class="${active === "groups" ? "active" : ""}">Groups${counts.groups === undefined ? "" : ` (${counts.groups})`}</a>
  <a href="${adminUrl("codes")}?pool=${encodeURIComponent(pool.Id)}">Codes</a>
</nav>`;

export const poolsPage = (
  pools: readonly PoolSummary[],
  emulator: EmulatorSummary,
) => html`
<h1>User pools</h1>
<p class="sub">Everything the emulator has stored, read straight from its data directory.</p>
<div class="panel">
  ${
    pools.length
      ? html`<div class="table-wrap"><table>
    <thead><tr><th>Name</th><th>Id</th><th>Users</th><th>App clients</th><th>Groups</th><th>Created</th></tr></thead>
    <tbody>${pools.map(
      (p) => html`<tr>
      <td><a href="${adminUrl("pools", p.pool.Id)}">${poolTitle(p.pool)}</a></td>
      <td><code>${p.pool.Id}</code> ${copyButton(p.pool.Id)}</td>
      <td><a href="${adminUrl("pools", p.pool.Id, "users")}">${p.users}</a></td>
      <td>${p.clients}</td>
      <td><a href="${adminUrl("pools", p.pool.Id, "groups")}">${p.groups}</a></td>
      <td class="muted">${formatDate(p.pool.CreationDate)}</td>
    </tr>`,
    )}</tbody></table></div>`
      : html`<p class="empty">No user pools yet. Create one through the API, e.g.
      <code>aws cognito-idp create-user-pool --pool-name local --endpoint-url http://localhost:9229</code>.</p>`
  }
</div>
<div class="panel">
  <h2>Emulator</h2>
  <dl>
    <dt>Trigger functions</dt><dd>${chips(emulator.triggers)}</dd>
    <dt>Token issuer domain</dt><dd><code>${emulator.issuerDomain ?? "request host"}</code></dd>
    <dt>CUSTOM_AUTH session validity</dt><dd>${emulator.authSessionValidityMinutes} min</dd>
    <dt>Codes kept in memory</dt><dd>last ${emulator.codeLogSize}</dd>
  </dl>
</div>`;

const passwordPolicy = (pool: UserPool) => {
  const p = pool.Policies?.PasswordPolicy;
  if (!p) return html`<span class="muted">default</span>`;
  const rules = [
    `min ${p.MinimumLength ?? 8}`,
    p.RequireUppercase ? "upper" : "",
    p.RequireLowercase ? "lower" : "",
    p.RequireNumbers ? "numbers" : "",
    p.RequireSymbols ? "symbols" : "",
  ].filter(Boolean);
  return chips(rules);
};

const yesNo = (value: boolean | undefined) =>
  value
    ? html`<span class="badge ok">yes</span>`
    : html`<span class="badge muted">no</span>`;

const clientPanel = (client: AppClient) => html`<div class="panel">
  <h2>${client.ClientName} <span class="muted mono" style="font-weight:400">${client.ClientId}</span> ${copyButton(client.ClientId)}</h2>
  <dl>
    <dt>Client secret</dt><dd>${
      client.ClientSecret
        ? html`<details><summary>show</summary><code>${client.ClientSecret}</code> ${copyButton(client.ClientSecret)}</details>`
        : html`<span class="muted">none (public client)</span>`
    }</dd>
    <dt>Auth flows</dt><dd>${chips(client.ExplicitAuthFlows)}</dd>
    <dt>OAuth enabled</dt><dd>${yesNo(client.AllowedOAuthFlowsUserPoolClient)}</dd>
    <dt>OAuth flows</dt><dd>${chips(client.AllowedOAuthFlows)}</dd>
    <dt>OAuth scopes</dt><dd>${chips(client.AllowedOAuthScopes)}</dd>
    <dt>Callback URLs</dt><dd>${chips(client.CallbackURLs)}</dd>
    <dt>Logout URLs</dt><dd>${chips(client.LogoutURLs)}</dd>
    <dt>Identity providers</dt><dd>${chips(client.SupportedIdentityProviders)}</dd>
    <dt>Token validity</dt><dd class="mono">access ${client.AccessTokenValidity ?? "default"} · id ${client.IdTokenValidity ?? "default"} · refresh ${client.RefreshTokenValidity ?? "default"}${client.TokenValidityUnits ? ` (${JSON.stringify(client.TokenValidityUnits)})` : ""}</dd>
    <dt>Created</dt><dd class="muted">${formatDate(client.CreationDate)}</dd>
  </dl>
</div>`;

export const poolPage = (opts: {
  pool: UserPool;
  clients: readonly AppClient[];
  users: number;
  groups: number;
}) => {
  const { pool } = opts;
  const triggers = Object.entries(pool.LambdaConfig ?? {})
    .filter(([, v]) => typeof v === "string" && v)
    .map(([k]) => k);
  const customAttributes = (pool.SchemaAttributes ?? [])
    .map((a) => a.Name ?? "")
    .filter((n) => n.startsWith("custom:"));
  return html`
${crumbs(poolsCrumb)}
<h1>${poolTitle(pool)}</h1>
<p class="sub"><code>${pool.Id}</code> ${copyButton(pool.Id)}</p>
${poolTabs(pool, "overview", { users: opts.users, groups: opts.groups })}
<div class="panel">
  <h2>Settings</h2>
  <dl>
    <dt>ARN</dt><dd><code>${pool.Arn ?? ""}</code></dd>
    <dt>Username attributes</dt><dd>${chips(pool.UsernameAttributes)}</dd>
    <dt>Alias attributes</dt><dd>${chips(pool.AliasAttributes)}</dd>
    <dt>Auto-verified</dt><dd>${chips(pool.AutoVerifiedAttributes)}</dd>
    <dt>MFA</dt><dd>${pool.MfaConfiguration ?? "OFF"}</dd>
    <dt>Password policy</dt><dd>${passwordPolicy(pool)}</dd>
    <dt>Admin-only sign-up</dt><dd>${yesNo(pool.AdminCreateUserConfig?.AllowAdminCreateUserOnly)}</dd>
    <dt>Lambda triggers</dt><dd>${chips(triggers)}</dd>
    <dt>Custom attributes</dt><dd>${chips(customAttributes)}</dd>
    <dt>Domain</dt><dd>${pool.Domain ?? html`<span class="muted">none</span>`}</dd>
    <dt>Created</dt><dd class="muted">${formatDate(pool.CreationDate)}</dd>
    <dt>Last modified</dt><dd class="muted">${formatDate(pool.LastModifiedDate)}</dd>
  </dl>
</div>
<h2>App clients (${opts.clients.length})</h2>
${opts.clients.length ? opts.clients.map(clientPanel) : html`<div class="panel empty">No app clients.</div>`}`;
};

export const USER_STATUSES = [
  "UNCONFIRMED",
  "CONFIRMED",
  "FORCE_CHANGE_PASSWORD",
  "RESET_REQUIRED",
  "EXTERNAL_PROVIDER",
];

const userLink = (poolId: string, username: string) =>
  html`<a href="${adminUrl("pools", poolId, "users", username)}">${username}</a>`;

export const usersPage = (opts: {
  pool: UserPool;
  users: readonly User[];
  total: number;
  groupsByUser: Map<string, string[]>;
  groupCount: number;
  q: string;
  status: string;
}) => {
  const { pool } = opts;
  return html`
${crumbs(poolsCrumb, poolCrumb(pool))}
<h1>Users</h1>
<p class="sub">${opts.users.length} of ${opts.total} users in <code>${pool.Id}</code></p>
${poolTabs(pool, "users", { users: opts.total, groups: opts.groupCount })}
<div class="panel">
  <form method="GET" class="row">
    <label>Search username, email, phone or sub<input type="search" name="q" value="${opts.q}" autofocus /></label>
    <label>Status<select name="status"><option value="">any</option>${USER_STATUSES.map(
      (s) =>
        html`<option value="${s}" ${opts.status === s ? "selected" : ""}>${s}</option>`,
    )}</select></label>
    <button class="primary" type="submit">Filter</button>
    ${opts.q || opts.status ? html`<a href="${adminUrl("pools", pool.Id, "users")}">clear</a>` : ""}
  </form>
</div>
<div class="panel">
  ${
    opts.users.length
      ? html`<div class="table-wrap"><table>
    <thead><tr><th>Username</th><th>Email</th><th>Phone</th><th>Status</th><th>Enabled</th><th>Groups</th><th>Created</th></tr></thead>
    <tbody>${opts.users.map(
      (u) => html`<tr>
      <td>${userLink(pool.Id, u.Username)}</td>
      <td>${attributeValue("email", u.Attributes) ?? ""}</td>
      <td>${attributeValue("phone_number", u.Attributes) ?? ""}</td>
      <td>${statusBadge(u.UserStatus)}</td>
      <td>${u.Enabled === false ? html`<span class="badge err">disabled</span>` : html`<span class="badge ok">enabled</span>`}</td>
      <td>${chips(opts.groupsByUser.get(u.Username))}</td>
      <td class="muted">${formatDate(u.UserCreateDate)}</td>
    </tr>`,
    )}</tbody></table></div>`
      : html`<p class="empty">No users match.</p>`
  }
</div>
<details class="panel">
  <summary><strong>Create user</strong> <span class="muted">(AdminCreateUser)</span></summary>
  <form method="POST" action="${adminUrl("pools", pool.Id, "users")}" style="margin-top:12px">
    <div class="row">
      <label>Username<input name="username" required /></label>
      <label>Email<input name="email" type="email" /></label>
      <label>Phone (E.164)<input name="phone_number" placeholder="+15555550100" /></label>
      <label>Password<input name="password" placeholder="generated if empty" /></label>
    </div>
    <label style="margin-top:8px">Extra attributes, one <code>name=value</code> per line<textarea name="attributes" style="min-height:60px" placeholder="custom:context=42"></textarea></label>
    <div class="row" style="margin-top:8px">
      <label class="check"><input type="checkbox" name="permanent" value="1" checked /> Password is permanent (status CONFIRMED)</label>
      <label class="check"><input type="checkbox" name="verified" value="1" checked /> Mark email/phone verified</label>
      <label class="check"><input type="checkbox" name="send" value="1" /> Send welcome message</label>
      <button class="primary" type="submit">Create</button>
    </div>
  </form>
</details>`;
};

const STORED_CODE_FIELDS = [
  ["ConfirmationCode", "Confirmation / reset code"],
  ["MFACode", "SMS MFA code"],
  ["AttributeVerificationCode", "Attribute verification code"],
] as const;

export const userPage = (opts: {
  pool: UserPool;
  user: User;
  groups: readonly string[];
  allGroups: readonly Group[];
  recentCodes: readonly CodeLogEntry[];
}) => {
  const { pool, user } = opts;
  const base = adminUrl("pools", pool.Id, "users", user.Username);
  const storedCodes = STORED_CODE_FIELDS.filter(([field]) => user[field]);
  const addable = opts.allGroups.filter(
    (g) => !opts.groups.includes(g.GroupName),
  );
  return html`
${crumbs(poolsCrumb, poolCrumb(pool), html`<a href="${adminUrl("pools", pool.Id, "users")}">Users</a>`)}
<h1>${user.Username} ${copyButton(user.Username)}</h1>
<p class="sub">${statusBadge(user.UserStatus)} ${user.Enabled === false ? html`<span class="badge err">disabled</span>` : html`<span class="badge ok">enabled</span>`}</p>
<div class="grid">
  <div class="panel">
    <h2>Attributes</h2>
    <div class="table-wrap"><table><tbody>${(user.Attributes ?? []).map(
      (a) =>
        html`<tr><td class="muted mono">${a.Name}</td><td class="mono">${a.Value ?? ""}</td></tr>`,
    )}</tbody></table></div>
  </div>
  <div class="panel">
    <h2>Account</h2>
    <dl>
      <dt>Created</dt><dd>${formatDate(user.UserCreateDate)}</dd>
      <dt>Last modified</dt><dd>${formatDate(user.UserLastModifiedDate)}</dd>
      <dt>MFA methods</dt><dd>${chips(user.UserMFASettingList)}</dd>
      <dt>Preferred MFA</dt><dd>${user.PreferredMfaSetting ?? html`<span class="muted">none</span>`}</dd>
      <dt>TOTP</dt><dd>${user.SoftwareTokenMfaConfiguration ? (user.SoftwareTokenMfaConfiguration.Verified ? "verified" : "associated, not verified") : html`<span class="muted">none</span>`}</dd>
      <dt>Refresh tokens</dt><dd>${(user.RefreshTokens ?? []).length}</dd>
    </dl>
    ${
      storedCodes.length
        ? html`<h2 style="margin-top:16px">Pending codes on the user</h2><dl>${storedCodes.map(
            ([field, label]) =>
              html`<dt>${label}</dt><dd><span class="code">${user[field]}</span> ${copyButton(user[field])}</dd>`,
          )}</dl>`
        : ""
    }
  </div>
</div>
<div class="grid">
  <div class="panel">
    <h2>Groups</h2>
    ${
      opts.groups.length
        ? html`<table><tbody>${opts.groups.map(
            (g) => html`<tr><td>${g}</td><td style="text-align:right">
          <form class="inline" method="POST" action="${base}/groups/remove">
            <input type="hidden" name="group" value="${g}" />
            <button class="link" type="submit">remove</button>
          </form></td></tr>`,
          )}</tbody></table>`
        : html`<p class="empty">Not in any group.</p>`
    }
    ${
      addable.length
        ? html`<form method="POST" action="${base}/groups/add" class="row" style="margin-top:8px">
      <label>Add to group<select name="group">${addable.map(
        (g) => html`<option value="${g.GroupName}">${g.GroupName}</option>`,
      )}</select></label>
      <button type="submit">Add</button>
    </form>`
        : ""
    }
  </div>
  <div class="panel">
    <h2>Actions</h2>
    <div class="row" style="margin-bottom:12px">
      ${
        user.UserStatus === "UNCONFIRMED"
          ? html`<form class="inline" method="POST" action="${base}/confirm"><button class="primary" type="submit">Confirm sign-up</button></form>`
          : ""
      }
      ${
        user.Enabled === false
          ? html`<form class="inline" method="POST" action="${base}/enable"><button type="submit">Enable</button></form>`
          : html`<form class="inline" method="POST" action="${base}/disable"><button type="submit">Disable</button></form>`
      }
      <form class="inline" method="POST" action="${base}/delete" data-confirm="Delete user ${user.Username}?"><button class="danger" type="submit">Delete</button></form>
    </div>
    <form method="POST" action="${base}/password" class="row">
      <label>New password<input name="password" required /></label>
      <label class="check"><input type="checkbox" name="permanent" value="1" checked /> permanent</label>
      <button type="submit">Set password</button>
    </form>
  </div>
</div>
<div class="panel">
  <h2>Recent codes for this user</h2>
  ${codesTable(opts.recentCodes, false)}
</div>`;
};

export const groupsPage = (opts: {
  pool: UserPool;
  groups: readonly Group[];
  users: number;
}) => {
  const { pool } = opts;
  return html`
${crumbs(poolsCrumb, poolCrumb(pool))}
<h1>Groups</h1>
<p class="sub">${opts.groups.length} groups in <code>${pool.Id}</code></p>
${poolTabs(pool, "groups", { users: opts.users, groups: opts.groups.length })}
<div class="panel">
  ${
    opts.groups.length
      ? html`<div class="table-wrap"><table>
    <thead><tr><th>Name</th><th>Description</th><th>Precedence</th><th>Members</th><th>Created</th></tr></thead>
    <tbody>${opts.groups.map(
      (g) => html`<tr>
      <td><strong>${g.GroupName}</strong></td>
      <td>${g.Description ?? ""}</td>
      <td>${g.Precedence ?? ""}</td>
      <td>${
        g.members?.length
          ? html`<span class="chips">${g.members.map((m) => userLink(pool.Id, m))}</span>`
          : html`<span class="muted">none</span>`
      }</td>
      <td class="muted">${formatDate(g.CreationDate)}</td>
    </tr>`,
    )}</tbody></table></div>`
      : html`<p class="empty">No groups.</p>`
  }
</div>
<details class="panel">
  <summary><strong>Create group</strong> <span class="muted">(CreateGroup)</span></summary>
  <form method="POST" action="${adminUrl("pools", pool.Id, "groups")}" class="row" style="margin-top:12px">
    <label>Name<input name="name" required /></label>
    <label>Description<input name="description" /></label>
    <label>Precedence<input name="precedence" type="number" min="0" style="width:110px" /></label>
    <button class="primary" type="submit">Create</button>
  </form>
</details>`;
};

export const CODE_TYPES: Record<CodeType, string> = {
  SIGN_UP: "Sign-up confirmation",
  FORGOT_PASSWORD: "Forgot password",
  MFA: "SMS MFA",
  TEMPORARY_PASSWORD: "Temporary password",
  ATTRIBUTE_VERIFICATION: "Attribute verification",
  CUSTOM_AUTH: "CUSTOM_AUTH challenge",
};

const params = (value: Record<string, string> | undefined) =>
  value && Object.keys(value).length
    ? html`<code>${JSON.stringify(value)}</code>`
    : "";

const codesTable = (entries: readonly CodeLogEntry[], showPool: boolean) =>
  entries.length
    ? html`<div class="table-wrap"><table>
  <thead><tr><th>Time</th><th>Type</th><th>Code</th><th>User</th>${showPool ? html`<th>Pool</th>` : ""}<th>Delivery / details</th></tr></thead>
  <tbody>${entries.map(
    (e) => html`<tr>
    <td class="muted" title="${formatDate(e.at)}">${formatDate(e.at)}</td>
    <td><span class="badge${e.type === "CUSTOM_AUTH" ? " warn" : ""}">${CODE_TYPES[e.type]}</span>${e.round ? html` <span class="muted">round ${e.round}</span>` : ""}</td>
    <td>${e.code ? html`<span class="code">${e.code}</span> ${copyButton(e.code)}` : html`<span class="muted">none</span>`}</td>
    <td>${userLink(e.userPoolId, e.username)}${e.email || e.phoneNumber ? html`<div class="muted">${[e.email, e.phoneNumber].filter(Boolean).join(" · ")}</div>` : ""}</td>
    ${showPool ? html`<td><code>${e.userPoolId}</code></td>` : ""}
    <td>${e.deliveryMedium ? html`${e.deliveryMedium} to ${e.destination ?? ""}` : ""}${params(e.privateChallengeParameters)}${e.expiresAt ? html`<div class="muted">session expires ${formatDate(e.expiresAt)}</div>` : ""}<div class="muted">${e.source}</div></td>
  </tr>`,
  )}</tbody></table></div>`
    : html`<p class="empty">No codes yet.</p>`;

export const codesPage = (opts: {
  entries: readonly CodeLogEntry[];
  sessions: readonly ActiveAuthSession[];
  pools: readonly UserPool[];
  filters: { pool: string; type: string; q: string };
  enabled: boolean;
  capacity: number;
}) => html`
<h1>Codes</h1>
<p class="sub">Codes the emulator produced or saw since it started, newest first (in memory, last ${opts.capacity}). JSON for scripts: <a href="${adminUrl("api", "codes")}"><code>${adminUrl("api", "codes")}</code></a></p>
<div class="panel">
  <form method="GET" class="row">
    <label>Pool<select name="pool"><option value="">all</option>${opts.pools.map(
      (p) =>
        html`<option value="${p.Id}" ${opts.filters.pool === p.Id ? "selected" : ""}>${poolTitle(p)} (${p.Id})</option>`,
    )}</select></label>
    <label>Type<select name="type"><option value="">all</option>${Object.entries(
      CODE_TYPES,
    ).map(
      ([k, v]) =>
        html`<option value="${k}" ${opts.filters.type === k ? "selected" : ""}>${v}</option>`,
    )}</select></label>
    <label>User, email, phone or code<input type="search" name="q" value="${opts.filters.q}" /></label>
    <button class="primary" type="submit">Filter</button>
    <label class="check"><input type="checkbox" id="autorefresh" /> auto-refresh</label>
  </form>
</div>
<div class="panel">
  <h2>Active CUSTOM_AUTH sessions (${opts.sessions.length})</h2>
  ${
    opts.sessions.length
      ? html`<div class="table-wrap"><table>
    <thead><tr><th>Session</th><th>User</th><th>Challenge</th><th>Private challenge parameters</th><th>Expires in</th></tr></thead>
    <tbody>${opts.sessions.map(
      (s) => html`<tr>
      <td><code>${s.id.slice(0, 8)}</code></td>
      <td>${userLink(s.session.userPoolId, s.session.username)}<div class="muted mono">${s.session.clientId}</div></td>
      <td>${s.session.pendingChallenge.challengeName} <span class="muted">round ${customAuthRound(s.session)}</span></td>
      <td>${
        s.session.pendingChallenge.privateChallengeParameters.secretLoginCode
          ? html`<span class="code">${s.session.pendingChallenge.privateChallengeParameters.secretLoginCode}</span> ${copyButton(s.session.pendingChallenge.privateChallengeParameters.secretLoginCode)}<br />`
          : ""
      }${params(s.session.pendingChallenge.privateChallengeParameters)}</td>
      <td><span data-expires="${s.expiresAt.toISOString()}">${formatDate(s.expiresAt)}</span></td>
    </tr>`,
    )}</tbody></table></div>`
      : html`<p class="empty">No active sessions.</p>`
  }
</div>
<div class="panel">
  <h2>Recent codes (${opts.entries.length})</h2>
  ${opts.enabled ? codesTable(opts.entries, true) : html`<p class="empty">The code log is not wired into this server.</p>`}
</div>`;

export const tokensPage = (opts: {
  pools: readonly UserPool[];
  token: string;
  poolId: string;
  resolvedPoolId?: string;
  result?: TokenInspection;
}) => html`
<h1>Tokens</h1>
<p class="sub">Paste an access or id token to decode it and verify it against the pool's JWKS. The token is posted to this emulator only.</p>
<form method="POST" class="panel">
  <label>JWT<textarea name="token" required spellcheck="false" autocomplete="off">${opts.token}</textarea></label>
  <div class="row" style="margin-top:8px">
    <label>Verify against pool<select name="pool"><option value="">from the iss claim</option>${opts.pools.map(
      (p) =>
        html`<option value="${p.Id}" ${opts.poolId === p.Id ? "selected" : ""}>${poolTitle(p)} (${p.Id})</option>`,
    )}</select></label>
    <button class="primary" type="submit">Decode and verify</button>
  </div>
</form>
${
  opts.result
    ? opts.result.error
      ? html`<div class="flash error" role="alert">${opts.result.error}</div>`
      : html`
<div class="panel">
  <h2>Verification${opts.resolvedPoolId ? html` against <code>${opts.resolvedPoolId}</code>` : html` <span class="muted">(no pool matched; signature only)</span>`}</h2>
  <table><tbody>${opts.result.checks.map(
    (c) =>
      html`<tr><td class="${c.ok ? "check-ok" : "check-fail"}">${c.ok ? "pass" : "fail"}</td><td>${c.name}</td><td class="muted">${c.detail}</td></tr>`,
  )}</tbody></table>
</div>
<div class="grid">
  <div class="panel"><h2>Header</h2><pre>${JSON.stringify(opts.result.header, null, 2)}</pre></div>
  <div class="panel"><h2>Claims</h2><pre>${JSON.stringify(opts.result.payload, null, 2)}</pre></div>
</div>`
    : ""
}`;

export const errorPage = (title: string, message: string) => html`
${crumbs(poolsCrumb)}
<h1>${title}</h1>
<div class="panel"><p>${message}</p></div>`;
