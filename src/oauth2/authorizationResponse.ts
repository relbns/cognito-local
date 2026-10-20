import type { Response } from "express";
import type { Services, UserPoolService } from "../services";
import type { AppClient } from "../services/appClient";
import type { Context } from "../services/context";
import type { User } from "../services/userPoolService";
import type { AuthorizationCodeStore } from "./authorizationCodeStore";
import { type AuthorizeFlow, includesIdToken } from "./oauthRequest";

export interface AuthorizationResponseInput {
  appClient: AppClient;
  userPool: UserPoolService;
  user: User;
  redirectUri: string;
  state: string | undefined;
  flow: AuthorizeFlow;
}

export async function sendAuthorizationResponse(
  ctx: Context,
  res: Response,
  services: Pick<Services, "tokenGenerator">,
  codeStore: AuthorizationCodeStore,
  {
    appClient,
    userPool,
    user,
    redirectUri,
    state,
    flow,
  }: AuthorizationResponseInput,
): Promise<void> {
  const redirectUrl = new URL(redirectUri);

  if (flow.responseType === "token") {
    const userGroups = await userPool.listUserGroupMembership(ctx, user);
    const tokens = await services.tokenGenerator.generate(
      ctx,
      user,
      userGroups,
      appClient,
      undefined,
      "HostedAuth",
      flow.scopes,
    );
    const fragment = new URLSearchParams();
    if (includesIdToken(flow.scopes)) {
      fragment.set("id_token", tokens.IdToken);
    }
    fragment.set("access_token", tokens.AccessToken);
    fragment.set("token_type", "bearer");
    fragment.set("expires_in", "3600");
    if (state) fragment.set("state", state);
    redirectUrl.hash = fragment.toString();
    return res.redirect(redirectUrl.toString());
  }

  const code = codeStore.create({
    clientId: appClient.ClientId,
    userPoolId: userPool.options.Id,
    username: user.Username,
    redirectUri,
    codeChallenge: flow.codeChallenge,
    scope: flow.scopes.join(" "),
    state: state || undefined,
  });

  redirectUrl.searchParams.set("code", code);
  if (state) redirectUrl.searchParams.set("state", state);
  res.redirect(redirectUrl.toString());
}
