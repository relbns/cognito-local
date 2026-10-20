import * as uuid from "uuid";
import { InvalidParameterError, NotAuthorizedError } from "../errors";
import type { Services, UserPoolService } from "../services";
import type { AppClient } from "../services/appClient";
import type { Context } from "../services/context";
import {
  attribute,
  attributesAppend,
  attributeValue,
  type User,
} from "../services/userPoolService";
import {
  type Claims,
  federatedUserId,
  federatedUsername,
  findLinkedUser,
  type IdentityProviderConfig,
  mapAttributes,
  newIdentity,
} from "./federation";

type FederatedSignInServices = Pick<Services, "clock" | "triggers">;

export interface FederatedSignInResult {
  user: User;
  outcome: "created" | "existing" | "linked";
}

async function signInExisting(
  ctx: Context,
  { clock, triggers }: FederatedSignInServices,
  userPool: UserPoolService,
  appClient: AppClient,
  user: User,
  mapped: User["Attributes"],
): Promise<User> {
  if (!user.Enabled) throw new NotAuthorizedError("User is disabled.");
  const updated: User = {
    ...user,
    Attributes: attributesAppend(user.Attributes, ...mapped),
    UserLastModifiedDate: clock.get(),
  };
  await userPool.saveUser(ctx, updated);

  if (triggers.enabled("PostAuthentication", userPool.options.Id)) {
    await triggers.postAuthentication(ctx, {
      clientId: appClient.ClientId,
      clientMetadata: undefined,
      source: "PostAuthentication_Authentication",
      userAttributes: updated.Attributes,
      username: updated.Username,
      userPoolId: userPool.options.Id,
    });
  }
  return updated;
}

export async function federatedSignIn(
  ctx: Context,
  services: FederatedSignInServices,
  userPool: UserPoolService,
  appClient: AppClient,
  provider: IdentityProviderConfig,
  claims: Claims,
): Promise<FederatedSignInResult> {
  const { clock, triggers } = services;
  const userId = federatedUserId(provider, claims);
  if (!userId) {
    throw new InvalidParameterError(
      `The identity provider response has no subject for ${provider.ProviderName}`,
    );
  }
  const providerName = provider.ProviderName;
  const username = federatedUsername(providerName, userId);
  const mapped = mapAttributes(provider, claims);

  const findLinked = async () =>
    findLinkedUser(await userPool.listUsers(ctx), providerName, userId, claims);

  const linked = await findLinked();
  if (linked) {
    const user = await signInExisting(
      ctx,
      services,
      userPool,
      appClient,
      linked,
      mapped,
    );
    return { user, outcome: "linked" };
  }

  const existing = await userPool.getUserByUsername(ctx, username);
  if (existing && existing.Username === username) {
    const user = await signInExisting(
      ctx,
      services,
      userPool,
      appClient,
      existing,
      mapped,
    );
    return { user, outcome: "existing" };
  }

  let attributes = mapped;
  if (triggers.enabled("PreSignUp", userPool.options.Id)) {
    const response = await triggers.preSignUp(ctx, {
      clientId: appClient.ClientId,
      clientMetadata: undefined,
      source: "PreSignUp_ExternalProvider",
      userAttributes: mapped,
      username,
      userPoolId: userPool.options.Id,
      validationData: undefined,
    });

    const linkedByTrigger = await findLinked();
    if (linkedByTrigger) {
      const user = await signInExisting(
        ctx,
        services,
        userPool,
        appClient,
        linkedByTrigger,
        mapped,
      );
      return { user, outcome: "linked" };
    }

    if (response?.autoVerifyEmail && attributeValue("email", attributes)) {
      attributes = attributesAppend(
        attributes,
        attribute("email_verified", "true"),
      );
    }
    if (
      response?.autoVerifyPhone &&
      attributeValue("phone_number", attributes)
    ) {
      attributes = attributesAppend(
        attributes,
        attribute("phone_number_verified", "true"),
      );
    }
  }

  const now = clock.get();
  const user: User = {
    Username: username,
    Attributes: [
      attribute("sub", uuid.v4()),
      ...attributes.filter((attr) => attr.Name !== "sub"),
      attribute(
        "identities",
        JSON.stringify([newIdentity(provider, userId, true, now)]),
      ),
    ],
    Enabled: true,
    UserStatus: "EXTERNAL_PROVIDER",
    Password: "",
    RefreshTokens: [],
    UserCreateDate: now,
    UserLastModifiedDate: now,
  };
  await userPool.saveUser(ctx, user);

  if (triggers.enabled("PostConfirmation", userPool.options.Id)) {
    await triggers.postConfirmation(ctx, {
      clientId: appClient.ClientId,
      clientMetadata: undefined,
      source: "PostConfirmation_ConfirmSignUp",
      userAttributes: user.Attributes,
      username: user.Username,
      userPoolId: userPool.options.Id,
    });
  }
  return { user, outcome: "created" };
}
