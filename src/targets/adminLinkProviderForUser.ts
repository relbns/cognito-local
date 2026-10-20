import type {
  AdminLinkProviderForUserRequest,
  AdminLinkProviderForUserResponse,
} from "@aws-sdk/client-cognito-identity-provider";
import { UserNotFoundError } from "../errors";
import {
  COGNITO_SUBJECT,
  type FederatedIdentity,
  identitiesOf,
  identityProvidersOf,
  newIdentity,
} from "../oauth2/federation";
import type { Services } from "../services";
import { attribute, attributesAppend } from "../services/userPoolService";
import type { Target } from "./Target";

export type AdminLinkProviderForUserTarget = Target<
  AdminLinkProviderForUserRequest,
  AdminLinkProviderForUserResponse
>;

type AdminLinkProviderForUserServices = Pick<Services, "cognito" | "clock">;

export const AdminLinkProviderForUser =
  ({
    cognito,
    clock,
  }: AdminLinkProviderForUserServices): AdminLinkProviderForUserTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    const user = await userPool.getUserByUsername(
      ctx,
      req.DestinationUser?.ProviderAttributeValue ?? "",
    );
    if (!user) {
      throw new UserNotFoundError();
    }

    const providerName = req.SourceUser?.ProviderName ?? "";
    const providerValue = req.SourceUser?.ProviderAttributeValue ?? "";
    const attributeName =
      req.SourceUser?.ProviderAttributeName ?? COGNITO_SUBJECT;
    const provider = identityProvidersOf(userPool.options).find(
      (p) => p.ProviderName === providerName,
    ) ?? { ProviderName: providerName, ProviderType: providerName };

    const now = clock.get();
    const identities: FederatedIdentity[] = [
      ...identitiesOf(user.Attributes).filter(
        (identity) =>
          !(
            identity.providerName === providerName &&
            String(identity.userId) === providerValue
          ),
      ),
      newIdentity(provider, providerValue, false, now),
    ];
    const links = (user.ProviderLinks ?? []).filter(
      (link) =>
        !(
          link.providerName === providerName &&
          link.attributeName === attributeName &&
          link.attributeValue === providerValue
        ),
    );

    await userPool.saveUser(ctx, {
      ...user,
      Attributes: attributesAppend(
        user.Attributes,
        attribute("identities", JSON.stringify(identities)),
      ),
      ProviderLinks: [
        ...links,
        { providerName, attributeName, attributeValue: providerValue },
      ],
      UserLastModifiedDate: now,
    });

    return {};
  };
