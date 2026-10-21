import type {
  AddCustomAttributesRequest,
  AddCustomAttributesResponse,
  SchemaAttributeType,
} from "@aws-sdk/client-cognito-identity-provider";
import { InvalidParameterError } from "../errors";
import type { Services } from "../services";
import { customAttributeName } from "./createUserPool";
import type { Target } from "./Target";
import { assertParameterLength } from "./utils/assertions";

export type AddCustomAttributesTarget = Target<
  AddCustomAttributesRequest,
  AddCustomAttributesResponse
>;

type AddCustomAttributesServices = Pick<Services, "clock" | "cognito">;

export const AddCustomAttributes =
  ({
    clock,
    cognito,
  }: AddCustomAttributesServices): AddCustomAttributesTarget =>
  async (ctx, req) => {
    assertParameterLength("CustomAttributes", 1, 25, req.CustomAttributes);

    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);

    await userPool.updateOptions(ctx, {
      ...userPool.options,
      SchemaAttributes: [
        ...(userPool.options.SchemaAttributes ?? []),
        ...req.CustomAttributes.map(
          ({ Name, ...attr }): SchemaAttributeType => {
            const name = customAttributeName(Name, attr.DeveloperOnlyAttribute);

            if (
              userPool.options.SchemaAttributes?.find(
                (x) =>
                  x.Name === `custom:${Name}` ||
                  x.Name === `dev:custom:${Name}`,
              )
            ) {
              throw new InvalidParameterError(
                `${name}: Existing attribute already has name ${name}.`,
              );
            }

            return {
              AttributeDataType: "String",
              DeveloperOnlyAttribute: false,
              Mutable: true,
              Required: false,
              StringAttributeConstraints: {},
              Name: name,
              ...attr,
            };
          },
        ),
      ],
      LastModifiedDate: clock.get(),
    });

    return {};
  };
