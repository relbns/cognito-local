import type {
  CreateGroupRequest,
  CreateGroupResponse,
} from "aws-sdk/clients/cognitoidentityserviceprovider";
import { GroupExistsError } from "../errors";
import type { Services } from "../services";
import type { Group } from "../services/userPoolService";
import { groupToResponseObject } from "./responses";
import type { Target } from "./Target";

export type CreateGroupTarget = Target<CreateGroupRequest, CreateGroupResponse>;

type CreateGroupServices = Pick<Services, "clock" | "cognito">;

export const CreateGroup =
  ({ cognito, clock }: CreateGroupServices): CreateGroupTarget =>
  async (ctx, req) => {
    const userPool = await cognito.getUserPool(ctx, req.UserPoolId);
    if (await userPool.getGroupByGroupName(ctx, req.GroupName)) {
      throw new GroupExistsError(req.GroupName);
    }

    const now = clock.get();
    const group: Group = {
      CreationDate: now,
      Description: req.Description,
      GroupName: req.GroupName,
      LastModifiedDate: now,
      Precedence: req.Precedence,
      RoleArn: req.RoleArn,
    };

    await userPool.saveGroup(ctx, group);

    return {
      Group: groupToResponseObject(req.UserPoolId)(group),
    };
  };
