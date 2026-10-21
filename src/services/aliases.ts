import { AliasExistsError, UsernameExistsError } from "../errors";
import type { Clock } from "./clock";
import type { Context } from "./context";
import type { Attribute } from "./sdkTypes";
import {
  attribute,
  attributesAppend,
  attributeValue,
  type User,
  type UserPoolService,
  usernameComparer,
} from "./userPoolService";

const VERIFIED_FLAG: Record<string, string> = {
  email: "email_verified",
  phone_number: "phone_number_verified",
};

export interface AliasConflict {
  attributeName: string;
  kind: "alias" | "username";
  user: User;
}

// Email and phone aliases only count once verified; preferred_username always counts.
export const isActiveAlias = (
  attributeName: string,
  attributes: Attribute[] | undefined,
): boolean => {
  if (!attributeValue(attributeName, attributes)) {
    return false;
  }
  const flag = VERIFIED_FLAG[attributeName];
  return !flag || attributeValue(flag, attributes) === "true";
};

export const aliasAttributesTouchedBy = (attributes: Attribute[]): string[] => {
  const touched = new Set<string>();
  for (const { Name } of attributes) {
    const base = Name.replace(/_verified$/, "");
    if (["email", "phone_number", "preferred_username"].includes(base)) {
      touched.add(base);
    }
  }
  return [...touched];
};

export const findAliasConflicts = async (
  ctx: Context,
  userPool: UserPoolService,
  username: string,
  attributes: Attribute[],
  attributeNames?: readonly string[],
): Promise<AliasConflict[]> => {
  const inScope = (name: string) =>
    !attributeNames || attributeNames.includes(name);
  const aliasAttributes = (userPool.options.AliasAttributes ?? []).filter(
    inScope,
  );
  const usernameAttributes = (userPool.options.UsernameAttributes ?? []).filter(
    inScope,
  );
  if (!aliasAttributes.length && !usernameAttributes.length) {
    return [];
  }

  const otherUsers = (await userPool.listUsers(ctx)).filter(
    (u) => u.Username !== username,
  );
  const conflicts: AliasConflict[] = [];
  const foldUsername = usernameComparer(userPool.options);
  const fold = (name: string) =>
    name === "phone_number"
      ? (value: string | undefined) => value
      : foldUsername;

  for (const name of aliasAttributes) {
    if (!isActiveAlias(name, attributes)) continue;
    const value = fold(name)(attributeValue(name, attributes));
    for (const user of otherUsers) {
      if (
        isActiveAlias(name, user.Attributes) &&
        fold(name)(attributeValue(name, user.Attributes)) === value
      ) {
        conflicts.push({ attributeName: name, kind: "alias", user });
      }
    }
  }

  for (const name of usernameAttributes) {
    const value = fold(name)(attributeValue(name, attributes));
    if (!value) continue;
    for (const user of otherUsers) {
      if (fold(name)(attributeValue(name, user.Attributes)) === value) {
        conflicts.push({ attributeName: name, kind: "username", user });
      }
    }
  }

  return conflicts;
};

export interface EnforceAliasUniquenessOptions {
  attributeNames?: readonly string[];
  forceAliasCreation?: boolean;
  usernameConflict?: "AliasExistsException" | "UsernameExistsException";
}

/**
 * Throws when attributes would duplicate another user's active alias or username attribute. With
 * forceAliasCreation, a verified email/phone alias moves here and is marked unverified on the other user.
 */
export const enforceAliasUniqueness = async (
  ctx: Context,
  userPool: UserPoolService,
  clock: Clock,
  username: string,
  attributes: Attribute[],
  {
    attributeNames,
    forceAliasCreation = false,
    usernameConflict = "AliasExistsException",
  }: EnforceAliasUniquenessOptions = {},
): Promise<void> => {
  const conflicts = await findAliasConflicts(
    ctx,
    userPool,
    username,
    attributes,
    attributeNames,
  );

  const blocking = conflicts.find(
    (c) =>
      c.kind === "username" ||
      !forceAliasCreation ||
      !VERIFIED_FLAG[c.attributeName],
  );
  if (blocking) {
    if (
      blocking.kind === "username" &&
      usernameConflict === "UsernameExistsException"
    ) {
      throw new UsernameExistsError(
        `An account with the given ${blocking.attributeName} already exists.`,
      );
    }
    throw new AliasExistsError(blocking.attributeName);
  }

  for (const conflict of conflicts) {
    const current =
      (await userPool.getUserByUsername(ctx, conflict.user.Username)) ??
      conflict.user;
    await userPool.saveUser(ctx, {
      ...current,
      Attributes: attributesAppend(
        current.Attributes,
        attribute(VERIFIED_FLAG[conflict.attributeName], "false"),
      ),
      UserLastModifiedDate: clock.get(),
    });
  }
};
