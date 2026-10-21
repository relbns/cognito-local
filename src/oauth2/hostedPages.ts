import type { AppClient } from "../services/appClient";
import type { Attribute } from "../services/sdkTypes";
import { computeSecretHash } from "../services/tokenVerifier";
import type { UserPool } from "../services/userPoolService";

export const HOSTED_PAGE_MESSAGES = {
  signUpNotPermitted: "SignUp is not permitted for this user pool",
  usernameRequired: "Username cannot be empty.",
  passwordRequired: "Password cannot be empty.",
  codeRequired: "Enter the code.",
  codeResent: "We have sent a new code.",
  accountConfirmed: "Your account is confirmed. Sign in to continue.",
  awaitingConfirmation:
    "Your account was created. An administrator must confirm it before you can sign in.",
  passwordReset:
    "Your password has been reset. Sign in with your new password.",
} as const;

export interface FormField {
  name: string;
  label: string;
  type: string;
  autocomplete: string;
}

type PoolForPages = Pick<
  UserPool,
  "AdminCreateUserConfig" | "SchemaAttributes" | "UsernameAttributes"
>;

const ATTRIBUTE_INPUTS: Record<
  string,
  { label: string; type?: string; autocomplete: string }
> = {
  address: { label: "Address", autocomplete: "street-address" },
  birthdate: { label: "Birthdate", type: "date", autocomplete: "bday" },
  email: { label: "Email", type: "email", autocomplete: "email" },
  family_name: { label: "Family name", autocomplete: "family-name" },
  gender: { label: "Gender", autocomplete: "sex" },
  given_name: { label: "Given name", autocomplete: "given-name" },
  locale: { label: "Locale", autocomplete: "language" },
  middle_name: { label: "Middle name", autocomplete: "additional-name" },
  name: { label: "Name", autocomplete: "name" },
  nickname: { label: "Nickname", autocomplete: "nickname" },
  phone_number: { label: "Phone number", type: "tel", autocomplete: "tel" },
  picture: { label: "Picture", type: "url", autocomplete: "photo" },
  preferred_username: {
    label: "Preferred username",
    autocomplete: "username",
  },
  profile: { label: "Profile", type: "url", autocomplete: "url" },
  website: { label: "Website", type: "url", autocomplete: "url" },
};

const attributeLabel = (name: string): string => {
  const words = name.replace(/^custom:/, "").replace(/_/g, " ");
  return words.charAt(0).toUpperCase() + words.slice(1);
};

/** The form field of a required attribute, named as managed login names it. */
export const attributeField = (attribute: string): FormField => {
  const known = ATTRIBUTE_INPUTS[attribute];
  return {
    name: `requiredAttributes[${attribute}]`,
    label: known?.label ?? attributeLabel(attribute),
    type: known?.type ?? "text",
    autocomplete: known?.autocomplete ?? "off",
  };
};

const usernameAttribute = (
  pool: PoolForPages,
): "email" | "phone_number" | undefined => {
  const attributes = pool.UsernameAttributes ?? [];
  if (attributes.length !== 1) return undefined;
  return attributes[0] === "email" || attributes[0] === "phone_number"
    ? attributes[0]
    : undefined;
};

/** The username field: email or phone number when the pool signs in with them, otherwise a username. */
export const usernameField = (
  pool: PoolForPages,
  purpose: "signUp" | "signIn",
): FormField => {
  const attributes = pool.UsernameAttributes ?? [];
  const single = usernameAttribute(pool);
  if (single === "email") {
    return {
      name: "username",
      label: "Email",
      type: "email",
      autocomplete: purpose === "signUp" ? "email" : "username",
    };
  }
  if (single === "phone_number") {
    return {
      name: "username",
      label: "Phone number",
      type: "tel",
      autocomplete: purpose === "signUp" ? "tel" : "username",
    };
  }
  return {
    name: "username",
    label: attributes.length > 1 ? "Email or phone number" : "Username",
    type: "text",
    autocomplete: "username",
  };
};

export const signUpAttributeFields = (pool: PoolForPages): FormField[] => {
  const fromUsername = usernameAttribute(pool);
  return (pool.SchemaAttributes ?? [])
    .filter(
      (schema) =>
        schema.Required &&
        schema.Name &&
        schema.Name !== "sub" &&
        schema.Name !== fromUsername,
    )
    .map((schema) => attributeField(schema.Name as string));
};

export const signUpAllowed = (pool: PoolForPages): boolean =>
  !pool.AdminCreateUserConfig?.AllowAdminCreateUserOnly;

const attributeNameOf = (fieldName: string): string =>
  fieldName.replace(/^requiredAttributes\[(.*)\]$/, "$1");

// The filled required attributes, plus the phone number a phone username stands for (SignUp adds the email).
export const signUpAttributes = (
  pool: PoolForPages,
  username: string,
  form: Record<string, string | undefined>,
): Attribute[] => {
  const attributes: Attribute[] = signUpAttributeFields(pool)
    .map((field) => ({
      Name: attributeNameOf(field.name),
      Value: form[field.name]?.trim() ?? "",
    }))
    .filter((attribute) => attribute.Value !== "");
  const signsInWithPhone = (pool.UsernameAttributes ?? []).includes(
    "phone_number",
  );
  if (
    signsInWithPhone &&
    !username.includes("@") &&
    !attributes.some((a) => a.Name === "phone_number")
  ) {
    attributes.push({ Name: "phone_number", Value: username });
  }
  return attributes;
};

/** The SecretHash a client with a secret needs, computed on the server where the secret lives. */
export const secretHashFor = (
  appClient: Pick<AppClient, "ClientId" | "ClientSecret">,
  username: string,
): string | undefined =>
  appClient.ClientSecret
    ? computeSecretHash(username, appClient.ClientId, appClient.ClientSecret)
    : undefined;

/** A delivery destination masked as Cognito masks it: `a***@e***` or `+*******0100`. */
export const maskDestination = (destination: string): string => {
  const at = destination.indexOf("@");
  if (at > 0) {
    return `${destination[0]}***@${destination[at + 1] ?? ""}***`;
  }
  if (destination.length <= 4) return destination;
  const plus = destination.startsWith("+") ? "+" : "";
  return `${plus}${"*".repeat(destination.length - 4 - plus.length)}${destination.slice(-4)}`;
};
