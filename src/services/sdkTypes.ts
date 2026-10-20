import type { AttributeType } from "@aws-sdk/client-cognito-identity-provider";

type RequiredKeys<T> = {
  [K in keyof T]-?: Partial<Pick<T, K>> extends Pick<T, K> ? never : K;
}[keyof T];
type OptionalKeys<T> = Exclude<keyof T, RequiredKeys<T>>;

// SDK v3 types members AWS marks required as `T | undefined`; the emulator treats them as present, as the v2 types did.
export type Present<T> = T extends Date | string | number | boolean
  ? T
  : T extends readonly (infer U)[]
    ? Present<U>[]
    : T extends object
      ? string extends keyof T
        ? T
        : { [K in RequiredKeys<T>]: Present<Exclude<T[K], undefined>> } & {
            [K in OptionalKeys<T>]?: Present<Exclude<T[K], undefined>>;
          }
      : T;

export type Attribute = Present<AttributeType>;
