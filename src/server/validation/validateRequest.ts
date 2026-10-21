import { CognitoError, InvalidParameterError } from "../../errors";
import { OPERATION_INPUTS, SHAPES } from "./cognitoIdpModel.generated";
import type { ModelShape } from "./modelShape";

export class SerializationError extends CognitoError {
  public constructor(message: string) {
    super("SerializationException", message);
  }
}

const SCALAR_TYPES = new Set([
  "string",
  "integer",
  "long",
  "boolean",
  "blob",
  "timestamp",
]);

const JAVA_TARGET_TYPES: Record<string, string> = {
  string: "String",
  integer: "Integer",
  long: "Long",
  boolean: "Boolean",
  blob: "ByteBuffer",
  timestamp: "Date",
};

const patternCache = new Map<string, RegExp | null>();

const compilePattern = (pattern: string): RegExp | null => {
  if (!patternCache.has(pattern)) {
    const dotAll = pattern.startsWith("(?s)");
    const body = dotAll ? pattern.slice(4) : pattern;
    try {
      patternCache.set(
        pattern,
        new RegExp(`^(?:${body})$`, dotAll ? "us" : "u"),
      );
    } catch {
      patternCache.set(pattern, null);
    }
  }
  return patternCache.get(pattern) ?? null;
};

const isAbsent = (value: unknown): value is null | undefined =>
  value === null || value === undefined;

const isPlainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null && !Array.isArray(value);

const javaClassOf = (value: unknown): string => {
  if (typeof value === "number") {
    return "com.amazon.coral.value.json.numbers.TruncatingBigNumber";
  }
  return typeof value === "boolean" ? "java.lang.Boolean" : "java.lang.String";
};

const javaString = (value: unknown): string => {
  if (Array.isArray(value)) return `[${value.map(javaString).join(", ")}]`;
  if (isPlainObject(value)) {
    return `{${Object.entries(value)
      .map(([k, v]) => `${k}=${javaString(v)}`)
      .join(", ")}}`;
  }
  return String(value);
};

const describeValue = (value: unknown, sensitive: boolean): string => {
  if (isAbsent(value)) return "Value null";
  return sensitive ? "Value" : `Value '${javaString(value)}'`;
};

const checkType = (shape: ModelShape, value: unknown): void => {
  if (isAbsent(value) || shape.type === "document") return;
  const isArray = Array.isArray(value);
  const isObject = isPlainObject(value);

  if (shape.type === "structure" || shape.type === "map") {
    if (isObject) return;
    throw new SerializationError(
      isArray
        ? "Start of list found where not expected"
        : "Unexpected value type in payload",
    );
  }
  if (shape.type === "list") {
    if (isArray) return;
    throw new SerializationError(
      isObject
        ? "Start of structure or map found where not expected."
        : `Unrecognized collection type class ${javaClassOf(value)}`,
    );
  }
  if (isObject) {
    throw new SerializationError(
      "Start of structure or map found where not expected.",
    );
  }
  if (isArray) {
    throw new SerializationError("Start of list found where not expected");
  }

  const ok =
    (shape.type === "string" && typeof value === "string") ||
    (shape.type === "blob" && typeof value === "string") ||
    ((shape.type === "integer" || shape.type === "long") &&
      typeof value === "number" &&
      Number.isFinite(value)) ||
    (shape.type === "boolean" && typeof value === "boolean") ||
    (shape.type === "timestamp" &&
      (typeof value === "number" || typeof value === "string"));
  if (!ok) {
    throw new SerializationError(
      `class ${javaClassOf(value)} can not be converted to an ${JAVA_TARGET_TYPES[shape.type]}`,
    );
  }
};

const lengthViolations = (shape: ModelShape, length: number): string[] => {
  const out: string[] = [];
  if (shape.min !== undefined && length < shape.min) {
    out.push(`Member must have length greater than or equal to ${shape.min}`);
  }
  if (shape.max !== undefined && length > shape.max) {
    out.push(`Member must have length less than or equal to ${shape.max}`);
  }
  return out;
};

const scalarViolations = (shape: ModelShape, value: unknown): string[] => {
  if (isAbsent(value)) return [];
  if (shape.type === "string" && typeof value === "string") {
    const out: string[] = [];
    const regex =
      shape.pattern === undefined ? null : compilePattern(shape.pattern);
    if (regex && !regex.test(value)) {
      out.push(
        `Member must satisfy regular expression pattern: ${shape.pattern}`,
      );
    }
    out.push(...lengthViolations(shape, value.length));
    if (shape.enum && !shape.enum.includes(value)) {
      out.push(
        `Member must satisfy enum value set: [${shape.enum.join(", ")}]`,
      );
    }
    return out;
  }
  if (
    (shape.type === "integer" || shape.type === "long") &&
    typeof value === "number"
  ) {
    const n = Math.trunc(value);
    const out: string[] = [];
    if (shape.min !== undefined && n < shape.min) {
      out.push(`Member must have value greater than or equal to ${shape.min}`);
    }
    if (shape.max !== undefined && n > shape.max) {
      out.push(`Member must have value less than or equal to ${shape.max}`);
    }
    return out;
  }
  if (shape.type === "blob" && typeof value === "string") {
    return lengthViolations(shape, Buffer.from(value, "base64").length);
  }
  return [];
};

const constraintError = (
  value: unknown,
  sensitive: boolean,
  path: string,
  constraint: string,
): string =>
  `${describeValue(value, sensitive)} at '${path}' failed to satisfy constraint: ${constraint}`;

const memberPath = (parent: string, member: string): string => {
  const name = member.charAt(0).toLowerCase() + member.slice(1);
  return parent ? `${parent}.${name}` : name;
};

const aggregate = (shape: ModelShape, values: unknown[]): string[] => {
  const found = new Set<string>();
  for (const value of values) {
    checkType(shape, value);
    for (const v of scalarViolations(shape, value)) found.add(v);
  }
  return [...found];
};

const walk = (
  shape: ModelShape,
  value: unknown,
  path: string,
  errors: string[],
): void => {
  if (isAbsent(value)) return;
  checkType(shape, value);
  const sensitive = !!shape.sensitive;

  if (shape.type === "structure") {
    const object = value as Record<string, unknown>;
    for (const [name, target] of Object.entries(shape.members)) {
      const child = object[name];
      const childPath = memberPath(path, name);
      if (shape.required?.includes(name) && isAbsent(child)) {
        errors.push(
          constraintError(child, false, childPath, "Member must not be null"),
        );
        continue;
      }
      walk(SHAPES[target], child, childPath, errors);
    }
    return;
  }

  if (shape.type === "list") {
    const items = value as unknown[];
    const member = SHAPES[shape.member];
    const listSensitive = sensitive || !!member.sensitive;
    for (const v of lengthViolations(shape, items.length)) {
      errors.push(constraintError(items, listSensitive, path, v));
    }
    if (SCALAR_TYPES.has(member.type)) {
      const found = aggregate(member, items);
      if (found.length > 0) {
        errors.push(
          constraintError(
            items,
            listSensitive,
            path,
            `Member must satisfy constraint: [${found.join(", ")}]`,
          ),
        );
      }
    } else {
      items.forEach((item, i) => {
        walk(member, item, `${path}.${i + 1}.member`, errors);
      });
    }
    return;
  }

  if (shape.type === "map") {
    const map = value as Record<string, unknown>;
    const keyShape = SHAPES[shape.key];
    const valueShape = SHAPES[shape.value];
    const mapSensitive = sensitive || !!valueShape.sensitive;
    for (const v of lengthViolations(shape, Object.keys(map).length)) {
      errors.push(constraintError(map, mapSensitive, path, v));
    }
    const keyFound = aggregate(keyShape, Object.keys(map));
    if (keyFound.length > 0) {
      errors.push(
        constraintError(
          map,
          mapSensitive,
          path,
          `Map keys must satisfy constraint: [${keyFound.join(", ")}]`,
        ),
      );
    }
    if (SCALAR_TYPES.has(valueShape.type)) {
      const valueFound = aggregate(valueShape, Object.values(map));
      if (valueFound.length > 0) {
        errors.push(
          constraintError(
            map,
            mapSensitive,
            path,
            `Map value must satisfy constraint: [${valueFound.join(", ")}]`,
          ),
        );
      }
    } else {
      for (const [key, item] of Object.entries(map)) {
        walk(valueShape, item, `${path}.${key}.member`, errors);
      }
    }
    return;
  }

  for (const v of scalarViolations(shape, value)) {
    errors.push(constraintError(value, sensitive, path, v));
  }
};

export const hasInputModel = (operation: string): boolean =>
  Object.hasOwn(OPERATION_INPUTS, operation);

/** Throws the error the service returns for an input that breaks the operation's model. */
export const validateRequest = (operation: string, input: unknown): void => {
  if (!hasInputModel(operation)) return;
  const shape = SHAPES[OPERATION_INPUTS[operation]];
  const errors: string[] = [];
  walk(shape, isAbsent(input) ? {} : input, "", errors);
  if (errors.length > 0) {
    const noun = errors.length === 1 ? "error" : "errors";
    throw new InvalidParameterError(
      `${errors.length} validation ${noun} detected: ${errors.join("; ")}`,
    );
  }
};
