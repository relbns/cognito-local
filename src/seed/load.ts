import fs from "node:fs";
import path from "node:path";
import {
  formatFileTarget,
  isFileTarget,
  parseFileTarget,
} from "../services/fileTrigger";
import type { SeedFile } from "./types";
import {
  assertValidSeed,
  type SeedIssue,
  SeedValidationError,
} from "./validate";

const mapLambdaTargets = (
  lambdaConfig: Record<string, unknown> | undefined,
  map: (value: string, key: string) => string,
): Record<string, unknown> | undefined => {
  if (!lambdaConfig) return lambdaConfig;
  return Object.fromEntries(
    Object.entries(lambdaConfig).map(([key, value]) => {
      if (typeof value === "string") return [key, map(value, key)];
      if (value && typeof value === "object") {
        const arn = (value as { LambdaArn?: unknown }).LambdaArn;
        if (typeof arn === "string") {
          return [key, { ...value, LambdaArn: map(arn, key) }];
        }
      }
      return [key, value];
    }),
  );
};

/** Rewrites every file: trigger in the seed with `map`, leaving Lambda names untouched. */
export const mapSeedFileTargets = (
  seed: SeedFile,
  map: (value: string, key: string, poolIndex: number) => string,
): SeedFile => ({
  ...seed,
  UserPools: seed.UserPools.map((pool, i) =>
    pool.LambdaConfig === undefined
      ? pool
      : {
          ...pool,
          LambdaConfig: mapLambdaTargets(
            pool.LambdaConfig as Record<string, unknown>,
            (value, key) => (isFileTarget(value) ? map(value, key, i) : value),
          ),
        },
  ),
});

/** Makes file: trigger paths absolute against baseDir and checks the files exist. */
export const resolveSeedFileTargets = (
  seed: SeedFile,
  baseDir: string,
  source: string,
): SeedFile => {
  const issues: SeedIssue[] = [];
  const resolved = mapSeedFileTargets(seed, (value, key, i) => {
    const target = parseFileTarget(value, baseDir);
    if (!fs.existsSync(target.file)) {
      issues.push({
        path: `UserPools[${i}].LambdaConfig.${key}`,
        message: `trigger file ${target.file} does not exist`,
      });
    }
    return formatFileTarget(target);
  });
  if (issues.length) throw new SeedValidationError(source, issues);
  return resolved;
};

/** Relativizes file: trigger paths at most one directory above baseDir, for a portable export. */
export const relativizeSeedFileTargets = (
  seed: SeedFile,
  baseDir: string,
): SeedFile =>
  mapSeedFileTargets(seed, (value) => {
    const target = parseFileTarget(value, baseDir);
    let rel = path.relative(baseDir, target.file).split(path.sep).join("/");
    if (rel.startsWith("../../") || path.isAbsolute(rel)) return value;
    if (!rel.startsWith(".")) rel = `./${rel}`;
    return formatFileTarget({ file: rel, exportName: target.exportName });
  });

export const parseSeed = (
  text: string,
  source: string,
  baseDir: string,
): SeedFile => {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch (e) {
    throw new SeedValidationError(source, [
      { path: "", message: `not valid JSON: ${(e as Error).message}` },
    ]);
  }
  assertValidSeed(value, source);
  return resolveSeedFileTargets(value, baseDir, source);
};

export const loadSeedFile = (file: string): SeedFile => {
  const absolute = path.resolve(file);
  let text: string;
  try {
    text = fs.readFileSync(absolute, "utf8");
  } catch (e) {
    throw new SeedValidationError(absolute, [
      { path: "", message: `cannot read file: ${(e as Error).message}` },
    ]);
  }
  return parseSeed(text, absolute, path.dirname(absolute));
};
