import { describe, expect, it } from "vitest";
import { lockoutSeconds } from "./signInLockout";

describe("lockoutSeconds", () => {
  it.each([
    [1, 0],
    [4, 0],
    [5, 1],
    [6, 2],
    [10, 32],
    [14, 512],
    [15, 900],
    [40, 900],
  ])(
    "locks out for 2^(n-5) seconds, at most 15 minutes: n=%i gives %i",
    (failed, seconds) => {
      expect(lockoutSeconds(failed)).toBe(seconds);
    },
  );
});
