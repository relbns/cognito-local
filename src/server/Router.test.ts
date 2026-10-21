import { describe, expect, it } from "vitest";
import { TestContext } from "../__tests__/testContext";
import { InvalidParameterError, UnknownOperationError } from "../errors";
import type { Services } from "../services";
import { Targets } from "../targets/targets";
import { Router } from "./Router";

describe("Router", () => {
  it("returns an error handler for an invalid target", async () => {
    const services = {} as Services;
    const route = Router(services)("invalid");

    await expect(route(TestContext, null as any)).rejects.toEqual(
      new UnknownOperationError('Unsupported x-amz-target header "invalid"'),
    );
  });

  it.each(Object.keys(Targets))("supports the %s target", (target) => {
    const services = {} as Services;
    const route = Router(services)(target);

    expect(route).toBeDefined();
  });

  it("rejects input that breaks the model before the target runs", async () => {
    const services = {} as Services;
    const route = Router(services)("GetUser");

    await expect(route(TestContext, {})).rejects.toEqual(
      new InvalidParameterError(
        "1 validation error detected: Value null at 'accessToken' failed to satisfy constraint: Member must not be null",
      ),
    );
  });

  it("hands invalid input to the target when validation is off", async () => {
    const services = {
      config: { ValidationConfig: { Enabled: false } },
    } as Services;
    const route = Router(services)("GetUser");

    await expect(route(TestContext, {})).rejects.not.toBeInstanceOf(
      InvalidParameterError,
    );
  });
});
