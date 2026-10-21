import { describe, expect, it } from "vitest";
import { MockLogger } from "../__tests__/mockLogger";
import { requestContext, requestIssuerDomain } from "./context";

const request = (host: string | undefined, protocol = "http") => ({
  log: MockLogger as never,
  protocol,
  get: ((name: string) =>
    name.toLowerCase() === "host" ? host : undefined) as never,
});

describe("requestIssuerDomain", () => {
  it("is the scheme and Host header when IssuerFromRequest is on", () => {
    expect(
      requestIssuerDomain(request("localhost:32768"), {
        IssuerFromRequest: true,
      }),
    ).toBe("http://localhost:32768");
    expect(
      requestIssuerDomain(request("auth.example.test", "https"), {
        IssuerFromRequest: true,
      }),
    ).toBe("https://auth.example.test");
  });

  it("is undefined when the switch is off or there is no Host", () => {
    expect(requestIssuerDomain(request("localhost:1"), {})).toBeUndefined();
    expect(
      requestIssuerDomain(request("localhost:1"), undefined),
    ).toBeUndefined();
    expect(
      requestIssuerDomain(request(undefined), { IssuerFromRequest: true }),
    ).toBeUndefined();
  });
});

describe("requestContext", () => {
  it("carries the request issuer only when it applies", () => {
    expect(
      requestContext(request("localhost:2"), { IssuerFromRequest: true }),
    ).toEqual({ logger: MockLogger, issuerDomain: "http://localhost:2" });
    expect(requestContext(request("localhost:2"), {})).toEqual({
      logger: MockLogger,
    });
  });
});
