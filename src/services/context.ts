import type { Request } from "express";
import type { LogService } from "./LogService";
import type { TokenConfig } from "./tokenGenerator";

export interface Context {
  readonly logger: LogService;
  /** `<scheme>://<Host header>` of the request when TokenConfig.IssuerFromRequest is on. */
  readonly issuerDomain?: string;
}

export const requestIssuerDomain = (
  req: Pick<Request, "protocol" | "get">,
  tokenConfig: Pick<TokenConfig, "IssuerFromRequest"> | undefined,
): string | undefined => {
  const host = req.get("host");
  return tokenConfig?.IssuerFromRequest && host
    ? `${req.protocol}://${host}`
    : undefined;
};

export const requestContext = (
  req: Pick<Request, "log" | "protocol" | "get">,
  tokenConfig: Pick<TokenConfig, "IssuerFromRequest"> | undefined,
): Context => {
  const issuerDomain = requestIssuerDomain(req, tokenConfig);
  return issuerDomain ? { logger: req.log, issuerDomain } : { logger: req.log };
};
