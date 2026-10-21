import {
  createHash,
  generateKeyPairSync,
  type KeyObject,
  randomBytes,
} from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import jwt from "jsonwebtoken";

export interface FakeOidcUser {
  sub: string;
  idTokenClaims?: Record<string, unknown>;
  userInfo?: Record<string, unknown>;
}

export interface FakeOidcOptions {
  clientId: string;
  clientSecret: string;
  user: FakeOidcUser;
  pkce?: boolean;
  acceptClientSecret?: (secret: string | null) => boolean;
  host?: string;
  port?: number;
}

interface IssuedCode {
  redirectUri: string;
  nonce: string | undefined;
  codeChallenge: string | undefined;
}

/** An OIDC provider on 127.0.0.1: discovery, JWKS (RS256), authorize, token and userinfo endpoints. */
export class FakeOidcProvider {
  issuer = "";
  kid = "fake-key-1";
  privateKey: KeyObject;
  publicKey: KeyObject;
  readonly requests: string[] = [];
  readonly tokenRequests: URLSearchParams[] = [];
  readonly authorizeRequests: URLSearchParams[] = [];
  readonly userInfoRequests: Array<{ method: string; url: string }> = [];
  idTokenOverrides: Record<string, unknown> = {};
  signingKey: KeyObject | undefined;
  tokenError: { status: number; body: unknown } | undefined;
  userInfoError: { status: number; body: unknown } | undefined;
  omitIdToken = false;
  private readonly codes = new Map<string, IssuedCode>();
  private readonly accessTokens = new Map<string, string>();
  private server: http.Server | undefined;

  constructor(readonly options: FakeOidcOptions) {
    const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
    this.privateKey = pair.privateKey;
    this.publicKey = pair.publicKey;
  }

  rotateKey(kid: string): void {
    const pair = generateKeyPairSync("rsa", { modulusLength: 2048 });
    this.kid = kid;
    this.privateKey = pair.privateKey;
    this.publicKey = pair.publicKey;
  }

  async start(): Promise<string> {
    this.server = http.createServer((req, res) => {
      this.handle(req, res).catch((err) => {
        res.writeHead(500, { "Content-Type": "application/json" });
        res.end(
          JSON.stringify({
            error: "server_error",
            error_description: String(err),
          }),
        );
      });
    });
    const host = this.options.host ?? "127.0.0.1";
    await new Promise<void>((resolve) =>
      this.server?.listen(this.options.port ?? 0, host, resolve),
    );
    const { port } = this.server.address() as AddressInfo;
    this.issuer = `http://${host}:${port}`;
    return this.issuer;
  }

  async stop(): Promise<void> {
    if (!this.server) return;
    this.server.closeAllConnections();
    await new Promise<void>((resolve) => this.server?.close(() => resolve()));
  }

  count(path: string): number {
    return this.requests.filter((p) => p === path).length;
  }

  private json(res: http.ServerResponse, status: number, body: unknown) {
    res.writeHead(status, { "Content-Type": "application/json" });
    res.end(JSON.stringify(body));
  }

  private async readBody(req: http.IncomingMessage): Promise<string> {
    let body = "";
    for await (const chunk of req) body += chunk;
    return body;
  }

  private async handle(req: http.IncomingMessage, res: http.ServerResponse) {
    const url = new URL(req.url ?? "/", this.issuer);
    this.requests.push(url.pathname);
    switch (url.pathname) {
      case "/.well-known/openid-configuration":
        return this.json(res, 200, {
          issuer: this.issuer,
          authorization_endpoint: `${this.issuer}/authorize`,
          token_endpoint: `${this.issuer}/token`,
          userinfo_endpoint: `${this.issuer}/userinfo`,
          jwks_uri: `${this.issuer}/jwks`,
          response_types_supported: ["code"],
          subject_types_supported: ["public"],
          id_token_signing_alg_values_supported: ["RS256"],
          token_endpoint_auth_methods_supported: ["client_secret_post"],
          ...(this.options.pkce === false
            ? {}
            : { code_challenge_methods_supported: ["S256"] }),
        });
      case "/jwks":
        return this.json(res, 200, {
          keys: [
            {
              ...this.publicKey.export({ format: "jwk" }),
              kid: this.kid,
              use: "sig",
              alg: "RS256",
            },
          ],
        });
      case "/authorize":
        return this.authorize(url, res);
      case "/token":
        return this.token(req, res);
      case "/userinfo":
      case "/me":
        return this.userInfo(req, res);
      default:
        res.writeHead(404, { "Content-Type": "text/plain" });
        res.end("Not Found");
    }
  }

  private authorize(url: URL, res: http.ServerResponse) {
    const params = url.searchParams;
    this.authorizeRequests.push(params);
    const redirectUri = params.get("redirect_uri") ?? "";
    const back = new URL(redirectUri);
    if (params.get("client_id") !== this.options.clientId) {
      back.searchParams.set("error", "unauthorized_client");
      back.searchParams.set("error_description", "Unknown client");
    } else {
      const code = `code-${randomBytes(8).toString("hex")}`;
      this.codes.set(code, {
        redirectUri,
        nonce: params.get("nonce") ?? undefined,
        codeChallenge: params.get("code_challenge") ?? undefined,
      });
      back.searchParams.set("code", code);
    }
    const state = params.get("state");
    if (state) back.searchParams.set("state", state);
    res.writeHead(302, { Location: back.toString() });
    res.end();
  }

  private async token(req: http.IncomingMessage, res: http.ServerResponse) {
    const url = new URL(req.url ?? "/", this.issuer);
    const params =
      req.method === "POST"
        ? new URLSearchParams(await this.readBody(req))
        : url.searchParams;
    this.tokenRequests.push(params);
    if (this.tokenError) {
      return this.json(res, this.tokenError.status, this.tokenError.body);
    }
    const acceptSecret =
      this.options.acceptClientSecret ??
      ((secret) => secret === this.options.clientSecret);
    if (
      params.get("client_id") !== this.options.clientId ||
      !acceptSecret(params.get("client_secret"))
    ) {
      return this.json(res, 401, {
        error: "invalid_client",
        error_description: "Client authentication failed",
      });
    }
    const code = params.get("code") ?? "";
    const issued = this.codes.get(code);
    this.codes.delete(code);
    if (!issued || issued.redirectUri !== params.get("redirect_uri")) {
      return this.json(res, 400, {
        error: "invalid_grant",
        error_description: "Unknown code",
      });
    }
    if (issued.codeChallenge) {
      const verifier = params.get("code_verifier") ?? "";
      const digest = createHash("sha256").update(verifier).digest("base64url");
      if (digest !== issued.codeChallenge) {
        return this.json(res, 400, {
          error: "invalid_grant",
          error_description: "PKCE verification failed",
        });
      }
    }
    const accessToken = `access-${randomBytes(8).toString("hex")}`;
    this.accessTokens.set(accessToken, this.options.user.sub);
    const now = Math.floor(Date.now() / 1000);
    const idToken = jwt.sign(
      {
        iss: this.issuer,
        aud: this.options.clientId,
        sub: this.options.user.sub,
        iat: now,
        exp: now + 300,
        ...(issued.nonce ? { nonce: issued.nonce } : {}),
        ...this.options.user.idTokenClaims,
        ...this.idTokenOverrides,
      },
      this.signingKey ?? this.privateKey,
      { algorithm: "RS256", keyid: this.kid },
    );
    return this.json(res, 200, {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 300,
      ...(this.omitIdToken ? {} : { id_token: idToken }),
    });
  }

  private userInfo(req: http.IncomingMessage, res: http.ServerResponse) {
    this.userInfoRequests.push({
      method: req.method ?? "",
      url: req.url ?? "",
    });
    if (this.userInfoError) {
      return this.json(res, this.userInfoError.status, this.userInfoError.body);
    }
    const token = /^Bearer (.+)$/.exec(req.headers.authorization ?? "")?.[1];
    const sub = token ? this.accessTokens.get(token) : undefined;
    if (!sub) return this.json(res, 401, { error: "invalid_token" });
    return this.json(res, 200, {
      sub,
      ...this.options.user.userInfo,
    });
  }
}
