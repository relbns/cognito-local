import * as crypto from "node:crypto";

type CborInput =
  | number
  | string
  | boolean
  | Buffer
  | CborInput[]
  | Map<CborInput, CborInput>;

const head = (major: number, length: number): Buffer => {
  if (length < 24) return Buffer.from([(major << 5) | length]);
  if (length < 0x100) return Buffer.from([(major << 5) | 24, length]);
  if (length < 0x10000) {
    const b = Buffer.alloc(3);
    b[0] = (major << 5) | 25;
    b.writeUInt16BE(length, 1);
    return b;
  }
  const b = Buffer.alloc(5);
  b[0] = (major << 5) | 26;
  b.writeUInt32BE(length, 1);
  return b;
};

export const encodeCbor = (value: CborInput): Buffer => {
  if (typeof value === "number") {
    return value >= 0 ? head(0, value) : head(1, -1 - value);
  }
  if (typeof value === "boolean") return Buffer.from([value ? 0xf5 : 0xf4]);
  if (typeof value === "string") {
    const bytes = Buffer.from(value, "utf8");
    return Buffer.concat([head(3, bytes.length), bytes]);
  }
  if (Buffer.isBuffer(value))
    return Buffer.concat([head(2, value.length), value]);
  if (Array.isArray(value)) {
    return Buffer.concat([head(4, value.length), ...value.map(encodeCbor)]);
  }
  const parts: Buffer[] = [head(5, value.size)];
  for (const [k, v] of value) parts.push(encodeCbor(k), encodeCbor(v));
  return Buffer.concat(parts);
};

export const ATTESTATION_CERTIFICATE = `-----BEGIN CERTIFICATE-----
MIIBwTCCAWgCCQCoAN+GF4qDHDAKBggqhkjOPQQDAjBoMQswCQYDVQQGEwJVUzEe
MBwGA1UECgwVRXhhbXBsZSBBdXRoZW50aWNhdG9yMSIwIAYDVQQLDBlBdXRoZW50
aWNhdG9yIEF0dGVzdGF0aW9uMRUwEwYDVQQDDAxleGFtcGxlLnRlc3QwIBcNMjYx
MDIxMTA1MDM0WhgPMjEyNjA5MjcxMDUwMzRaMGgxCzAJBgNVBAYTAlVTMR4wHAYD
VQQKDBVFeGFtcGxlIEF1dGhlbnRpY2F0b3IxIjAgBgNVBAsMGUF1dGhlbnRpY2F0
b3IgQXR0ZXN0YXRpb24xFTATBgNVBAMMDGV4YW1wbGUudGVzdDBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABFog+lIptSP02Ou3E/ZD42hl3BTw87JmRUHWNtvlhBSF
1XwmuEtmM/fPsuucg6G64WoM0lAIYUIAO5kThP1+H0QwCgYIKoZIzj0EAwIDRwAw
RAIgR3Vbr8x0oGdaNHifvf4vX9sN2ANfrmoom6vSWbnvQnUCIBTyadiE+MrrtSs+
Y3gYAHkXeK/tTPF/ZlNSUoYQdm0f
-----END CERTIFICATE-----`;

const ATTESTATION_KEY = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgJJKNWi3fsbxDfg/l
7zRCNwOAp3/Ro1jd5Q5wN69sJJ2hRANCAARaIPpSKbUj9NjrtxP2Q+NoZdwU8POy
ZkVB1jbb5YQUhdV8JrhLZjP3z7LrnIOhuuFqDNJQCGFCADuZE4T9fh9E
-----END PRIVATE KEY-----`;

export type Algorithm = -7 | -257 | -8;
export type AttestationFormat = "none" | "packed" | "packed-x5c" | "fido-u2f";

export interface SoftwareCredential {
  id: Buffer;
  algorithm: Algorithm;
  privateKey: crypto.KeyObject;
  publicKey: crypto.KeyObject;
  signCount: number;
  userHandle?: string;
}

const sha256 = (data: Buffer | string) =>
  crypto.createHash("sha256").update(data).digest();

const sign = (key: crypto.KeyObject, data: Buffer): Buffer =>
  crypto.sign(key.asymmetricKeyType === "ed25519" ? null : "sha256", data, key);

const coseKey = (credential: SoftwareCredential): Buffer => {
  const jwk = credential.publicKey.export({ format: "jwk" });
  const b = (v: string | undefined) => Buffer.from(v ?? "", "base64url");
  if (credential.algorithm === -7) {
    return encodeCbor(
      new Map<CborInput, CborInput>([
        [1, 2],
        [3, -7],
        [-1, 1],
        [-2, b(jwk.x)],
        [-3, b(jwk.y)],
      ]),
    );
  }
  if (credential.algorithm === -8) {
    return encodeCbor(
      new Map<CborInput, CborInput>([
        [1, 1],
        [3, -8],
        [-1, 6],
        [-2, b(jwk.x)],
      ]),
    );
  }
  return encodeCbor(
    new Map<CborInput, CborInput>([
      [1, 3],
      [3, -257],
      [-1, b(jwk.n)],
      [-2, b(jwk.e)],
    ]),
  );
};

const flagsByte = (o: { up?: boolean; uv?: boolean; at?: boolean }) =>
  (o.up === false ? 0 : 0x01) | (o.uv ? 0x04 : 0) | (o.at ? 0x40 : 0);

export interface CreateOptions {
  rpId: string;
  origin: string;
  challenge: string;
  algorithm?: Algorithm;
  attestation?: AttestationFormat;
  userVerified?: boolean;
  userPresent?: boolean;
  type?: string;
  transports?: string[];
  attachment?: string;
  userHandle?: string;
  /** Signs the attestation with a different key. */
  badAttestationSignature?: boolean;
}

export interface GetOptions {
  rpId: string;
  origin: string;
  challenge: string;
  userVerified?: boolean;
  userPresent?: boolean;
  type?: string;
  /** Overrides the counter the authenticator reports (it otherwise increments). */
  signCount?: number;
  badSignature?: boolean;
  userHandle?: string | null;
}

/** A WebAuthn authenticator in software: ES256 or RS256 keys, none, packed or fido-u2f attestation. */
export class SoftwareAuthenticator {
  public readonly credentials: SoftwareCredential[] = [];

  public create(options: CreateOptions) {
    const algorithm = options.algorithm ?? -7;
    const pair =
      algorithm === -7
        ? crypto.generateKeyPairSync("ec", { namedCurve: "P-256" })
        : algorithm === -8
          ? crypto.generateKeyPairSync("ed25519")
          : crypto.generateKeyPairSync("rsa", { modulusLength: 2048 });
    const credential: SoftwareCredential = {
      id: crypto.randomBytes(32),
      algorithm,
      privateKey: pair.privateKey,
      publicKey: pair.publicKey,
      signCount: 0,
      userHandle: options.userHandle,
    };
    const idLength = Buffer.alloc(2);
    idLength.writeUInt16BE(credential.id.length);
    const counter = Buffer.alloc(4);
    const authData = Buffer.concat([
      sha256(options.rpId),
      Buffer.from([
        flagsByte({
          up: options.userPresent,
          uv: options.userVerified ?? true,
          at: true,
        }),
      ]),
      counter,
      Buffer.alloc(16),
      idLength,
      credential.id,
      coseKey(credential),
    ]);
    const clientDataJSON = Buffer.from(
      JSON.stringify({
        type: options.type ?? "webauthn.create",
        challenge: options.challenge,
        origin: options.origin,
        crossOrigin: false,
      }),
    );
    const signed = Buffer.concat([authData, sha256(clientDataJSON)]);
    const format = options.attestation ?? "none";
    const signer = options.badAttestationSignature
      ? crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey
      : undefined;
    let fmt: string = format;
    let attStmt = new Map<CborInput, CborInput>();
    if (format === "packed") {
      attStmt = new Map<CborInput, CborInput>([
        ["alg", algorithm],
        ["sig", sign(signer ?? credential.privateKey, signed)],
      ]);
    } else if (format === "packed-x5c") {
      fmt = "packed";
      const certificate = new crypto.X509Certificate(ATTESTATION_CERTIFICATE);
      attStmt = new Map<CborInput, CborInput>([
        ["alg", -7],
        [
          "sig",
          sign(signer ?? crypto.createPrivateKey(ATTESTATION_KEY), signed),
        ],
        ["x5c", [certificate.raw]],
      ]);
    } else if (format === "fido-u2f") {
      attStmt = new Map<CborInput, CborInput>([
        ["sig", Buffer.from("unverified")],
        ["x5c", [new crypto.X509Certificate(ATTESTATION_CERTIFICATE).raw]],
      ]);
    }
    const attestationObject = encodeCbor(
      new Map<CborInput, CborInput>([
        ["fmt", fmt],
        ["attStmt", attStmt],
        ["authData", authData],
      ]),
    );
    this.credentials.push(credential);
    const id = credential.id.toString("base64url");
    return {
      credential,
      response: {
        id,
        rawId: id,
        type: "public-key",
        authenticatorAttachment: options.attachment ?? "platform",
        clientExtensionResults: {},
        response: {
          clientDataJSON: clientDataJSON.toString("base64url"),
          attestationObject: attestationObject.toString("base64url"),
          transports: options.transports ?? ["internal"],
        },
      },
    };
  }

  public get(credential: SoftwareCredential, options: GetOptions) {
    credential.signCount =
      options.signCount !== undefined
        ? options.signCount
        : credential.signCount + 1;
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(credential.signCount);
    const authData = Buffer.concat([
      sha256(options.rpId),
      Buffer.from([
        flagsByte({
          up: options.userPresent,
          uv: options.userVerified ?? true,
        }),
      ]),
      counter,
    ]);
    const clientDataJSON = Buffer.from(
      JSON.stringify({
        type: options.type ?? "webauthn.get",
        challenge: options.challenge,
        origin: options.origin,
        crossOrigin: false,
      }),
    );
    const signed = Buffer.concat([authData, sha256(clientDataJSON)]);
    const key = options.badSignature
      ? crypto.generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey
      : credential.privateKey;
    const id = credential.id.toString("base64url");
    const userHandle =
      options.userHandle === null
        ? undefined
        : (options.userHandle ?? credential.userHandle);
    return {
      id,
      rawId: id,
      type: "public-key",
      authenticatorAttachment: "platform",
      clientExtensionResults: {},
      response: {
        clientDataJSON: clientDataJSON.toString("base64url"),
        authenticatorData: authData.toString("base64url"),
        signature: sign(key, signed).toString("base64url"),
        ...(userHandle ? { userHandle } : {}),
      },
    };
  }
}
