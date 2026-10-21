import { describe, expect, it } from "vitest";
import {
  encodeCbor,
  SoftwareAuthenticator,
} from "../__tests__/softwareAuthenticator";
import * as TDB from "../__tests__/testDataBuilder";
import {
  InvalidParameterError,
  NotAuthorizedError,
  WebAuthnChallengeNotFoundError,
  WebAuthnCredentialNotSupportedError,
  WebAuthnOriginNotAllowedError,
  WebAuthnRelyingPartyMismatchError,
} from "../errors";
import { CborError, decodeCbor, decodeCborFirst } from "./cbor";
import type { UserPool } from "./userPoolService";
import {
  credentialCreationOptions,
  isOriginAllowed,
  relyingPartyId,
  userHandle,
  verifyAssertion,
  verifyRegistration,
  type WebAuthnCredential,
} from "./webAuthn";

const RP_ID = "auth.example.test";
const ORIGIN = "https://auth.example.test";
const CHALLENGE = Buffer.from("registration-challenge").toString("base64url");

const register = (
  authenticator: SoftwareAuthenticator,
  options: Partial<Parameters<SoftwareAuthenticator["create"]>[0]> = {},
  requireUserVerification = false,
) => {
  const created = authenticator.create({
    rpId: RP_ID,
    origin: ORIGIN,
    challenge: CHALLENGE,
    ...options,
  });
  return {
    created,
    verify: () =>
      verifyRegistration({
        credential: created.response,
        expectedChallenge: CHALLENGE,
        rpId: RP_ID,
        requireUserVerification,
      }),
  };
};

describe("cbor", () => {
  it("decodes the types WebAuthn structures use", () => {
    const encoded = encodeCbor(
      new Map<unknown, unknown>([
        [1, 2],
        [-7, "text"],
        ["bytes", Buffer.from([1, 2, 3])],
        ["list", [true, false, 300, 70000]],
      ]) as never,
    );
    const decoded = decodeCbor(encoded) as Map<unknown, unknown>;
    expect(decoded.get(1)).toEqual(2);
    expect(decoded.get(-7)).toEqual("text");
    expect(decoded.get("bytes")).toEqual(Buffer.from([1, 2, 3]));
    expect(decoded.get("list")).toEqual([true, false, 300, 70000]);
  });

  it("reports where the first item ends and refuses malformed input", () => {
    const first = encodeCbor("abc");
    expect(
      decodeCborFirst(Buffer.concat([first, Buffer.from([0xff])])).end,
    ).toEqual(first.length);
    expect(() => decodeCbor(Buffer.concat([first, Buffer.from([0])]))).toThrow(
      CborError,
    );
    expect(() => decodeCbor(Buffer.from([0x5f]))).toThrow(CborError);
    expect(() => decodeCbor(Buffer.from([0x45, 1]))).toThrow(CborError);
  });
});

describe("relyingPartyId", () => {
  const pool = (options: Partial<UserPool>): UserPool => ({
    Id: "local_Pool1",
    ...options,
  });

  it("uses the configured RP ID, then the custom domain, then the prefix domain", () => {
    expect(
      relyingPartyId(
        pool({
          WebAuthnConfiguration: { RelyingPartyId: "example.test" },
          CustomDomain: "auth.example.test",
          Domain: "example",
        }),
      ),
    ).toEqual("example.test");
    expect(
      relyingPartyId(pool({ CustomDomain: "auth.example.test", Domain: "x" })),
    ).toEqual("auth.example.test");
    expect(relyingPartyId(pool({ Domain: "example" }))).toEqual(
      "example.auth.local.amazoncognito.com",
    );
    expect(relyingPartyId(pool({}))).toBeUndefined();
  });
});

describe("isOriginAllowed", () => {
  it.each([
    ["https://auth.example.test", true],
    ["https://auth.example.test:8443", true],
    ["https://app.auth.example.test", true],
    ["https://example.test", false],
    ["https://evil-auth.example.test", false],
    ["http://auth.example.test", false],
    ["android:apk-key-hash:abc", true],
    ["not a url", false],
  ])("%s for auth.example.test is %s", (origin, allowed) => {
    expect(isOriginAllowed(origin, RP_ID)).toEqual(allowed);
  });

  it("accepts plain http only on localhost", () => {
    expect(isOriginAllowed("http://localhost:9229", "localhost")).toEqual(true);
    expect(isOriginAllowed("https://localhost", "localhost")).toEqual(true);
  });
});

describe("credentialCreationOptions", () => {
  it("asks for a discoverable ES256 or RS256 credential and excludes registered ones", () => {
    const user = {
      ...TDB.user({
        Username: "user-1",
        Attributes: [{ Name: "sub", Value: "sub-1" }],
      }),
      WebAuthnCredentials: [
        { CredentialId: "existing" } as unknown as WebAuthnCredential,
      ],
    };
    const options = credentialCreationOptions(
      {
        Id: "local_Pool1",
        WebAuthnConfiguration: { UserVerification: "required" },
      },
      user,
      RP_ID,
      CHALLENGE,
    );
    expect(options).toMatchObject({
      rp: { id: RP_ID, name: RP_ID },
      user: {
        id: Buffer.from("sub-1").toString("base64url"),
        name: "user-1",
      },
      challenge: CHALLENGE,
      pubKeyCredParams: [
        { type: "public-key", alg: -7 },
        { type: "public-key", alg: -257 },
      ],
      excludeCredentials: [{ type: "public-key", id: "existing" }],
      authenticatorSelection: {
        residentKey: "required",
        requireResidentKey: true,
        userVerification: "required",
      },
    });
  });
});

describe("verifyRegistration", () => {
  it.each([
    ["none", -7],
    ["none", -257],
    ["packed", -7],
    ["packed", -257],
    ["packed-x5c", -7],
    ["fido-u2f", -7],
  ] as const)(
    "accepts %s attestation with algorithm %s",
    (attestation, algorithm) => {
      const authenticator = new SoftwareAuthenticator();
      const { created, verify } = register(authenticator, {
        attestation,
        algorithm,
        transports: ["internal", "hybrid"],
        attachment: "platform",
      });
      const verified = verify();
      expect(verified).toMatchObject({
        credentialId: created.credential.id.toString("base64url"),
        algorithm,
        signCount: 0,
        transports: ["internal", "hybrid"],
        authenticatorAttachment: "platform",
      });
    },
  );

  it("refuses a packed attestation with a bad signature", () => {
    for (const attestation of ["packed", "packed-x5c"] as const) {
      const { verify } = register(new SoftwareAuthenticator(), {
        attestation,
        badAttestationSignature: true,
      });
      expect(verify).toThrow(InvalidParameterError);
    }
  });

  it("refuses a credential for another challenge, origin or relying party", () => {
    const authenticator = new SoftwareAuthenticator();
    expect(register(authenticator, { challenge: "b3RoZXI" }).verify).toThrow(
      WebAuthnChallengeNotFoundError,
    );
    expect(
      register(authenticator, { origin: "https://example.test" }).verify,
    ).toThrow(WebAuthnOriginNotAllowedError);
    expect(register(authenticator, { rpId: "example.test" }).verify).toThrow(
      WebAuthnRelyingPartyMismatchError,
    );
    expect(register(authenticator, { type: "webauthn.get" }).verify).toThrow(
      InvalidParameterError,
    );
  });

  it("checks user presence, and user verification when the pool requires it", () => {
    const authenticator = new SoftwareAuthenticator();
    expect(register(authenticator, { userPresent: false }).verify).toThrow(
      InvalidParameterError,
    );
    expect(
      register(authenticator, { userVerified: false }, true).verify,
    ).toThrow(WebAuthnCredentialNotSupportedError);
    expect(
      register(authenticator, { userVerified: false }, false).verify(),
    ).toBeTruthy();
  });

  it("refuses algorithms other than ES256 and RS256", () => {
    expect(
      register(new SoftwareAuthenticator(), { algorithm: -8 }).verify,
    ).toThrow(WebAuthnCredentialNotSupportedError);
  });

  it("refuses malformed credentials", () => {
    const base = { expectedChallenge: CHALLENGE, rpId: RP_ID };
    const verify = (credential: unknown) => () =>
      verifyRegistration({
        ...base,
        credential,
        requireUserVerification: false,
      });
    expect(verify("not json")).toThrow(InvalidParameterError);
    expect(verify({ id: "x" })).toThrow(InvalidParameterError);
    expect(verify({ response: { clientDataJSON: "e30" } })).toThrow(
      InvalidParameterError,
    );

    const { created } = register(new SoftwareAuthenticator());
    expect(
      verify({
        ...created.response,
        response: { ...created.response.response, attestationObject: "AAAA" },
      }),
    ).toThrow(InvalidParameterError);
    expect(verify({ ...created.response, rawId: "b3RoZXI" })).toThrow(
      InvalidParameterError,
    );
    expect(verify(JSON.stringify(created.response))()).toBeTruthy();
  });
});

describe("verifyAssertion", () => {
  const AUTH_CHALLENGE = Buffer.from("sign-in-challenge").toString("base64url");
  const HANDLE = Buffer.from("sub-1").toString("base64url");

  const setUpCredential = (algorithm: -7 | -257 = -7) => {
    const authenticator = new SoftwareAuthenticator();
    const { created, verify } = register(authenticator, {
      algorithm,
      userHandle: HANDLE,
    });
    const verified = verify();
    const stored: WebAuthnCredential = {
      CredentialId: verified.credentialId,
      PublicKey: verified.publicKey,
      Algorithm: verified.algorithm,
      SignCount: verified.signCount,
      RelyingPartyId: RP_ID,
      FriendlyCredentialName: "Passkey",
      AuthenticatorTransports: [],
      CreatedDate: new Date(),
    };
    const assert = (
      options: Partial<Parameters<SoftwareAuthenticator["get"]>[1]> = {},
      overrides: Partial<Parameters<typeof verifyAssertion>[0]> = {},
    ) =>
      verifyAssertion({
        credential: JSON.stringify(
          authenticator.get(created.credential, {
            rpId: RP_ID,
            origin: ORIGIN,
            challenge: AUTH_CHALLENGE,
            ...options,
          }),
        ),
        expectedChallenge: AUTH_CHALLENGE,
        rpId: RP_ID,
        stored,
        requireUserVerification: false,
        expectedUserHandle: HANDLE,
        ...overrides,
      });
    return { stored, assert };
  };

  it("accepts a valid ES256 or RS256 assertion and returns the counter", () => {
    expect(setUpCredential(-7).assert()).toEqual({
      signCount: 1,
      userVerified: true,
    });
    expect(setUpCredential(-257).assert().signCount).toEqual(1);
  });

  it("refuses a bad signature, challenge, origin, type or relying party", () => {
    const { assert, stored } = setUpCredential();
    expect(() => assert({ badSignature: true })).toThrow(NotAuthorizedError);
    expect(() => assert({ challenge: "b3RoZXI" })).toThrow(NotAuthorizedError);
    expect(() => assert({ origin: "https://example.test" })).toThrow(
      NotAuthorizedError,
    );
    expect(() => assert({ type: "webauthn.create" })).toThrow(
      NotAuthorizedError,
    );
    expect(() => assert({ rpId: "example.test" })).toThrow(NotAuthorizedError);
    expect(() =>
      assert({}, { stored: { ...stored, RelyingPartyId: "example.test" } }),
    ).toThrow(NotAuthorizedError);
  });

  it("checks user presence, and user verification when required", () => {
    const { assert } = setUpCredential();
    expect(() => assert({ userPresent: false })).toThrow(NotAuthorizedError);
    expect(() =>
      assert({ userVerified: false }, { requireUserVerification: true }),
    ).toThrow(NotAuthorizedError);
    expect(assert({ userVerified: false }).userVerified).toEqual(false);
  });

  it("refuses a counter that does not grow, unless the authenticator keeps none", () => {
    const { assert, stored } = setUpCredential();
    expect(() =>
      assert({ signCount: 5 }, { stored: { ...stored, SignCount: 5 } }),
    ).toThrow(NotAuthorizedError);
    expect(() =>
      assert({ signCount: 0 }, { stored: { ...stored, SignCount: 5 } }),
    ).toThrow(NotAuthorizedError);
    expect(assert({ signCount: 0 }).signCount).toEqual(0);
  });

  it("refuses a user handle for another user, and accepts none", () => {
    const { assert } = setUpCredential();
    expect(() =>
      assert({ userHandle: Buffer.from("sub-2").toString("base64url") }),
    ).toThrow(NotAuthorizedError);
    expect(assert({ userHandle: null }).signCount).toEqual(2);
  });

  it("matches the user handle that registration options carry", () => {
    const user = TDB.user({ Attributes: [{ Name: "sub", Value: "sub-1" }] });
    expect(userHandle(user)).toEqual(HANDLE);
  });
});
