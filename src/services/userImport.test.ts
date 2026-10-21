import { describe, expect, it } from "vitest";
import { ClockFake } from "../__tests__/clockFake";
import { newMockUserPoolService } from "../__tests__/mockUserPoolService";
import { TestContext } from "../__tests__/testContext";
import * as TDB from "../__tests__/testDataBuilder";
import {
  COMPLETED_SUCCESSFULLY,
  csvHeaderFor,
  parseCsv,
  runUserImport,
  TOO_MANY_FAILURES,
  toUserImportJob,
  userImportUrl,
} from "./userImport";
import type { User } from "./userPoolService";

const clock = new ClockFake(new Date("2026-01-01T00:00:00Z"));

const poolWith = (partial: Parameters<typeof TDB.userPool>[0] = {}) => {
  const pool = newMockUserPoolService(
    TDB.userPool({ Id: "local_Import", ...partial }),
  );
  pool.getUserByUsername.mockResolvedValue(null);
  return pool;
};

const saved = (pool: ReturnType<typeof poolWith>): User[] =>
  pool.saveUser.mock.calls.map((call) => call[1]);

describe("parseCsv", () => {
  it("handles quotes, doubled quotes, CRLF, a BOM and a missing final newline", () => {
    expect(parseCsv('﻿a,b,c\r\n"x, y","say ""hi""",\n1,2,3')).toEqual([
      ["a", "b", "c"],
      ["x, y", 'say "hi"', ""],
      ["1", "2", "3"],
    ]);
  });

  it("keeps a newline inside a quoted field", () => {
    expect(parseCsv('a\n"line 1\nline 2"\n')).toEqual([
      ["a"],
      ["line 1\nline 2"],
    ]);
  });
});

describe("csvHeaderFor", () => {
  it("adds the pool's custom attributes before the cognito columns", () => {
    const header = csvHeaderFor(
      TDB.userPool({
        SchemaAttributes: [
          { Name: "email", AttributeDataType: "String" },
          { Name: "custom:team", AttributeDataType: "String" },
        ],
      }),
    );

    expect(header.slice(-4)).toEqual([
      "updated_at",
      "custom:team",
      "cognito:mfa_enabled",
      "cognito:username",
    ]);
    expect(header[0]).toBe("name");
  });
});

describe("runUserImport", () => {
  it("fails the job without an upload or with an empty file", async () => {
    const pool = poolWith();

    expect(
      await runUserImport(TestContext, pool, clock, undefined),
    ).toMatchObject({ status: "Failed", imported: 0 });
    expect(await runUserImport(TestContext, pool, clock, "")).toMatchObject({
      status: "Failed",
      completionMessage: "The CSV file is empty.",
    });
  });

  it("needs the username and MFA columns, once each", async () => {
    const pool = poolWith();

    expect(
      (await runUserImport(TestContext, pool, clock, "email\n"))
        .completionMessage,
    ).toBe("The CSV header is missing cognito:username, cognito:mfa_enabled.");
    expect(
      (
        await runUserImport(
          TestContext,
          pool,
          clock,
          "cognito:username,cognito:mfa_enabled,email,email\n",
        )
      ).completionMessage,
    ).toBe("The CSV header has email twice.");
  });

  it("accepts the columns in any order and records each failed line", async () => {
    const pool = poolWith({
      SchemaAttributes: [
        { Name: "custom:team", AttributeDataType: "String" },
        { Name: "family_name", AttributeDataType: "String", Required: true },
      ],
    });
    const csv = [
      "cognito:mfa_enabled,cognito:username,email,phone_number,family_name,custom:team",
      "false,ana,ana@example.com,,Doe,blue",
      "maybe,bad-mfa,,,Doe,",
      "true,no-phone,,,Doe,",
      "false,bad-phone,,555-0100,Doe,",
      "false,bad-email,not-an-email,,Doe,",
      "false,no-family,,,,",
      "false,short",
      ",,,,,",
    ].join("\n");

    const result = await runUserImport(TestContext, pool, clock, csv);

    expect(result).toMatchObject({
      status: "Succeeded",
      completionMessage: COMPLETED_SUCCESSFULLY,
      imported: 1,
      failed: 6,
      skipped: 0,
    });
    expect(result.log).toEqual([
      "[ERROR] Line Number 3 - cognito:mfa_enabled must be TRUE or FALSE.",
      "[ERROR] Line Number 4 - cognito:mfa_enabled is TRUE, but the record has no phone_number.",
      "[ERROR] Line Number 5 - Invalid phone number format.",
      "[ERROR] Line Number 6 - Invalid email address format.",
      "[ERROR] Line Number 7 - The attribute family_name is required.",
      "[ERROR] Line Number 8 - The record has 2 fields, but the header has 6.",
    ]);
    expect(saved(pool)).toEqual([
      {
        Username: "ana",
        Password: "",
        Attributes: [
          { Name: "custom:team", Value: "blue" },
          { Name: "email", Value: "ana@example.com" },
          { Name: "family_name", Value: "Doe" },
          { Name: "sub", Value: expect.any(String) },
        ],
        Enabled: true,
        UserStatus: "RESET_REQUIRED",
        UserCreateDate: clock.get(),
        UserLastModifiedDate: clock.get(),
        RefreshTokens: [],
      },
    ]);
  });

  it("uses the sub as the username when the pool signs in with email", async () => {
    const pool = poolWith({ UsernameAttributes: ["email"] });
    const csv = [
      "cognito:username,cognito:mfa_enabled,email",
      "ana@example.com,FALSE,",
      "someone,FALSE,",
    ].join("\n");

    const result = await runUserImport(TestContext, pool, clock, csv);

    expect(result.log).toEqual([
      "[ERROR] Line Number 3 - The user pool uses email as the username, but the record has no email.",
    ]);
    const [user] = saved(pool);
    expect(user.Username).toMatch(/^[0-9a-f-]{36}$/);
    expect(user.Attributes).toContainEqual({
      Name: "email",
      Value: "ana@example.com",
    });
    expect(user.Attributes).toContainEqual({
      Name: "sub",
      Value: user.Username,
    });
  });

  it("refuses an existing user and fails the job when every user fails", async () => {
    const pool = poolWith();
    pool.getUserByUsername.mockResolvedValue(TDB.user({ Username: "ana" }));

    const result = await runUserImport(
      TestContext,
      pool,
      clock,
      "cognito:username,cognito:mfa_enabled\nana,FALSE\n",
    );

    expect(result).toMatchObject({
      status: "Failed",
      completionMessage: TOO_MANY_FAILURES,
      failed: 1,
      log: ["[ERROR] Line Number 2 - User already exists."],
    });
    expect(pool.saveUser).not.toHaveBeenCalled();
  });
});

describe("user import job helpers", () => {
  it("keeps internal fields out of the API shape", () => {
    expect(
      toUserImportJob({
        JobId: "import-1",
        Status: "Created",
        _uploadToken: "secret",
        _csv: "a",
        _log: [],
      }),
    ).toEqual({ JobId: "import-1", Status: "Created" });
  });

  it("builds the upload URL from the public base URL", () => {
    expect(
      userImportUrl("http://localhost:9229/", "local_Import", "import-1", "t"),
    ).toBe(
      "http://localhost:9229/_import/local_Import/import-1?X-Amz-Signature=t",
    );
  });
});
