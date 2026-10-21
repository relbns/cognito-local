import {
  CognitoIdentityProviderClient,
  CreateManagedLoginBrandingCommand,
  CreateTermsCommand,
  CreateUserPoolClientCommand,
  CreateUserPoolCommand,
  CreateUserPoolDomainCommand,
  DeleteManagedLoginBrandingCommand,
  DeleteTermsCommand,
  DescribeManagedLoginBrandingByClientCommand,
  DescribeManagedLoginBrandingCommand,
  DescribeTermsCommand,
  DescribeUserPoolDomainCommand,
  GetUICustomizationCommand,
  ListTermsCommand,
  ResourceNotFoundException,
  SetUICustomizationCommand,
  UpdateManagedLoginBrandingCommand,
  UpdateTermsCommand,
  UpdateUserPoolDomainCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import { describe, expect, it } from "vitest";
import { withCognitoSdk } from "../aws-sdk/setup";

const credentials = { accessKeyId: "local", secretAccessKey: "local" };

describe(
  "Managed login settings",
  withCognitoSdk((_, { serverUrl }) => {
    const setUp = async () => {
      const cognito = new CognitoIdentityProviderClient({
        endpoint: serverUrl(),
        region: "local",
        credentials,
        maxAttempts: 1,
      });
      const pool = await cognito.send(
        new CreateUserPoolCommand({ PoolName: "managed-login" }),
      );
      const userPoolId = pool.UserPool?.Id as string;
      const client = await cognito.send(
        new CreateUserPoolClientCommand({
          UserPoolId: userPoolId,
          ClientName: "web",
        }),
      );
      return {
        cognito,
        userPoolId,
        clientId: client.UserPoolClient?.ClientId as string,
      };
    };

    describe("terms", () => {
      it("creates, describes, lists, updates and deletes terms of use", async () => {
        const { cognito, userPoolId, clientId } = await setUp();

        const created = await cognito.send(
          new CreateTermsCommand({
            UserPoolId: userPoolId,
            ClientId: clientId,
            TermsName: "terms-of-use",
            TermsSource: "LINK",
            Enforcement: "NONE",
            Links: { "cognito:default": "https://example.test/terms" },
          }),
        );
        const TermsId = created.Terms?.TermsId as string;
        expect(created.Terms).toEqual({
          TermsId: expect.stringMatching(/^[0-9a-f-]{36}$/),
          UserPoolId: userPoolId,
          ClientId: clientId,
          TermsName: "terms-of-use",
          TermsSource: "LINK",
          Enforcement: "NONE",
          Links: { "cognito:default": "https://example.test/terms" },
          CreationDate: expect.any(Date),
          LastModifiedDate: expect.any(Date),
        });

        await cognito.send(
          new UpdateTermsCommand({
            UserPoolId: userPoolId,
            TermsId,
            Links: { "cognito:default": "https://example.test/terms-v2" },
          }),
        );
        const described = await cognito.send(
          new DescribeTermsCommand({ UserPoolId: userPoolId, TermsId }),
        );
        expect(described.Terms).toMatchObject({
          TermsName: "terms-of-use",
          Links: { "cognito:default": "https://example.test/terms-v2" },
        });

        const listed = await cognito.send(
          new ListTermsCommand({ UserPoolId: userPoolId }),
        );
        expect(listed.Terms).toEqual([
          {
            TermsId,
            TermsName: "terms-of-use",
            Enforcement: "NONE",
            CreationDate: expect.any(Date),
            LastModifiedDate: expect.any(Date),
          },
        ]);

        await cognito.send(
          new DeleteTermsCommand({ UserPoolId: userPoolId, TermsId }),
        );
        await expect(
          cognito.send(
            new DescribeTermsCommand({ UserPoolId: userPoolId, TermsId }),
          ),
        ).rejects.toBeInstanceOf(ResourceNotFoundException);
        await expect(
          cognito.send(
            new UpdateTermsCommand({ UserPoolId: userPoolId, TermsId }),
          ),
        ).rejects.toBeInstanceOf(ResourceNotFoundException);
        await expect(
          cognito.send(
            new DeleteTermsCommand({ UserPoolId: userPoolId, TermsId }),
          ),
        ).rejects.toBeInstanceOf(ResourceNotFoundException);
      });

      it("pages the list of terms", async () => {
        const { cognito, userPoolId, clientId } = await setUp();
        for (const TermsName of ["terms-of-use", "privacy-policy"]) {
          await cognito.send(
            new CreateTermsCommand({
              UserPoolId: userPoolId,
              ClientId: clientId,
              TermsName,
              TermsSource: "LINK",
              Enforcement: "NONE",
            }),
          );
        }

        const first = await cognito.send(
          new ListTermsCommand({ UserPoolId: userPoolId, MaxResults: 1 }),
        );
        const second = await cognito.send(
          new ListTermsCommand({
            UserPoolId: userPoolId,
            MaxResults: 1,
            NextToken: first.NextToken,
          }),
        );

        expect(first.Terms?.map((t) => t.TermsName)).toEqual(["terms-of-use"]);
        expect(second.Terms?.map((t) => t.TermsName)).toEqual([
          "privacy-policy",
        ]);
        expect(second.NextToken).toBeUndefined();
      });
    });

    describe("branding", () => {
      it("creates, finds by client, updates and deletes a branding style", async () => {
        const { cognito, userPoolId, clientId } = await setUp();

        const created = await cognito.send(
          new CreateManagedLoginBrandingCommand({
            UserPoolId: userPoolId,
            ClientId: clientId,
            Settings: { components: { pageBackground: { color: "ffffffff" } } },
          }),
        );
        const ManagedLoginBrandingId = created.ManagedLoginBranding
          ?.ManagedLoginBrandingId as string;
        expect(created.ManagedLoginBranding).toMatchObject({
          UserPoolId: userPoolId,
          UseCognitoProvidedValues: false,
          Settings: { components: { pageBackground: { color: "ffffffff" } } },
        });

        const byClient = await cognito.send(
          new DescribeManagedLoginBrandingByClientCommand({
            UserPoolId: userPoolId,
            ClientId: clientId,
          }),
        );
        expect(byClient.ManagedLoginBranding?.ManagedLoginBrandingId).toBe(
          ManagedLoginBrandingId,
        );

        await cognito.send(
          new UpdateManagedLoginBrandingCommand({
            UserPoolId: userPoolId,
            ManagedLoginBrandingId,
            UseCognitoProvidedValues: true,
          }),
        );
        const described = await cognito.send(
          new DescribeManagedLoginBrandingCommand({
            UserPoolId: userPoolId,
            ManagedLoginBrandingId,
          }),
        );
        expect(described.ManagedLoginBranding).toMatchObject({
          UseCognitoProvidedValues: true,
          Settings: { components: { pageBackground: { color: "ffffffff" } } },
        });

        await cognito.send(
          new DeleteManagedLoginBrandingCommand({
            UserPoolId: userPoolId,
            ManagedLoginBrandingId,
          }),
        );
        for (const command of [
          new DescribeManagedLoginBrandingCommand({
            UserPoolId: userPoolId,
            ManagedLoginBrandingId,
          }),
          new DescribeManagedLoginBrandingByClientCommand({
            UserPoolId: userPoolId,
            ClientId: clientId,
          }),
          new UpdateManagedLoginBrandingCommand({
            UserPoolId: userPoolId,
            ManagedLoginBrandingId,
          }),
          new DeleteManagedLoginBrandingCommand({
            UserPoolId: userPoolId,
            ManagedLoginBrandingId,
          }),
        ]) {
          await expect(cognito.send(command as any)).rejects.toBeInstanceOf(
            ResourceNotFoundException,
          );
        }
      });
    });

    describe("UI customization", () => {
      it("returns the pool default until CSS is set", async () => {
        const { cognito, userPoolId } = await setUp();

        const before = await cognito.send(
          new GetUICustomizationCommand({ UserPoolId: userPoolId }),
        );
        expect(before.UICustomization).toEqual({
          UserPoolId: userPoolId,
          ClientId: "ALL",
        });

        await cognito.send(
          new SetUICustomizationCommand({
            UserPoolId: userPoolId,
            CSS: ".banner-customizable { background-color: white; }",
          }),
        );
        const after = await cognito.send(
          new GetUICustomizationCommand({ UserPoolId: userPoolId }),
        );
        expect(after.UICustomization).toMatchObject({
          UserPoolId: userPoolId,
          ClientId: "ALL",
          CSS: ".banner-customizable { background-color: white; }",
          CSSVersion: "1",
          LastModifiedDate: expect.any(Date),
        });
      });
    });

    describe("domain", () => {
      it("moves the pool to a new domain", async () => {
        const { cognito, userPoolId } = await setUp();
        await cognito.send(
          new CreateUserPoolDomainCommand({
            UserPoolId: userPoolId,
            Domain: "example-old",
          }),
        );

        const updated = await cognito.send(
          new UpdateUserPoolDomainCommand({
            UserPoolId: userPoolId,
            Domain: "example-new",
            CustomDomainConfig: {
              CertificateArn:
                "arn:aws:acm:us-east-1:123456789012:certificate/example",
            },
          }),
        );

        expect(updated.CloudFrontDomain).toBe("example-new");
        const found = await cognito.send(
          new DescribeUserPoolDomainCommand({ Domain: "example-new" }),
        );
        expect(found.DomainDescription).toMatchObject({
          UserPoolId: userPoolId,
          Status: "ACTIVE",
        });
        const old = await cognito.send(
          new DescribeUserPoolDomainCommand({ Domain: "example-old" }),
        );
        expect(old.DomainDescription).toEqual({});
      });
    });
  }),
);
