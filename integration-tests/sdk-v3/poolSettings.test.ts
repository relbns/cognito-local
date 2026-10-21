import {
  AdminCreateUserCommand,
  AdminListUserAuthEventsCommand,
  AdminUpdateAuthEventFeedbackCommand,
  CognitoIdentityProviderClient,
  CreateIdentityProviderCommand,
  CreateResourceServerCommand,
  CreateUserPoolCommand,
  DescribeRiskConfigurationCommand,
  GetIdentityProviderByIdentifierCommand,
  GetLogDeliveryConfigurationCommand,
  GetSigningCertificateCommand,
  ListIdentityProvidersCommand,
  ListResourceServersCommand,
  ResourceNotFoundException,
  SetLogDeliveryConfigurationCommand,
  SetRiskConfigurationCommand,
  UpdateAuthEventFeedbackCommand,
  UpdateIdentityProviderCommand,
  UpdateResourceServerCommand,
} from "@aws-sdk/client-cognito-identity-provider";
import { describe, expect, it } from "vitest";
import { withCognitoSdk } from "../aws-sdk/setup";

const credentials = { accessKeyId: "local", secretAccessKey: "local" };
const MISSING_POOL = "us-east-1_Missing00";

describe(
  "Pool settings",
  withCognitoSdk((_, { serverUrl }) => {
    const setUp = async () => {
      const cognito = new CognitoIdentityProviderClient({
        endpoint: serverUrl(),
        region: "local",
        credentials,
        maxAttempts: 1,
      });
      const pool = await cognito.send(
        new CreateUserPoolCommand({
          PoolName: "settings",
          UsernameAttributes: [],
        }),
      );
      return { cognito, userPoolId: pool.UserPool?.Id as string };
    };

    it("returns an empty risk configuration until one is set", async () => {
      const { cognito, userPoolId } = await setUp();

      const before = await cognito.send(
        new DescribeRiskConfigurationCommand({ UserPoolId: userPoolId }),
      );
      expect(before.RiskConfiguration).toEqual({ UserPoolId: userPoolId });

      await cognito.send(
        new SetRiskConfigurationCommand({
          UserPoolId: userPoolId,
          CompromisedCredentialsRiskConfiguration: {
            EventFilter: ["SIGN_IN"],
            Actions: { EventAction: "BLOCK" },
          },
          RiskExceptionConfiguration: {
            BlockedIPRangeList: ["192.0.2.0/24"],
          },
        }),
      );
      const after = await cognito.send(
        new DescribeRiskConfigurationCommand({ UserPoolId: userPoolId }),
      );
      expect(after.RiskConfiguration).toEqual({
        UserPoolId: userPoolId,
        CompromisedCredentialsRiskConfiguration: {
          EventFilter: ["SIGN_IN"],
          Actions: { EventAction: "BLOCK" },
        },
        RiskExceptionConfiguration: { BlockedIPRangeList: ["192.0.2.0/24"] },
      });
    });

    it("keeps the log delivery configuration it is given", async () => {
      const { cognito, userPoolId } = await setUp();

      const before = await cognito.send(
        new GetLogDeliveryConfigurationCommand({ UserPoolId: userPoolId }),
      );
      expect(before.LogDeliveryConfiguration).toEqual({
        UserPoolId: userPoolId,
        LogConfigurations: [],
      });

      const LogConfigurations = [
        {
          LogLevel: "ERROR" as const,
          EventSource: "userNotification" as const,
          CloudWatchLogsConfiguration: {
            LogGroupArn:
              "arn:aws:logs:us-east-1:123456789012:log-group:example",
          },
        },
      ];
      await cognito.send(
        new SetLogDeliveryConfigurationCommand({
          UserPoolId: userPoolId,
          LogConfigurations,
        }),
      );
      const after = await cognito.send(
        new GetLogDeliveryConfigurationCommand({ UserPoolId: userPoolId }),
      );
      expect(after.LogDeliveryConfiguration).toEqual({
        UserPoolId: userPoolId,
        LogConfigurations,
      });
    });

    it("accepts auth event feedback and lists no auth events", async () => {
      const { cognito, userPoolId } = await setUp();
      await cognito.send(
        new AdminCreateUserCommand({
          UserPoolId: userPoolId,
          Username: "events-user",
          MessageAction: "SUPPRESS",
        }),
      );

      const events = await cognito.send(
        new AdminListUserAuthEventsCommand({
          UserPoolId: userPoolId,
          Username: "events-user",
        }),
      );
      expect(events.AuthEvents).toEqual([]);
      expect(events.NextToken).toBeUndefined();
      await expect(
        cognito.send(
          new AdminUpdateAuthEventFeedbackCommand({
            UserPoolId: userPoolId,
            Username: "events-user",
            EventId: "example-event",
            FeedbackValue: "Valid",
          }),
        ),
      ).resolves.toBeDefined();
      await expect(
        cognito.send(
          new UpdateAuthEventFeedbackCommand({
            UserPoolId: userPoolId,
            Username: "events-user",
            EventId: "example-event",
            FeedbackToken: "example-token",
            FeedbackValue: "Invalid",
          }),
        ),
      ).resolves.toBeDefined();
    });

    it("returns a signing certificate for the pool", async () => {
      const { cognito, userPoolId } = await setUp();

      const result = await cognito.send(
        new GetSigningCertificateCommand({ UserPoolId: userPoolId }),
      );

      expect(result.Certificate).toMatch(/^[A-Za-z0-9+/]+=*$/);
    });

    it.each([
      new DescribeRiskConfigurationCommand({ UserPoolId: MISSING_POOL }),
      new GetLogDeliveryConfigurationCommand({ UserPoolId: MISSING_POOL }),
      new GetSigningCertificateCommand({ UserPoolId: MISSING_POOL }),
      new AdminListUserAuthEventsCommand({
        UserPoolId: MISSING_POOL,
        Username: "anyone",
      }),
    ])("refuses $constructor.name on an unknown pool", async (command) => {
      const { cognito } = await setUp();

      await expect(cognito.send(command as any)).rejects.toBeInstanceOf(
        ResourceNotFoundException,
      );
    });

    describe("resource servers", () => {
      it("renames a resource server and replaces its scopes", async () => {
        const { cognito, userPoolId } = await setUp();
        for (const [Identifier, Name] of [
          ["https://api.example.test", "API"],
          ["https://admin.example.test", "Admin"],
        ]) {
          await cognito.send(
            new CreateResourceServerCommand({
              UserPoolId: userPoolId,
              Identifier,
              Name,
              Scopes: [{ ScopeName: "read", ScopeDescription: "Read" }],
            }),
          );
        }

        const updated = await cognito.send(
          new UpdateResourceServerCommand({
            UserPoolId: userPoolId,
            Identifier: "https://api.example.test",
            Name: "Example API",
            Scopes: [{ ScopeName: "write", ScopeDescription: "Write" }],
          }),
        );
        expect(updated.ResourceServer).toEqual({
          UserPoolId: userPoolId,
          Identifier: "https://api.example.test",
          Name: "Example API",
          Scopes: [{ ScopeName: "write", ScopeDescription: "Write" }],
        });

        const first = await cognito.send(
          new ListResourceServersCommand({
            UserPoolId: userPoolId,
            MaxResults: 1,
          }),
        );
        const second = await cognito.send(
          new ListResourceServersCommand({
            UserPoolId: userPoolId,
            MaxResults: 1,
            NextToken: first.NextToken,
          }),
        );
        expect(first.ResourceServers?.map((s) => s.Name)).toEqual([
          "Example API",
        ]);
        expect(second.ResourceServers?.map((s) => s.Identifier)).toEqual([
          "https://admin.example.test",
        ]);
        expect(second.NextToken).toBeUndefined();
      });

      it("refuses to update an unknown resource server", async () => {
        const { cognito, userPoolId } = await setUp();

        await expect(
          cognito.send(
            new UpdateResourceServerCommand({
              UserPoolId: userPoolId,
              Identifier: "https://missing.example.test",
              Name: "Missing",
            }),
          ),
        ).rejects.toBeInstanceOf(ResourceNotFoundException);
      });
    });

    describe("identity providers", () => {
      const createOidc = (
        cognito: CognitoIdentityProviderClient,
        userPoolId: string,
      ) =>
        cognito.send(
          new CreateIdentityProviderCommand({
            UserPoolId: userPoolId,
            ProviderName: "ExampleOIDC",
            ProviderType: "OIDC",
            IdpIdentifiers: ["example-oidc"],
            ProviderDetails: {
              client_id: "example-oidc-client",
              client_secret: "example-oidc-secret",
              oidc_issuer: "https://login.example.test",
              authorize_scopes: "openid email",
              attributes_request_method: "GET",
            },
            AttributeMapping: { email: "email", username: "sub" },
          }),
        );

      it("updates the mapping and identifiers, and finds the provider by its new identifier", async () => {
        const { cognito, userPoolId } = await setUp();
        await createOidc(cognito, userPoolId);

        const updated = await cognito.send(
          new UpdateIdentityProviderCommand({
            UserPoolId: userPoolId,
            ProviderName: "ExampleOIDC",
            AttributeMapping: { email: "email", name: "name", username: "sub" },
            IdpIdentifiers: ["example-renamed"],
          }),
        );
        expect(updated.IdentityProvider).toMatchObject({
          ProviderName: "ExampleOIDC",
          AttributeMapping: { email: "email", name: "name", username: "sub" },
          IdpIdentifiers: ["example-renamed"],
          ProviderDetails: expect.objectContaining({
            client_id: "example-oidc-client",
          }),
        });

        const found = await cognito.send(
          new GetIdentityProviderByIdentifierCommand({
            UserPoolId: userPoolId,
            IdpIdentifier: "example-renamed",
          }),
        );
        expect(found.IdentityProvider?.ProviderName).toBe("ExampleOIDC");
        await expect(
          cognito.send(
            new GetIdentityProviderByIdentifierCommand({
              UserPoolId: userPoolId,
              IdpIdentifier: "example-oidc",
            }),
          ),
        ).rejects.toBeInstanceOf(ResourceNotFoundException);
      });

      it("lists the providers of the pool", async () => {
        const { cognito, userPoolId } = await setUp();
        await createOidc(cognito, userPoolId);

        const listed = await cognito.send(
          new ListIdentityProvidersCommand({ UserPoolId: userPoolId }),
        );

        expect(listed.Providers).toEqual([
          expect.objectContaining({
            ProviderName: "ExampleOIDC",
            ProviderType: "OIDC",
          }),
        ]);
      });

      it("refuses to update an unknown provider", async () => {
        const { cognito, userPoolId } = await setUp();

        await expect(
          cognito.send(
            new UpdateIdentityProviderCommand({
              UserPoolId: userPoolId,
              ProviderName: "Missing",
              AttributeMapping: { email: "email" },
            }),
          ),
        ).rejects.toBeInstanceOf(ResourceNotFoundException);
      });
    });
  }),
);
