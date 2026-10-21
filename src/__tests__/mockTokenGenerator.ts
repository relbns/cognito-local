import { type MockedObject, vi } from "vitest";
import type { TokenGenerator } from "../services/tokenGenerator";

export const newMockTokenGenerator = (): MockedObject<TokenGenerator> => ({
  generate: vi.fn().mockResolvedValue({
    AccessToken: "access",
    IdToken: "id",
    RefreshToken: "refresh",
    ExpiresIn: 3600,
    TokenType: "Bearer",
  }),
  generateClientCredentials: vi.fn().mockResolvedValue({
    AccessToken: "access",
    ExpiresIn: 3600,
    TokenType: "Bearer",
  }),
});
