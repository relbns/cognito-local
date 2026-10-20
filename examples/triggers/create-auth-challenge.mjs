// CreateAuthChallenge (ES module): a new 6-digit code for the first round, the same code on retries.
import { randomInt } from "node:crypto";

export const handler = async (event) => {
  const session = event.request.session ?? [];
  const previous = session.findLast?.((s) => s.challengeMetadata?.startsWith("CODE-"));
  const code = previous
    ? previous.challengeMetadata.slice("CODE-".length)
    : String(randomInt(0, 1_000_000)).padStart(6, "0");

  if (!previous) {
    console.log(`[otp] code for ${event.request.userAttributes.email ?? event.userName}: ${code}`);
  }

  event.response.publicChallengeParameters = {
    email: event.request.userAttributes.email ?? "",
  };
  event.response.privateChallengeParameters = { answer: code };
  event.response.challengeMetadata = `CODE-${code}`;
  return event;
};
