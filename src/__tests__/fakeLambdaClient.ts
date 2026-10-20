import type { LambdaClient } from "../services/lambda";

// biome-ignore lint/suspicious/noExplicitAny: trigger events are untyped JSON
type TriggerHandler = (functionName: string, event: any) => unknown;

export const fakeLambdaClient = (handle: TriggerHandler): LambdaClient => ({
  invoke: (async (params: { FunctionName: string; Payload: Uint8Array }) => {
    const event = JSON.parse(new TextDecoder().decode(params.Payload));
    const result = await handle(params.FunctionName, event);
    return {
      $metadata: {},
      StatusCode: 200,
      Payload: new TextEncoder().encode(JSON.stringify(result)),
    };
  }) as unknown as LambdaClient["invoke"],
});
