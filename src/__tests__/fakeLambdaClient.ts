import type { LambdaClient } from "../services/lambda";

// biome-ignore lint/suspicious/noExplicitAny: trigger events are untyped JSON
type TriggerHandler = (functionName: string, event: any) => unknown;

export const fakeLambdaClient = (handle: TriggerHandler): LambdaClient => ({
  invoke: (async (params: { FunctionName: string; Payload: Uint8Array }) => {
    const event = JSON.parse(new TextDecoder().decode(params.Payload));
    let result: unknown;
    try {
      result = await handle(params.FunctionName, event);
    } catch (e) {
      // A handler that throws comes back the way Lambda reports an unhandled error.
      return {
        $metadata: {},
        StatusCode: 200,
        FunctionError: "Unhandled",
        Payload: new TextEncoder().encode(
          JSON.stringify({ errorMessage: (e as Error).message }),
        ),
      };
    }
    return {
      $metadata: {},
      StatusCode: 200,
      Payload: new TextEncoder().encode(JSON.stringify(result)),
    };
  }) as unknown as LambdaClient["invoke"],
});
