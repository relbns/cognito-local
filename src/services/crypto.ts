import {
  buildClient,
  CommitmentPolicy,
  KMS,
  KmsKeyringNode,
} from "@aws-crypto/client-node";
import type { SdkV3ClientConfig } from "./awsClientConfig";
import type { Context } from "./context";

export interface KMSConfig {
  KMSKeyId?: string;
  KMSKeyAlias?: string;
}

const { encrypt } = buildClient(CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT);

export class CryptoService {
  _keyringNode?: KmsKeyringNode;
  config?: KMSConfig;
  clientConfig: SdkV3ClientConfig;

  constructor(config?: KMSConfig, clientConfig: SdkV3ClientConfig = {}) {
    this.config = config;
    this.clientConfig = clientConfig;
  }

  get keyringNode(): KmsKeyringNode {
    if (this._keyringNode) {
      return this._keyringNode;
    }

    if (!this.config || !this.config.KMSKeyAlias || !this.config.KMSKeyId) {
      throw new Error(
        "KMSConfig.KMSKeyAlias and KMSConfig.KMSKeyId is required when using a CustomEmailSender trigger.",
      );
    }

    const generatorKeyId = this.config.KMSKeyAlias;
    const keyIds = [this.config.KMSKeyId];

    this._keyringNode = new KmsKeyringNode({
      generatorKeyId,
      keyIds,
      clientProvider: () => new KMS(this.clientConfig),
    });

    return this._keyringNode;
  }

  async encrypt(ctx: Context, plaintext: string): Promise<string> {
    ctx.logger.debug({ plaintext }, "encrypting code");

    const { result } = await encrypt(this.keyringNode, plaintext);

    const encryptedCode = result.toString("base64");

    ctx.logger.debug({ encryptedCode }, "code succesfully encrypted");

    return encryptedCode;
  }
}
