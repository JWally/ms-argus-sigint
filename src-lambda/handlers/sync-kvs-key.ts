/**
 * CloudFormation custom resource: sync a Secrets Manager value into a
 * CloudFront KeyValueStore key.
 *
 * Runs at every deploy (Timestamp property forces update) to keep the
 * CF KVS entry in lockstep with the shared SIGINT AES secret — so the
 * CloudFront Function can verify tokens using the same key the API does.
 *
 * On Delete: no-op. Deliberately preserves the key so that if the custom
 * resource is replaced but the KVS itself persists, existing cookies
 * continue to verify.
 */

// Side-effect import: registers SigV4A signer in the shared @smithy/signature-v4
// container at module load time. CloudFront KVS requires SigV4A (multi-region
// asymmetric) signing, which isn't bundled into the base AWS SDK.
import "@aws-sdk/signature-v4a";
import {
  CloudFrontKeyValueStoreClient,
  DescribeKeyValueStoreCommand,
  PutKeyCommand,
} from "@aws-sdk/client-cloudfront-keyvaluestore";
import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";

interface CustomResourceEvent {
  RequestType: "Create" | "Update" | "Delete";
  ResourceProperties: {
    SecretArn: string;
    KvsArn: string;
    KeyName: string;
  };
  PhysicalResourceId?: string;
}

const kvs = new CloudFrontKeyValueStoreClient({});
const sm = new SecretsManagerClient({});

export async function handler(event: CustomResourceEvent) {
  const physicalId =
    event.PhysicalResourceId ??
    `${event.ResourceProperties.KvsArn}:${event.ResourceProperties.KeyName}`;

  if (event.RequestType === "Delete") {
    return { PhysicalResourceId: physicalId };
  }

  const { SecretArn, KvsArn, KeyName } = event.ResourceProperties;

  const secret = await sm.send(new GetSecretValueCommand({ SecretId: SecretArn }));
  const value = secret.SecretString;
  if (!value) {
    throw new Error(`Secret ${SecretArn} has no SecretString`);
  }

  const desc = await kvs.send(new DescribeKeyValueStoreCommand({ KvsARN: KvsArn }));
  if (!desc.ETag) {
    throw new Error(`DescribeKeyValueStore returned no ETag for ${KvsArn}`);
  }

  await kvs.send(
    new PutKeyCommand({
      KvsARN: KvsArn,
      Key: KeyName,
      Value: value,
      IfMatch: desc.ETag,
    })
  );

  return {
    PhysicalResourceId: physicalId,
    Data: { KeyName, KvsArn },
  };
}
