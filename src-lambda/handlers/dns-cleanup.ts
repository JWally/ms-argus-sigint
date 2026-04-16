import { Logger } from "@aws-lambda-powertools/logger";
import {
  CloudFormationCustomResourceEvent,
  CloudFormationCustomResourceResponse,
} from "aws-lambda";
import {
  Route53Client,
  ChangeResourceRecordSetsCommand,
  DeleteHealthCheckCommand,
  ListResourceRecordSetsCommand,
  RRType,
  type ResourceRecordSet,
} from "@aws-sdk/client-route-53";
import {
  DynamoDBClient,
  ScanCommand,
  DeleteItemCommand,
  AttributeValue,
} from "@aws-sdk/client-dynamodb";

const logger = new Logger({ serviceName: "dns-cleanup" });

const route53 = new Route53Client({});
const dynamodb = new DynamoDBClient({});

const REGISTRY_TABLE = process.env.REGISTRY_TABLE!;
const HOSTED_ZONE_ID = process.env.HOSTED_ZONE_ID!;

interface RegistryItem {
  instanceId: string;
  subdomain: string;
  hostedZoneId: string;
  publicIp: string;
  healthCheckId: string;
}

export const handler = async (
  event: CloudFormationCustomResourceEvent
): Promise<CloudFormationCustomResourceResponse> => {
  const physicalResourceId = `dns-cleanup-${HOSTED_ZONE_ID}`;

  logger.info("Cleanup handler invoked", { requestType: event.RequestType, physicalResourceId });

  try {
    switch (event.RequestType) {
      case "Create":
      case "Update":
        logger.info("Create/Update - no cleanup needed");
        return buildResponse(event, physicalResourceId, "SUCCESS");

      case "Delete":
        logger.info("Delete - cleaning up all DNS records and health checks");
        await performCleanup();
        return buildResponse(event, physicalResourceId, "SUCCESS");

      default:
        logger.warn("Unknown request type", {
          requestType: (event as { RequestType: string }).RequestType,
        });
        return buildResponse(event, physicalResourceId, "SUCCESS");
    }
  } catch (error) {
    logger.error("Cleanup failed", { error });
    // Return SUCCESS anyway to not block stack deletion
    return buildResponse(event, physicalResourceId, "SUCCESS", String(error));
  }
};

async function performCleanup(): Promise<void> {
  const registryItems = await getRegistryItems();
  logger.info(`Found ${registryItems.length} items in registry`);

  for (const item of registryItems) {
    await cleanupItem(item);
  }

  await cleanupOrphanedRecords();
}

async function getRegistryItems(): Promise<RegistryItem[]> {
  const items: RegistryItem[] = [];
  let lastEvaluatedKey: Record<string, AttributeValue> | undefined;

  do {
    const response = await dynamodb.send(
      new ScanCommand({
        TableName: REGISTRY_TABLE,
        ExclusiveStartKey: lastEvaluatedKey,
      })
    );

    for (const item of response.Items ?? []) {
      if (
        item.instanceId?.S &&
        item.subdomain?.S &&
        item.hostedZoneId?.S &&
        item.publicIp?.S &&
        item.healthCheckId?.S
      ) {
        items.push({
          instanceId: item.instanceId.S,
          subdomain: item.subdomain.S,
          hostedZoneId: item.hostedZoneId.S,
          publicIp: item.publicIp.S,
          healthCheckId: item.healthCheckId.S,
        });
      }
    }

    lastEvaluatedKey = response.LastEvaluatedKey;
  } while (lastEvaluatedKey);

  return items;
}

async function cleanupItem(item: RegistryItem): Promise<void> {
  try {
    await route53.send(
      new ChangeResourceRecordSetsCommand({
        HostedZoneId: item.hostedZoneId,
        ChangeBatch: {
          Comment: `Cleanup ${item.instanceId}`,
          Changes: [
            {
              Action: "DELETE",
              ResourceRecordSet: {
                Name: item.subdomain,
                Type: RRType.A,
                TTL: 60,
                SetIdentifier: item.instanceId,
                MultiValueAnswer: true,
                HealthCheckId: item.healthCheckId,
                ResourceRecords: [{ Value: item.publicIp }],
              },
            },
          ],
        },
      })
    );
  } catch (error: unknown) {
    const err = error as { name?: string };
    if (err.name !== "InvalidChangeBatch" && err.name !== "NoSuchHostedZone") {
      logger.warn("Failed to delete DNS record", { instanceId: item.instanceId, error });
    }
  }

  try {
    await route53.send(new DeleteHealthCheckCommand({ HealthCheckId: item.healthCheckId }));
  } catch (error: unknown) {
    const err = error as { name?: string };
    if (err.name !== "NoSuchHealthCheck") {
      logger.warn("Failed to delete health check", { healthCheckId: item.healthCheckId, error });
    }
  }

  try {
    await dynamodb.send(
      new DeleteItemCommand({
        TableName: REGISTRY_TABLE,
        Key: { instanceId: { S: item.instanceId } },
      })
    );
  } catch (error) {
    logger.warn("Failed to delete DynamoDB item", { instanceId: item.instanceId, error });
  }
}

async function cleanupOrphanedRecords(): Promise<void> {
  logger.info("Scanning Route53 for orphaned records");

  try {
    let isTruncated = true;
    let nextRecordName: string | undefined;
    let nextRecordType: RRType | undefined;

    while (isTruncated) {
      const response = await route53.send(
        new ListResourceRecordSetsCommand({
          HostedZoneId: HOSTED_ZONE_ID,
          MaxItems: 100,
          StartRecordName: nextRecordName,
          StartRecordType: nextRecordType,
        })
      );

      const orphanedRecords = (response.ResourceRecordSets ?? []).filter(
        (record) =>
          record.Type === RRType.A &&
          record.SetIdentifier?.startsWith("i-") &&
          record.MultiValueAnswer === true
      );

      logger.info(`Found ${orphanedRecords.length} orphaned records in this batch`);

      for (const record of orphanedRecords) {
        await cleanupSingleOrphan(record);
      }

      isTruncated = response.IsTruncated ?? false;
      nextRecordName = response.NextRecordName;
      nextRecordType = response.NextRecordType;
    }
  } catch (error) {
    logger.warn("Failed to scan for orphaned records", { error });
  }
}

interface OrphanRecord {
  Name?: string;
  Type?: string;
  SetIdentifier?: string;
  HealthCheckId?: string;
  TTL?: number;
  MultiValueAnswer?: boolean;
  ResourceRecords?: Array<{ Value?: string }>;
}

async function cleanupSingleOrphan(record: OrphanRecord): Promise<void> {
  try {
    if (record.HealthCheckId) {
      try {
        await route53.send(new DeleteHealthCheckCommand({ HealthCheckId: record.HealthCheckId }));
        logger.info("Deleted orphaned health check", { healthCheckId: record.HealthCheckId });
      } catch (error: unknown) {
        const err = error as { name?: string };
        if (err.name !== "NoSuchHealthCheck") {
          logger.warn("Failed to delete orphaned health check", { error });
        }
      }
    }

    await route53.send(
      new ChangeResourceRecordSetsCommand({
        HostedZoneId: HOSTED_ZONE_ID,
        ChangeBatch: {
          Comment: `Cleanup orphaned record ${record.SetIdentifier}`,
          Changes: [
            { Action: "DELETE", ResourceRecordSet: record as ResourceRecordSet },
          ],
        },
      })
    );
    logger.info("Deleted orphaned record", { setIdentifier: record.SetIdentifier });
  } catch (error: unknown) {
    const err = error as { name?: string };
    if (err.name !== "InvalidChangeBatch") {
      logger.warn("Failed to delete orphaned record", {
        setIdentifier: record.SetIdentifier,
        error,
      });
    }
  }
}

function buildResponse(
  event: CloudFormationCustomResourceEvent,
  physicalResourceId: string,
  status: "SUCCESS" | "FAILED",
  reason?: string
): CloudFormationCustomResourceResponse {
  return {
    Status: status,
    Reason: reason ?? status,
    PhysicalResourceId: physicalResourceId,
    StackId: event.StackId,
    RequestId: event.RequestId,
    LogicalResourceId: event.LogicalResourceId,
  };
}
