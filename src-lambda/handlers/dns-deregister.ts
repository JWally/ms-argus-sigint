import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { EventBridgeEvent } from "aws-lambda";
import {
  Route53Client,
  ChangeResourceRecordSetsCommand,
  DeleteHealthCheckCommand,
  RRType,
} from "@aws-sdk/client-route-53";
import { DynamoDBClient, GetItemCommand, DeleteItemCommand } from "@aws-sdk/client-dynamodb";

const logger = new Logger({ serviceName: "dns-deregister" });
const metrics = new Metrics({ namespace: "ProbeServices", serviceName: "dns-deregister" });

const route53 = new Route53Client({});
const dynamodb = new DynamoDBClient({});

const REGISTRY_TABLE = process.env.REGISTRY_TABLE!;

interface Ec2StateChangeDetail {
  "instance-id": string;
  state: string;
}

export const handler = async (
  event: EventBridgeEvent<"EC2 Instance State-change Notification", Ec2StateChangeDetail>
): Promise<void> => {
  const instanceId = event.detail["instance-id"];
  const state = event.detail.state;

  logger.info("Processing instance termination", { instanceId, state });

  const item = await dynamodb.send(
    new GetItemCommand({
      TableName: REGISTRY_TABLE,
      Key: { instanceId: { S: instanceId } },
    })
  );

  if (!item.Item) {
    logger.info("Instance not found in registry, skipping", { instanceId });
    metrics.addMetric("DeregistrationSkipped", MetricUnit.Count, 1);
    return;
  }

  const subdomain = item.Item.subdomain?.S;
  const hostedZoneId = item.Item.hostedZoneId?.S;
  const publicIp = item.Item.publicIp?.S;
  const healthCheckId = item.Item.healthCheckId?.S;

  if (!subdomain || !hostedZoneId || !publicIp || !healthCheckId) {
    logger.warn("Incomplete registry entry", { instanceId });
  }

  logger.info("Deregistering instance", { instanceId, subdomain, publicIp, healthCheckId });

  try {
    if (subdomain && hostedZoneId && publicIp && healthCheckId) {
      await deleteDnsRecord(instanceId, subdomain, hostedZoneId, publicIp, healthCheckId);
      logger.info("Deleted DNS record", { instanceId });
    }

    if (healthCheckId) {
      await deleteHealthCheck(healthCheckId);
      logger.info("Deleted health check", { instanceId, healthCheckId });
    }

    await dynamodb.send(
      new DeleteItemCommand({
        TableName: REGISTRY_TABLE,
        Key: { instanceId: { S: instanceId } },
      })
    );

    logger.info("Deregistration complete", { instanceId });
    metrics.addMetric("DeregistrationSuccess", MetricUnit.Count, 1);
  } catch (error) {
    logger.error("Deregistration failed", { instanceId, error });
    metrics.addMetric("DeregistrationFailed", MetricUnit.Count, 1);
    throw error;
  }
};

async function deleteDnsRecord(
  instanceId: string,
  fullDomain: string,
  hostedZoneId: string,
  publicIp: string,
  healthCheckId: string
): Promise<void> {
  try {
    await route53.send(
      new ChangeResourceRecordSetsCommand({
        HostedZoneId: hostedZoneId,
        ChangeBatch: {
          Comment: `Deregister ${instanceId}`,
          Changes: [
            {
              Action: "DELETE",
              ResourceRecordSet: {
                Name: fullDomain,
                Type: RRType.A,
                TTL: 60,
                SetIdentifier: instanceId,
                MultiValueAnswer: true,
                HealthCheckId: healthCheckId,
                ResourceRecords: [{ Value: publicIp }],
              },
            },
          ],
        },
      })
    );
  } catch (error: unknown) {
    const err = error as { name?: string };
    if (err.name === "InvalidChangeBatch") {
      logger.info("DNS record already deleted or mismatched", { instanceId });
      return;
    }
    throw error;
  }
}

async function deleteHealthCheck(healthCheckId: string): Promise<void> {
  try {
    await route53.send(new DeleteHealthCheckCommand({ HealthCheckId: healthCheckId }));
  } catch (error: unknown) {
    const err = error as { name?: string };
    if (err.name === "NoSuchHealthCheck") {
      logger.info("Health check already deleted", { healthCheckId });
      return;
    }
    throw error;
  }
}
