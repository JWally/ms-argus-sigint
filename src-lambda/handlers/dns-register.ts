import { Logger } from "@aws-lambda-powertools/logger";
import { Metrics, MetricUnit } from "@aws-lambda-powertools/metrics";
import { EventBridgeEvent } from "aws-lambda";
import {
  Route53Client,
  ChangeResourceRecordSetsCommand,
  CreateHealthCheckCommand,
  GetHealthCheckCommand,
  GetChangeCommand,
  ListResourceRecordSetsCommand,
  RRType,
  ChangeStatus,
} from "@aws-sdk/client-route-53";
import { DynamoDBClient, PutItemCommand, GetItemCommand } from "@aws-sdk/client-dynamodb";
import { EC2Client, DescribeInstancesCommand, DescribeTagsCommand } from "@aws-sdk/client-ec2";

const logger = new Logger({ serviceName: "dns-register" });
const metrics = new Metrics({ namespace: "ProbeServices", serviceName: "dns-register" });

const route53 = new Route53Client({});
const dynamodb = new DynamoDBClient({});
const ec2 = new EC2Client({});

const REGISTRY_TABLE = process.env.REGISTRY_TABLE!;
const DEFAULT_HOSTED_ZONE_ID = process.env.HOSTED_ZONE_ID!;

interface Ec2StateChangeDetail {
  "instance-id": string;
  state: string;
}

interface InstanceDnsConfig {
  subdomain: string;
  fullDomain: string;
  hostedZoneId: string;
}

export const handler = async (
  event: EventBridgeEvent<"EC2 Instance State-change Notification", Ec2StateChangeDetail>
): Promise<void> => {
  const instanceId = event.detail["instance-id"];

  logger.info("Processing instance launch", { instanceId });

  // Idempotency check
  const existingItem = await dynamodb.send(
    new GetItemCommand({
      TableName: REGISTRY_TABLE,
      Key: { instanceId: { S: instanceId } },
    })
  );

  if (existingItem.Item) {
    logger.info("Instance already registered, skipping", { instanceId });
    return;
  }

  // Wait for public IP and tags
  await sleep(3000);

  const instanceInfo = await describeInstance(instanceId);
  if (!instanceInfo?.publicIp) {
    logger.warn("No public IP found, skipping", { instanceId });
    metrics.addMetric("RegistrationSkipped", MetricUnit.Count, 1);
    return;
  }

  const dnsConfig = await getDnsConfigFromTags(instanceId);
  if (!dnsConfig) {
    logger.info("No DNS tags found, instance not managed by this system", { instanceId });
    return;
  }

  logger.info("Registering instance", {
    instanceId,
    publicIp: instanceInfo.publicIp,
    fullDomain: dnsConfig.fullDomain,
  });

  try {
    const healthCheckId = await createHealthCheck(
      instanceId,
      instanceInfo.publicIp,
      dnsConfig.fullDomain
    );
    logger.info("Created health check", { instanceId, healthCheckId });

    await createDnsRecord(instanceId, instanceInfo.publicIp, healthCheckId, dnsConfig);
    logger.info("Created DNS record", { instanceId, fullDomain: dnsConfig.fullDomain });

    await dynamodb.send(
      new PutItemCommand({
        TableName: REGISTRY_TABLE,
        Item: {
          instanceId: { S: instanceId },
          subdomain: { S: dnsConfig.fullDomain },
          hostedZoneId: { S: dnsConfig.hostedZoneId },
          publicIp: { S: instanceInfo.publicIp },
          healthCheckId: { S: healthCheckId },
          createdAt: { S: new Date().toISOString() },
        },
      })
    );

    logger.info("Registration complete", { instanceId });
    metrics.addMetric("RegistrationSuccess", MetricUnit.Count, 1);
  } catch (error) {
    logger.error("Registration failed", { instanceId, error });
    metrics.addMetric("RegistrationFailed", MetricUnit.Count, 1);
    throw error;
  }
};

async function describeInstance(instanceId: string): Promise<{ publicIp?: string } | null> {
  try {
    const response = await ec2.send(new DescribeInstancesCommand({ InstanceIds: [instanceId] }));
    const instance = response.Reservations?.[0]?.Instances?.[0];
    return instance ? { publicIp: instance.PublicIpAddress } : null;
  } catch (error) {
    logger.error("Failed to describe instance", { instanceId, error });
    return null;
  }
}

async function getDnsConfigFromTags(instanceId: string): Promise<InstanceDnsConfig | null> {
  try {
    const response = await ec2.send(
      new DescribeTagsCommand({
        Filters: [
          { Name: "resource-id", Values: [instanceId] },
          { Name: "key", Values: ["dns:subdomain", "dns:fullDomain", "dns:hostedZoneId"] },
        ],
      })
    );

    const tags: Record<string, string> = {};
    for (const tag of response.Tags ?? []) {
      if (tag.Key && tag.Value) {
        tags[tag.Key] = tag.Value;
      }
    }

    const subdomain = tags["dns:subdomain"];
    const fullDomain = tags["dns:fullDomain"];
    const hostedZoneId = tags["dns:hostedZoneId"] ?? DEFAULT_HOSTED_ZONE_ID;

    if (!subdomain || !fullDomain) {
      return null;
    }

    return { subdomain, fullDomain, hostedZoneId };
  } catch (error) {
    logger.error("Failed to get instance tags", { instanceId, error });
    return null;
  }
}

async function createHealthCheck(
  instanceId: string,
  publicIp: string,
  _fullDomain: string
): Promise<string> {
  const callerRef = `${instanceId}-${Date.now()}`;

  logger.debug("Creating health check", { instanceId, publicIp, callerRef });

  const response = await route53.send(
    new CreateHealthCheckCommand({
      CallerReference: callerRef,
      HealthCheckConfig: {
        IPAddress: publicIp,
        Port: 8080,
        Type: "HTTP",
        ResourcePath: "/health",
        RequestInterval: 10,
        FailureThreshold: 2,
        EnableSNI: false,
      },
    })
  );

  if (!response.HealthCheck?.Id) {
    logger.error("CreateHealthCheck returned no ID", { response });
    throw new Error("Failed to create health check - no ID returned");
  }

  const healthCheckId = response.HealthCheck.Id;

  // Verify the health check actually exists
  logger.debug("Verifying health check exists", { healthCheckId });
  const verifyResponse = await route53.send(
    new GetHealthCheckCommand({ HealthCheckId: healthCheckId })
  );

  if (!verifyResponse.HealthCheck) {
    logger.error("Health check verification failed - not found after creation", {
      healthCheckId,
      verifyResponse,
    });
    throw new Error(`Health check ${healthCheckId} not found after creation`);
  }

  logger.debug("Health check verified", {
    healthCheckId,
    ipAddress: verifyResponse.HealthCheck.HealthCheckConfig?.IPAddress,
  });

  return healthCheckId;
}

async function createDnsRecord(
  instanceId: string,
  publicIp: string,
  healthCheckId: string,
  config: InstanceDnsConfig
): Promise<void> {
  logger.debug("Creating DNS record", {
    instanceId,
    publicIp,
    healthCheckId,
    fullDomain: config.fullDomain,
    hostedZoneId: config.hostedZoneId,
  });

  const changeResponse = await route53.send(
    new ChangeResourceRecordSetsCommand({
      HostedZoneId: config.hostedZoneId,
      ChangeBatch: {
        Comment: `Register ${instanceId} for ${config.fullDomain}`,
        Changes: [
          {
            Action: "UPSERT",
            ResourceRecordSet: {
              Name: config.fullDomain,
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

  const changeId = changeResponse.ChangeInfo?.Id;
  if (!changeId) {
    logger.error("ChangeResourceRecordSets returned no change ID", { changeResponse });
    throw new Error("Failed to create DNS record - no change ID returned");
  }

  logger.debug("DNS change submitted", {
    changeId,
    status: changeResponse.ChangeInfo?.Status,
  });

  // Wait for the change to be INSYNC (with timeout)
  await waitForChange(changeId);

  // Verify the record exists
  await verifyDnsRecord(config.hostedZoneId, config.fullDomain, instanceId, publicIp);
}

async function waitForChange(changeId: string, maxAttempts = 10): Promise<void> {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const response = await route53.send(new GetChangeCommand({ Id: changeId }));

    const status = response.ChangeInfo?.Status;
    logger.debug("Change status", { changeId, status, attempt });

    if (status === ChangeStatus.INSYNC) {
      return;
    }

    if (attempt < maxAttempts) {
      await sleep(1000);
    }
  }

  logger.warn("Change did not reach INSYNC within timeout", { changeId, maxAttempts });
  // Don't throw - the change may still propagate
}

async function verifyDnsRecord(
  hostedZoneId: string,
  fullDomain: string,
  instanceId: string,
  expectedIp: string
): Promise<void> {
  logger.debug("Verifying DNS record", { hostedZoneId, fullDomain, instanceId });

  const response = await route53.send(
    new ListResourceRecordSetsCommand({
      HostedZoneId: hostedZoneId,
      StartRecordName: fullDomain,
      StartRecordType: RRType.A,
      MaxItems: 10,
    })
  );

  // Look for our specific record (with SetIdentifier matching instanceId)
  const ourRecord = response.ResourceRecordSets?.find(
    (r) => r.Name === `${fullDomain}.` && r.Type === RRType.A && r.SetIdentifier === instanceId
  );

  if (!ourRecord) {
    logger.error("DNS record verification failed - record not found", {
      fullDomain,
      instanceId,
      foundRecords: response.ResourceRecordSets?.map((r) => ({
        name: r.Name,
        type: r.Type,
        setId: r.SetIdentifier,
      })),
    });
    throw new Error(`DNS record for ${fullDomain} (${instanceId}) not found after creation`);
  }

  const recordIp = ourRecord.ResourceRecords?.[0]?.Value;
  if (recordIp !== expectedIp) {
    logger.error("DNS record verification failed - IP mismatch", {
      fullDomain,
      instanceId,
      expectedIp,
      actualIp: recordIp,
    });
    throw new Error(`DNS record IP mismatch: expected ${expectedIp}, got ${recordIp}`);
  }

  logger.debug("DNS record verified", { fullDomain, instanceId, ip: recordIp });
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
