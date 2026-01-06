import * as cdk from "aws-cdk-lib";
import * as dynamodb from "aws-cdk-lib/aws-dynamodb";
import { Construct } from "constructs";

export interface TablesProps {
  /** Stack name for resource naming */
  stackName: string;
  /** Deployment stage (dev, staging, prod) */
  stage: string;
}

/**
 * DynamoDB tables for DNS registration tracking.
 *
 * Tables:
 *   - dnsRegistry: instanceId → healthCheckId, IP, subdomain
 */
export class Tables extends Construct {
  public readonly dnsRegistry: dynamodb.Table;

  constructor(scope: Construct, id: string, props: TablesProps) {
    super(scope, id);

    const { stackName, stage } = props;
    const isProd = stage === "prod";

    this.dnsRegistry = new dynamodb.Table(this, "DnsRegistry", {
      tableName: `${stackName}-dns-registry`,
      partitionKey: {
        name: "instanceId",
        type: dynamodb.AttributeType.STRING,
      },
      billingMode: dynamodb.BillingMode.PAY_PER_REQUEST,
      removalPolicy: isProd ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
      pointInTimeRecovery: isProd,
      timeToLiveAttribute: "ttl",
    });

    // GSI for querying by subdomain (debugging/monitoring)
    this.dnsRegistry.addGlobalSecondaryIndex({
      indexName: "by-subdomain",
      partitionKey: {
        name: "subdomain",
        type: dynamodb.AttributeType.STRING,
      },
      sortKey: {
        name: "createdAt",
        type: dynamodb.AttributeType.STRING,
      },
      projectionType: dynamodb.ProjectionType.ALL,
    });

    cdk.Tags.of(this).add("Component", "Tables");
  }
}
