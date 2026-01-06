import * as cdk from "aws-cdk-lib";
import * as cr from "aws-cdk-lib/custom-resources";
import * as lambda from "aws-cdk-lib/aws-lambda";
import { Construct } from "constructs";

export interface DnsCleanupProps {
  /** The cleanup Lambda function */
  cleanupFunction: lambda.IFunction;
  /** Unique identifier for this cleanup (used as physical resource ID) */
  identifier: string;
}

/**
 * Custom Resource that triggers DNS cleanup on stack deletion.
 *
 * On Create/Update: No-op
 * On Delete: Invokes the cleanup Lambda to remove all DNS records and health checks
 */
export class DnsCleanup extends Construct {
  constructor(scope: Construct, id: string, props: DnsCleanupProps) {
    super(scope, id);

    const { cleanupFunction, identifier } = props;

    // Custom resource provider
    const provider = new cr.Provider(this, "Provider", {
      onEventHandler: cleanupFunction,
    });

    // Custom resource - triggers cleanup on delete
    new cdk.CustomResource(this, "Resource", {
      serviceToken: provider.serviceToken,
      properties: {
        // Force update on identifier change
        Identifier: identifier,
        // Timestamp to allow manual trigger if needed
        Timestamp: Date.now().toString(),
      },
    });

    cdk.Tags.of(this).add("Component", "DnsCleanup");
  }
}
