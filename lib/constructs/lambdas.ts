import * as path from "path";
import * as cdk from "aws-cdk-lib";
import * as iam from "aws-cdk-lib/aws-iam";
import * as lambda from "aws-cdk-lib/aws-lambda-nodejs";
import { Runtime, Tracing, Architecture } from "aws-cdk-lib/aws-lambda";
import { OutputFormat } from "aws-cdk-lib/aws-lambda-nodejs";
import { Construct } from "constructs";

import { Tables } from "./tables";

export interface LambdasProps {
  stackName: string;
  stage: string;
  tables: Tables;
  hostedZoneId: string;
  hostedZoneArn: string;
}

/**
 * Lambda functions for DNS registration lifecycle.
 *
 * Functions:
 *   - dnsRegister: Registers instance in Route53 with health check
 *   - dnsDeregister: Removes instance from Route53, deletes health check
 *   - dnsCleanup: Cleans up all records on stack destroy
 */
export class Lambdas extends Construct {
  public readonly dnsRegister: lambda.NodejsFunction;
  public readonly dnsDeregister: lambda.NodejsFunction;
  public readonly dnsCleanup: lambda.NodejsFunction;

  constructor(scope: Construct, id: string, props: LambdasProps) {
    super(scope, id);

    const { stackName, stage, tables, hostedZoneId, hostedZoneArn } = props;

    const commonEnv = {
      NODE_OPTIONS: "--enable-source-maps",
      POWERTOOLS_SERVICE_NAME: stackName,
      POWERTOOLS_METRICS_NAMESPACE: stackName,
      LOG_LEVEL: stage === "prod" ? "INFO" : "DEBUG",
      REGISTRY_TABLE: tables.dnsRegistry.tableName,
      HOSTED_ZONE_ID: hostedZoneId,
    };

    // --- DNS Register ---
    this.dnsRegister = this.createFunction("dns-register", {
      stackName,
      entry: "src-lambda/handlers/dns-register.ts",
      timeout: cdk.Duration.seconds(30),
      description: "Registers EC2 instance in Route53 with health check",
      environment: commonEnv,
    });

    tables.dnsRegistry.grantReadWriteData(this.dnsRegister);
    this.grantEc2Describe(this.dnsRegister);
    this.grantRoute53Register(this.dnsRegister, hostedZoneArn);

    // --- DNS Deregister ---
    this.dnsDeregister = this.createFunction("dns-deregister", {
      stackName,
      entry: "src-lambda/handlers/dns-deregister.ts",
      timeout: cdk.Duration.seconds(30),
      description: "Deregisters EC2 instance from Route53",
      environment: commonEnv,
    });

    tables.dnsRegistry.grantReadWriteData(this.dnsDeregister);
    this.grantEc2Describe(this.dnsDeregister);
    this.grantRoute53Deregister(this.dnsDeregister, hostedZoneArn);

    // --- DNS Cleanup ---
    this.dnsCleanup = this.createFunction("dns-cleanup", {
      stackName,
      entry: "src-lambda/handlers/dns-cleanup.ts",
      timeout: cdk.Duration.minutes(5),
      memorySize: 512,
      description: "Cleans up all DNS records on stack destroy",
      environment: commonEnv,
    });

    tables.dnsRegistry.grantReadWriteData(this.dnsCleanup);
    this.grantRoute53Cleanup(this.dnsCleanup, hostedZoneArn);

    cdk.Tags.of(this).add("Component", "Lambdas");
  }

  private createFunction(
    name: string,
    config: {
      stackName: string;
      entry: string;
      timeout: cdk.Duration;
      description: string;
      environment: Record<string, string>;
      memorySize?: number;
    }
  ): lambda.NodejsFunction {
    return new lambda.NodejsFunction(this, name, {
      functionName: `${config.stackName}-${name}`,
      entry: path.join(process.cwd(), config.entry),
      handler: "handler",
      runtime: Runtime.NODEJS_20_X,
      architecture: Architecture.ARM_64,
      memorySize: config.memorySize ?? 256,
      timeout: config.timeout,
      tracing: Tracing.ACTIVE,
      description: config.description,
      bundling: {
        minify: true,
        sourceMap: true,
        target: "node20",
        format: OutputFormat.CJS,
        externalModules: ["@aws-sdk/*"],
      },
      environment: config.environment,
    });
  }

  private grantEc2Describe(fn: lambda.NodejsFunction): void {
    fn.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ["ec2:DescribeInstances", "ec2:DescribeTags"],
        resources: ["*"],
      })
    );
  }

  private grantRoute53Register(fn: lambda.NodejsFunction, hostedZoneArn: string): void {
    fn.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ["route53:ChangeResourceRecordSets"],
        resources: [hostedZoneArn],
      })
    );
    fn.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ["route53:CreateHealthCheck", "route53:GetHealthCheck"],
        resources: ["*"],
      })
    );
  }

  private grantRoute53Deregister(fn: lambda.NodejsFunction, hostedZoneArn: string): void {
    fn.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ["route53:ChangeResourceRecordSets"],
        resources: [hostedZoneArn],
      })
    );
    fn.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ["route53:DeleteHealthCheck", "route53:GetHealthCheck"],
        resources: ["*"],
      })
    );
  }

  private grantRoute53Cleanup(fn: lambda.NodejsFunction, hostedZoneArn: string): void {
    fn.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: ["route53:ChangeResourceRecordSets", "route53:ListResourceRecordSets"],
        resources: [hostedZoneArn],
      })
    );
    fn.addToRolePolicy(
      new iam.PolicyStatement({
        effect: iam.Effect.ALLOW,
        actions: [
          "route53:DeleteHealthCheck",
          "route53:GetHealthCheck",
          "route53:ListHealthChecks",
        ],
        resources: ["*"],
      })
    );
  }
}
