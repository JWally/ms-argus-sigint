// lib/stacks/app-stack.ts
import * as cdk from "aws-cdk-lib";
import * as route53 from "aws-cdk-lib/aws-route53";
import * as s3 from "aws-cdk-lib/aws-s3";
import { Construct } from "constructs";

import {
  Vpc,
  Tables,
  Lambdas,
  EventRules,
  DnsCleanup,
  ProbeService,
  SecurityGroupTemplate,
  TlsFingerprintEdge,
} from "../constructs";

export interface AppStackProps extends cdk.StackProps {
  stackName: string;
  stage: string;
  hostedZoneDomain: string;
  features?: {
    tcpProbe?: boolean;
    tlsProbe?: boolean;
    stun?: boolean;
    tlsFingerprint?: boolean;
  };
  vpc?: {
    maxAzs?: number;
    enableNat?: boolean;
  };
}

/**
 * Main application stack for probe services.
 */
export class AppStack extends cdk.Stack {
  public readonly tlsFingerprintEndpoint?: string;

  constructor(scope: Construct, id: string, props: AppStackProps) {
    super(scope, id, props);

    const { stackName, stage, hostedZoneDomain, features = {}, vpc: vpcConfig = {} } = props;

    const enabledFeatures = {
      tcpProbe: features.tcpProbe ?? true,
      tlsProbe: features.tlsProbe ?? false,
      stun: features.stun ?? false,
      tlsFingerprint: features.tlsFingerprint ?? false,
    };

    // =========================================================================
    // 1. VPC
    // =========================================================================
    const vpc = new Vpc(this, "Vpc", {
      maxAzs: vpcConfig.maxAzs ?? 2,
      enableNat: vpcConfig.enableNat ?? false,
    });

    // =========================================================================
    // 2. Shared Resources
    // =========================================================================
    const hostedZone = route53.HostedZone.fromLookup(this, "HostedZone", {
      domainName: hostedZoneDomain,
    });

    const certBucket = new s3.Bucket(this, "CertBucket", {
      bucketName: `${stackName}-certs-${this.account}`,
      removalPolicy: stage === "prod" ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: stage !== "prod",
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
      encryption: s3.BucketEncryption.S3_MANAGED,
      lifecycleRules: [
        { id: "cleanup-old-backups", prefix: "backup/", expiration: cdk.Duration.days(30) },
      ],
    });

    // =========================================================================
    // 3. Tables
    // =========================================================================
    const tables = new Tables(this, "Tables", { stackName, stage });

    // =========================================================================
    // 4. Lambdas
    // =========================================================================
    const lambdas = new Lambdas(this, "Lambdas", {
      stackName,
      stage,
      tables,
      hostedZoneId: hostedZone.hostedZoneId,
      hostedZoneArn: hostedZone.hostedZoneArn,
    });

    // =========================================================================
    // 5. EventBridge Rules
    // =========================================================================
    const eventRules = new EventRules(this, "EventRules", { stackName, lambdas });

    // =========================================================================
    // 6. DNS Cleanup (Custom Resource)
    // =========================================================================
    new DnsCleanup(this, "DnsCleanup", {
      cleanupFunction: lambdas.dnsCleanup,
      identifier: hostedZoneDomain,
    });

    // =========================================================================
    // 7. Probe Services
    // =========================================================================
    const serviceDependencies = [eventRules.instanceLaunch, eventRules.instanceTerminate];

    if (enabledFeatures.tcpProbe) {
      new ProbeService(this, "TcpProbe", {
        vpc: vpc.vpc,
        subdomain: "tcp-probe",
        hostedZone,
        certBucket,
        goSourcePath: "src-go/tcp-probe/main.go",
        securityGroupTemplate: SecurityGroupTemplate.TCP_PROBE,
        dependsOn: serviceDependencies,
        minCapacity: 2,
        maxCapacity: 5,
      });
    }

    if (enabledFeatures.tlsProbe) {
      new ProbeService(this, "TlsProbe", {
        vpc: vpc.vpc,
        subdomain: "tls-probe",
        hostedZone,
        certBucket,
        goSourcePath: "src-go/tls-probe/main.go",
        securityGroupTemplate: SecurityGroupTemplate.TLS_PROBE,
        dependsOn: serviceDependencies,
        minCapacity: 2,
        maxCapacity: 5,
      });
    }

    if (enabledFeatures.stun) {
      new ProbeService(this, "Stun", {
        vpc: vpc.vpc,
        subdomain: "stun",
        hostedZone,
        certBucket,
        goSourcePath: "src-go/stun/main.go",
        securityGroupTemplate: SecurityGroupTemplate.STUN,
        dependsOn: serviceDependencies,
        minCapacity: 2,
        maxCapacity: 4,
      });
    }

    // =========================================================================
    // 8. Edge Services (CloudFront-based, no VPC needed)
    // =========================================================================
    if (enabledFeatures.tlsFingerprint) {
      const tlsFp = new TlsFingerprintEdge(this, "TlsFingerprint", {
        hostedZone,
      });
      this.tlsFingerprintEndpoint = tlsFp.endpoint;
    }

    // =========================================================================
    // Stack Outputs
    // =========================================================================
    new cdk.CfnOutput(this, "VpcId", { value: vpc.vpc.vpcId });
    new cdk.CfnOutput(this, "CertBucketName", { value: certBucket.bucketName });

    cdk.Tags.of(this).add("Application", stackName);
    cdk.Tags.of(this).add("Stage", stage);
    cdk.Tags.of(this).add("ManagedBy", "CDK");
  }
}
