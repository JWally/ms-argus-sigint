// lib/stacks/app-stack.ts
import * as cdk from "aws-cdk-lib";
import * as ecr from "aws-cdk-lib/aws-ecr";
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
  EcrRepositories,
} from "../constructs";

export interface AppStackProps extends cdk.StackProps {
  stackName: string;
  stage: string;
  hostedZoneDomain: string;
  /**
   * Subdomain prefix for stage-specific DNS.
   * e.g., "qa-" results in "qa-tcp-probe.domain.com"
   * Empty string (prod) results in "tcp-probe.domain.com"
   */
  subdomainPrefix?: string;
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
  /** Stage-specific scaling configuration */
  scaling?: {
    minCapacity?: number;
    maxCapacity?: number;
  };
  /**
   * Optional: Import shared ECR repos instead of creating new ones.
   * Used by pipeline stages to share images built once.
   */
  sharedEcr?: {
    tcpProbeRepoName?: string;
    stunRepoName?: string;
  };
}

/**
 * Main application stack for probe services.
 */
export class AppStack extends cdk.Stack {
  public readonly tlsFingerprintEndpoint?: string;
  public readonly ecrRepositories?: EcrRepositories;

  constructor(scope: Construct, id: string, props: AppStackProps) {
    super(scope, id, props);

    const {
      stackName,
      stage,
      hostedZoneDomain,
      subdomainPrefix = "",
      features = {},
      vpc: vpcConfig = {},
      scaling = {},
      sharedEcr = {},
    } = props;

    // Helper to get stage-prefixed subdomain
    const getSubdomain = (base: string) => `${subdomainPrefix}${base}`;

    // Default scaling values
    const defaultMinCapacity = scaling.minCapacity ?? 2;
    const defaultMaxCapacity = scaling.maxCapacity ?? 5;

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
    // 3. ECR Repositories (import shared or create new)
    // =========================================================================
    const needsEcr = enabledFeatures.tcpProbe || enabledFeatures.tlsProbe || enabledFeatures.stun;

    // ECR repos - either imported (shared from pipeline) or created (standalone dev)
    let tcpProbeRepo: ecr.IRepository | undefined;
    let stunRepo: ecr.IRepository | undefined;

    if (needsEcr) {
      if (sharedEcr.tcpProbeRepoName && sharedEcr.stunRepoName) {
        // Import shared repos from pipeline by name
        tcpProbeRepo = ecr.Repository.fromRepositoryName(this, "TcpProbeRepo", sharedEcr.tcpProbeRepoName);
        stunRepo = ecr.Repository.fromRepositoryName(this, "StunRepo", sharedEcr.stunRepoName);
      } else {
        // Create new repos (standalone dev stack)
        const ecrRepos = new EcrRepositories(this, "EcrRepos", {
          stackName,
          stage,
        });
        this.ecrRepositories = ecrRepos;
        tcpProbeRepo = ecrRepos.tcpProbe;
        stunRepo = ecrRepos.stun;

        // Output ECR URIs for build script (only when creating)
        new cdk.CfnOutput(this, "TcpProbeEcrUri", {
          value: ecrRepos.tcpProbe.repositoryUri,
          description: "TCP Probe ECR repository URI",
        });
        new cdk.CfnOutput(this, "StunEcrUri", {
          value: ecrRepos.stun.repositoryUri,
          description: "STUN ECR repository URI",
        });
      }
    }

    // =========================================================================
    // 4. Tables
    // =========================================================================
    const tables = new Tables(this, "Tables", { stackName, stage });

    // =========================================================================
    // 5. Lambdas
    // =========================================================================
    const lambdas = new Lambdas(this, "Lambdas", {
      stackName,
      stage,
      tables,
      hostedZoneId: hostedZone.hostedZoneId,
      hostedZoneArn: hostedZone.hostedZoneArn,
    });

    // =========================================================================
    // 6. EventBridge Rules
    // =========================================================================
    const eventRules = new EventRules(this, "EventRules", { stackName, lambdas });

    // =========================================================================
    // 7. DNS Cleanup (Custom Resource)
    // =========================================================================
    new DnsCleanup(this, "DnsCleanup", {
      cleanupFunction: lambdas.dnsCleanup,
      identifier: hostedZoneDomain,
    });

    // =========================================================================
    // 8. Probe Services
    // =========================================================================
    const serviceDependencies = [eventRules.instanceLaunch, eventRules.instanceTerminate];

    if (enabledFeatures.tcpProbe && tcpProbeRepo) {
      new ProbeService(this, "TcpProbe", {
        vpc: vpc.vpc,
        subdomain: getSubdomain("tcp-probe"),
        hostedZone,
        certBucket,
        ecrRepository: tcpProbeRepo,
        imageTag: "latest",
        securityGroupTemplate: SecurityGroupTemplate.TCP_PROBE,
        dependsOn: serviceDependencies,
        minCapacity: defaultMinCapacity,
        maxCapacity: defaultMaxCapacity,
      });
    }

    if (enabledFeatures.tlsProbe && tcpProbeRepo) {
      new ProbeService(this, "TlsProbe", {
        vpc: vpc.vpc,
        subdomain: getSubdomain("tls-probe"),
        hostedZone,
        certBucket,
        ecrRepository: tcpProbeRepo, // Shares tcp-probe image for now
        imageTag: "latest",
        securityGroupTemplate: SecurityGroupTemplate.TLS_PROBE,
        dependsOn: serviceDependencies,
        minCapacity: defaultMinCapacity,
        maxCapacity: defaultMaxCapacity,
      });
    }

    if (enabledFeatures.stun && stunRepo) {
      new ProbeService(this, "Stun", {
        vpc: vpc.vpc,
        subdomain: getSubdomain("stun"),
        hostedZone,
        certBucket,
        ecrRepository: stunRepo,
        imageTag: "latest",
        securityGroupTemplate: SecurityGroupTemplate.STUN,
        dependsOn: serviceDependencies,
        minCapacity: defaultMinCapacity,
        maxCapacity: Math.max(defaultMaxCapacity - 1, defaultMinCapacity), // STUN needs slightly fewer
      });
    }

    // =========================================================================
    // 9. Edge Services (CloudFront-based, no VPC needed)
    // =========================================================================
    if (enabledFeatures.tlsFingerprint) {
      const tlsFp = new TlsFingerprintEdge(this, "TlsFingerprint", {
        hostedZone,
        subdomain: getSubdomain("id"),
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
