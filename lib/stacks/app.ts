// lib/stacks/app-stack.ts
import * as path from "path";
import * as cdk from "aws-cdk-lib";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as ecr from "aws-cdk-lib/aws-ecr";
import * as ecrAssets from "aws-cdk-lib/aws-ecr-assets";
import * as route53 from "aws-cdk-lib/aws-route53";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as ssm from "aws-cdk-lib/aws-ssm";
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
    h2Probe?: boolean;
  };
  /**
   * VPC configuration. Only used if sharedVpcEnvironment is not set.
   */
  vpc?: {
    maxAzs?: number;
    enableNat?: boolean;
  };
  /**
   * Optional: Import shared VPC from ms-argus-infra instead of creating a new one.
   * The value is the environment name used in SSM parameter paths (e.g., "dev-jw", "qa", "prod").
   * When set, reads VPC ID from SSM parameter: /argus/{sharedVpcEnvironment}/vpc-id
   */
  sharedVpcEnvironment?: string;
  /** Stage-specific scaling configuration */
  scaling?: {
    minCapacity?: number;
    maxCapacity?: number;
    /** EC2 instance type string (e.g., "t3.micro"). Default: t3.small */
    instanceType?: string;
  };
  /**
   * Optional: Import shared ECR repos instead of creating new ones.
   * Used by pipeline stages to share images built once.
   */
  sharedEcr?: {
    tcpProbeRepoName?: string;
    stunRepoName?: string;
    h2ProbeRepoName?: string;
  };
  /**
   * If true, automatically build and push Docker images during CDK deploy.
   * Uses CDK Docker assets - no manual build step required.
   * Default: true for dev stacks, false when using sharedEcr.
   */
  autoBuildImages?: boolean;
  /**
   * Secrets Manager ARN for the AES-256 key used to encrypt probe responses.
   * When set, the EC2 instance role is granted GetSecretValue and the key is
   * fetched at boot time — never stored in the CloudFormation template.
   * Prefer sigintPlatformEnvironment for automatic SSM lookup.
   */
  sigintAesKeySecretArn?: string;
  /**
   * ms-argus-platform environment name (e.g. "dev-jw") to auto-lookup the
   * sigint AES key ARN from SSM at synth time (cached in cdk.context.json).
   * Takes precedence over sigintAesKeySecretArn.
   * SSM path: /argus-platform/{sigintPlatformEnvironment}/sigint-aes-key-arn
   */
  sigintPlatformEnvironment?: string;
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
      sharedVpcEnvironment,
      scaling = {},
      sharedEcr = {},
      autoBuildImages,
      sigintAesKeySecretArn,
      sigintPlatformEnvironment,
    } = props;

    const resolvedSecretArn =
      sigintPlatformEnvironment
        ? ssm.StringParameter.valueFromLookup(
            this,
            `/argus-platform/${sigintPlatformEnvironment}/sigint-aes-key-arn`,
          )
        : sigintAesKeySecretArn;

    const probeTokensTableName = sigintPlatformEnvironment
      ? ssm.StringParameter.valueFromLookup(
          this,
          `/argus-platform/${sigintPlatformEnvironment}/probe-tokens-table-name`,
        )
      : undefined;

    const probeTokensTableArn = sigintPlatformEnvironment
      ? ssm.StringParameter.valueFromLookup(
          this,
          `/argus-platform/${sigintPlatformEnvironment}/probe-tokens-table-arn`,
        )
      : undefined;

    // Raw ECDH public key published by ms-argus-api — not secret, just a P-256 public key.
    // Injected into h2-probe so it can embed it in responses, letting clients skip the handshake.
    const apiEcdhPubkey = sigintPlatformEnvironment
      ? ssm.StringParameter.valueFromLookup(
          this,
          `/argus-platform/${sigintPlatformEnvironment}/api-ecdh-pubkey`,
        )
      : undefined;

    // Auto-build images by default for dev stacks (when not using shared ECR)
    const shouldAutoBuild = autoBuildImages ?? (!sharedEcr.tcpProbeRepoName && !sharedEcr.stunRepoName);

    // Helper to get stage-prefixed subdomain
    const getSubdomain = (base: string) => `${subdomainPrefix}${base}`;

    // Default scaling values
    const defaultMinCapacity = scaling.minCapacity ?? 2;
    const defaultMaxCapacity = scaling.maxCapacity ?? 5;
    const defaultInstanceType = scaling.instanceType
      ? new ec2.InstanceType(scaling.instanceType)
      : undefined;

    const enabledFeatures = {
      tcpProbe: features.tcpProbe ?? true,
      tlsProbe: features.tlsProbe ?? false,
      stun: features.stun ?? false,
      tlsFingerprint: features.tlsFingerprint ?? false,
      h2Probe: features.h2Probe ?? false,
    };

    // =========================================================================
    // 1. VPC (import shared or create new)
    // =========================================================================
    let vpcInstance: ec2.IVpc;

    if (sharedVpcEnvironment) {
      // Import shared VPC from ms-argus-infra via SSM Parameter Store
      const ssmPrefix = `/argus/${sharedVpcEnvironment}`;
      const vpcId = ssm.StringParameter.valueFromLookup(this, `${ssmPrefix}/vpc-id`);
      vpcInstance = ec2.Vpc.fromLookup(this, "SharedVpc", { vpcId });
    } else {
      // Create a new VPC for this stack
      const vpc = new Vpc(this, "Vpc", {
        maxAzs: vpcConfig.maxAzs ?? 2,
        enableNat: vpcConfig.enableNat ?? false,
      });
      vpcInstance = vpc.vpc;
    }

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
    // 3. Docker Images (auto-build via CDK assets, or import shared ECR repos)
    // =========================================================================
    const needsImages = enabledFeatures.tcpProbe || enabledFeatures.tlsProbe || enabledFeatures.stun || enabledFeatures.h2Probe;

    // Image sources - either built automatically via CDK assets, or from shared repos
    let tcpProbeRepo: ecr.IRepository | undefined;
    let stunRepo: ecr.IRepository | undefined;
    let h2ProbeRepo: ecr.IRepository | undefined;
    let tcpProbeImageTag = "latest";
    let stunImageTag = "latest";
    let h2ProbeImageTag = "latest";

    if (needsImages) {
      if (sharedEcr.tcpProbeRepoName && sharedEcr.stunRepoName) {
        // Import shared repos from pipeline by name
        tcpProbeRepo = ecr.Repository.fromRepositoryName(this, "TcpProbeRepo", sharedEcr.tcpProbeRepoName);
        stunRepo = ecr.Repository.fromRepositoryName(this, "StunRepo", sharedEcr.stunRepoName);
        if (sharedEcr.h2ProbeRepoName) {
          h2ProbeRepo = ecr.Repository.fromRepositoryName(this, "H2ProbeRepo", sharedEcr.h2ProbeRepoName);
        }
      } else if (shouldAutoBuild) {
        // Auto-build images using CDK Docker assets (recommended for dev)
        // CDK will build and push images automatically during deploy
        const tcpProbeAsset = new ecrAssets.DockerImageAsset(this, "TcpProbeImage", {
          directory: path.join(__dirname, "../../src-go/tcp-probe"),
          platform: ecrAssets.Platform.LINUX_AMD64,
          assetName: "tcp-probe",
        });
        tcpProbeRepo = tcpProbeAsset.repository;
        tcpProbeImageTag = tcpProbeAsset.imageTag;

        const stunAsset = new ecrAssets.DockerImageAsset(this, "StunImage", {
          directory: path.join(__dirname, "../../src-go/stun"),
          platform: ecrAssets.Platform.LINUX_AMD64,
          assetName: "stun",
        });
        stunRepo = stunAsset.repository;
        stunImageTag = stunAsset.imageTag;

        const h2ProbeAsset = new ecrAssets.DockerImageAsset(this, "H2ProbeImage", {
          directory: path.join(__dirname, "../../src-go/h2-probe"),
          platform: ecrAssets.Platform.LINUX_AMD64,
          assetName: "h2-probe",
        });
        h2ProbeRepo = h2ProbeAsset.repository;
        h2ProbeImageTag = h2ProbeAsset.imageTag;

        // Output image URIs for reference
        new cdk.CfnOutput(this, "TcpProbeImageUri", {
          value: tcpProbeAsset.imageUri,
          description: "TCP Probe Docker image URI (auto-built)",
        });
        new cdk.CfnOutput(this, "StunImageUri", {
          value: stunAsset.imageUri,
          description: "STUN Docker image URI (auto-built)",
        });
        new cdk.CfnOutput(this, "H2ProbeImageUri", {
          value: h2ProbeAsset.imageUri,
          description: "H2 Probe Docker image URI (auto-built)",
        });
      } else {
        // Create ECR repos only (manual build required)
        const ecrRepos = new EcrRepositories(this, "EcrRepos", {
          stackName,
          stage,
        });
        this.ecrRepositories = ecrRepos;
        tcpProbeRepo = ecrRepos.tcpProbe;
        stunRepo = ecrRepos.stun;
        h2ProbeRepo = ecrRepos.h2Probe;

        // Output ECR URIs for manual build script
        new cdk.CfnOutput(this, "TcpProbeEcrUri", {
          value: ecrRepos.tcpProbe.repositoryUri,
          description: "TCP Probe ECR repository URI (manual build required)",
        });
        new cdk.CfnOutput(this, "StunEcrUri", {
          value: ecrRepos.stun.repositoryUri,
          description: "STUN ECR repository URI (manual build required)",
        });
        new cdk.CfnOutput(this, "H2ProbeEcrUri", {
          value: ecrRepos.h2Probe.repositoryUri,
          description: "H2 Probe ECR repository URI (manual build required)",
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
    const sigintRuntimeSecrets = resolvedSecretArn
      ? [{ envVar: "SIGINT_AES_KEY", secretArn: resolvedSecretArn }]
      : [];

    if (enabledFeatures.tcpProbe && tcpProbeRepo) {
      new ProbeService(this, "TcpProbe", {
        vpc: vpcInstance,
        subdomain: getSubdomain("tcp-probe"),
        hostedZone,
        certBucket,
        ecrRepository: tcpProbeRepo,
        imageTag: tcpProbeImageTag,
        securityGroupTemplate: SecurityGroupTemplate.TCP_PROBE,
        dependsOn: serviceDependencies,
        instanceType: defaultInstanceType,
        minCapacity: defaultMinCapacity,
        maxCapacity: defaultMaxCapacity,
        runtimeSecrets: sigintRuntimeSecrets,
        additionalEnv: probeTokensTableName ? { PROBE_TOKENS_TABLE: probeTokensTableName } : {},
        dynamoWriteTableArns: probeTokensTableArn ? [probeTokensTableArn] : [],
      });
    }

    if (enabledFeatures.tlsProbe && tcpProbeRepo) {
      new ProbeService(this, "TlsProbe", {
        vpc: vpcInstance,
        subdomain: getSubdomain("tls-probe"),
        hostedZone,
        certBucket,
        ecrRepository: tcpProbeRepo, // Shares tcp-probe image for now
        imageTag: tcpProbeImageTag,
        securityGroupTemplate: SecurityGroupTemplate.TLS_PROBE,
        dependsOn: serviceDependencies,
        instanceType: defaultInstanceType,
        minCapacity: defaultMinCapacity,
        maxCapacity: defaultMaxCapacity,
        runtimeSecrets: sigintRuntimeSecrets,
      });
    }

    if (enabledFeatures.stun && stunRepo) {
      new ProbeService(this, "Stun", {
        vpc: vpcInstance,
        subdomain: getSubdomain("stun"),
        hostedZone,
        certBucket,
        ecrRepository: stunRepo,
        imageTag: stunImageTag,
        securityGroupTemplate: SecurityGroupTemplate.STUN,
        dependsOn: serviceDependencies,
        instanceType: defaultInstanceType,
        minCapacity: defaultMinCapacity,
        maxCapacity: defaultMaxCapacity,
      });
    }

    if (enabledFeatures.h2Probe && h2ProbeRepo) {
      new ProbeService(this, "H2Probe", {
        vpc: vpcInstance,
        subdomain: getSubdomain("h2"),
        hostedZone,
        certBucket,
        ecrRepository: h2ProbeRepo,
        imageTag: h2ProbeImageTag,
        securityGroupTemplate: SecurityGroupTemplate.TCP_PROBE, // Same security group as tcp-probe (443, 80, 8080)
        dependsOn: serviceDependencies,
        instanceType: defaultInstanceType,
        minCapacity: defaultMinCapacity,
        maxCapacity: defaultMaxCapacity,
        runtimeSecrets: sigintRuntimeSecrets,
        additionalEnv: {
          ...(probeTokensTableName ? { PROBE_TOKENS_TABLE: probeTokensTableName } : {}),
          ...(apiEcdhPubkey ? { API_ECDH_RAW_PUBKEY: apiEcdhPubkey } : {}),
        },
        dynamoWriteTableArns: probeTokensTableArn ? [probeTokensTableArn] : [],
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
    new cdk.CfnOutput(this, "VpcId", { value: vpcInstance.vpcId });
    new cdk.CfnOutput(this, "CertBucketName", { value: certBucket.bucketName });

    cdk.Tags.of(this).add("Application", stackName);
    cdk.Tags.of(this).add("Stage", stage);
    cdk.Tags.of(this).add("ManagedBy", "CDK");
  }
}
