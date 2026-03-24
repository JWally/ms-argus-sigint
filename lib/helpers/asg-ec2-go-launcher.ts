import * as cdk from "aws-cdk-lib";
import * as asg from "aws-cdk-lib/aws-autoscaling";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as ecr from "aws-cdk-lib/aws-ecr";
import * as iam from "aws-cdk-lib/aws-iam";
import * as route53 from "aws-cdk-lib/aws-route53";
import * as s3 from "aws-cdk-lib/aws-s3";
import { Construct, IDependable } from "constructs";

import { SecurityGroups, SecurityGroupTemplate } from "../constructs/security-groups";
import { DockerServiceInit } from "./docker-service-init";

export interface ProbeServiceProps {
  /** VPC to deploy into */
  vpc: ec2.IVpc;
  /** Subdomain for this service (e.g., "tcp-probe") */
  subdomain: string;
  /** Route53 hosted zone */
  hostedZone: route53.IHostedZone;
  /** Shared S3 bucket for Let's Encrypt certificates */
  certBucket: s3.IBucket;
  /** ECR repository containing the service image */
  ecrRepository: ecr.IRepository;
  /** Image tag to deploy. Default: "latest" */
  imageTag?: string;
  /** Security group template */
  securityGroupTemplate: SecurityGroupTemplate;
  /** Resources that must exist before ASG (EventBridge rules) */
  dependsOn: IDependable[];
  /** Instance type. Default: t4g.small */
  instanceType?: ec2.InstanceType;
  /** Minimum instances. Default: 2 */
  minCapacity?: number;
  /** Maximum instances. Default: 10 */
  maxCapacity?: number;
  /** Additional environment variables for the service (static, baked into user data) */
  additionalEnv?: Record<string, string>;
  /**
   * Secrets to fetch from AWS Secrets Manager at instance boot time.
   * The EC2 role is automatically granted GetSecretValue on each ARN.
   * The secret value is fetched at boot and passed to the container.
   */
  runtimeSecrets?: { envVar: string; secretArn: string }[];
  /**
   * DynamoDB table ARNs to grant PutItem access on.
   * Used for probes that write fingerprint tokens directly to DynamoDB.
   */
  dynamoWriteTableArns?: string[];
}

/**
 * A probe service running on EC2 with auto-scaling and DNS registration.
 *
 * Creates:
 *   - Security Group
 *   - IAM Role with SSM + S3 + ECR access
 *   - Launch Template with user data (Docker-based)
 *   - Auto Scaling Group
 *   - Instance tags for DNS registration
 *
 * Instance tags (read by Lambda for DNS):
 *   - dns:subdomain
 *   - dns:fullDomain
 *   - dns:hostedZoneId
 */
export class ProbeService extends Construct {
  public readonly asg: asg.AutoScalingGroup;
  public readonly securityGroup: ec2.SecurityGroup;
  public readonly fullDomain: string;

  constructor(scope: Construct, id: string, props: ProbeServiceProps) {
    super(scope, id);

    const {
      vpc,
      subdomain,
      hostedZone,
      certBucket,
      ecrRepository,
      imageTag = "latest",
      securityGroupTemplate,
      dependsOn,
      instanceType = ec2.InstanceType.of(ec2.InstanceClass.T3, ec2.InstanceSize.SMALL),
      minCapacity = 2,
      maxCapacity = 10,
      additionalEnv = {},
      runtimeSecrets = [],
      dynamoWriteTableArns = [],
    } = props;

    this.fullDomain = `${subdomain}.${hostedZone.zoneName}`;
    const serviceName = subdomain.replace(/-/g, "");

    // Security Group
    this.securityGroup = SecurityGroups.create(this, "SG", {
      vpc,
      template: securityGroupTemplate,
    });

    // IAM Role
    const role = new iam.Role(this, "Role", {
      assumedBy: new iam.ServicePrincipal("ec2.amazonaws.com"),
      managedPolicies: [iam.ManagedPolicy.fromAwsManagedPolicyName("AmazonSSMManagedInstanceCore")],
    });

    // S3 access for certificate caching
    certBucket.grantReadWrite(role);

    // ECR pull access
    ecrRepository.grantPull(role);

    // Grant Secrets Manager access for runtime secrets
    if (runtimeSecrets.length > 0) {
      role.addToPolicy(
        new iam.PolicyStatement({
          actions: ["secretsmanager:GetSecretValue"],
          resources: runtimeSecrets.map(({ secretArn }) => secretArn),
        }),
      );
    }

    // Grant DynamoDB write access for probes that store tokens
    if (dynamoWriteTableArns.length > 0) {
      role.addToPolicy(
        new iam.PolicyStatement({
          actions: ["dynamodb:PutItem"],
          resources: dynamoWriteTableArns,
        }),
      );
    }

    // User Data - Docker-based
    const userDataScript = DockerServiceInit.generate({
      serviceName,
      ecrRepositoryUri: ecrRepository.repositoryUri,
      imageTag,
      awsRegion: cdk.Stack.of(this).region,
      environment: {
        DOMAIN: this.fullDomain,
        CERT_BUCKET: certBucket.bucketName,
        CERT_PREFIX: `${subdomain}/`,
        AWS_REGION: cdk.Stack.of(this).region,
        ...additionalEnv,
      },
      hostNetwork: true,
      capabilities: ["NET_BIND_SERVICE"],
      runtimeSecrets,
    });

    const userData = ec2.UserData.forLinux();
    userData.addCommands(userDataScript);

    // Launch Template
    const launchTemplate = new ec2.LaunchTemplate(this, "LaunchTemplate", {
      machineImage: ec2.MachineImage.latestAmazonLinux2023({
        cpuType: ec2.AmazonLinuxCpuType.X86_64,
      }),
      instanceType,
      role,
      securityGroup: this.securityGroup,
      userData,
      associatePublicIpAddress: true,
      requireImdsv2: true,
    });

    // DNS tags - read by Lambda to register this instance
    cdk.Tags.of(launchTemplate).add("dns:subdomain", subdomain);
    cdk.Tags.of(launchTemplate).add("dns:fullDomain", this.fullDomain);
    cdk.Tags.of(launchTemplate).add("dns:hostedZoneId", hostedZone.hostedZoneId);

    // Auto Scaling Group
    this.asg = new asg.AutoScalingGroup(this, "ASG", {
      vpc,
      vpcSubnets: { subnetType: ec2.SubnetType.PUBLIC },
      launchTemplate,
      minCapacity,
      maxCapacity,
      healthCheck: asg.HealthCheck.ec2({ grace: cdk.Duration.minutes(5) }),
      updatePolicy: asg.UpdatePolicy.rollingUpdate({
        minInstancesInService: 1,
        maxBatchSize: 1,
        pauseTime: cdk.Duration.minutes(5),
      }),
    });

    // ASG must wait for EventBridge rules to exist
    for (const dep of dependsOn) {
      this.asg.node.addDependency(dep);
    }

    // Outputs
    new cdk.CfnOutput(this, "Endpoint", {
      value: `https://${this.fullDomain}`,
      description: `${subdomain} service endpoint`,
    });

    cdk.Tags.of(this).add("Service", subdomain);
    cdk.Tags.of(this).add("Component", "ProbeService");
  }
}
