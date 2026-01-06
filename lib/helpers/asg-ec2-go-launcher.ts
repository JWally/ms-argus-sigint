import * as cdk from "aws-cdk-lib";
import * as asg from "aws-cdk-lib/aws-autoscaling";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import * as iam from "aws-cdk-lib/aws-iam";
import * as route53 from "aws-cdk-lib/aws-route53";
import * as s3 from "aws-cdk-lib/aws-s3";
import { Construct, IDependable } from "constructs";

import { SecurityGroups, SecurityGroupTemplate } from "../constructs/security-groups";
import { GoServiceInit } from ".";

export interface ProbeServiceProps {
  /** VPC to deploy into */
  vpc: ec2.IVpc;
  /** Subdomain for this service (e.g., "tcp-probe") */
  subdomain: string;
  /** Route53 hosted zone */
  hostedZone: route53.IHostedZone;
  /** Shared S3 bucket for Let's Encrypt certificates */
  certBucket: s3.IBucket;
  /** Path to Go source file, relative to project root */
  goSourcePath: string;
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
  /** Additional environment variables for the Go service */
  additionalEnv?: Record<string, string>;
}

/**
 * A probe service running on EC2 with auto-scaling and DNS registration.
 *
 * Creates:
 *   - Security Group
 *   - IAM Role with SSM + S3 access
 *   - Launch Template with user data (Go service)
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
      goSourcePath,
      securityGroupTemplate,
      dependsOn,
      instanceType = ec2.InstanceType.of(ec2.InstanceClass.T4G, ec2.InstanceSize.SMALL),
      minCapacity = 2,
      maxCapacity = 10,
      additionalEnv = {},
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

    // S3 access scoped to this service's prefix
    certBucket.grantReadWrite(role);

    // User Data
    const userDataScript = GoServiceInit.generate({
      sourcePath: goSourcePath,
      serviceName,
      installDir: `/opt/${subdomain}`,
      certDir: `/var/lib/${subdomain}-certs`,
      environment: {
        DOMAIN: this.fullDomain,
        CERT_BUCKET: certBucket.bucketName,
        CERT_PREFIX: `${subdomain}/`,
        AWS_REGION: cdk.Stack.of(this).region,
        ...additionalEnv,
      },
      capabilities: ["CAP_NET_BIND_SERVICE"],
    });

    const userData = ec2.UserData.forLinux();
    userData.addCommands(userDataScript);

    // Launch Template
    const launchTemplate = new ec2.LaunchTemplate(this, "LaunchTemplate", {
      machineImage: ec2.MachineImage.latestAmazonLinux2023({
        cpuType: ec2.AmazonLinuxCpuType.ARM_64,
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
