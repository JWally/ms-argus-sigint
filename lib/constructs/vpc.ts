import * as cdk from "aws-cdk-lib";
import * as ec2 from "aws-cdk-lib/aws-ec2";
import { Construct } from "constructs";

export interface VpcProps {
  /** Maximum availability zones. Default: 2 */
  maxAzs?: number;
  /** Enable NAT gateway for private subnet egress. Default: false */
  enableNat?: boolean;
  /** CIDR block for the VPC. Default: 10.0.0.0/16 */
  cidr?: string;
}

/**
 * Minimal VPC for probe infrastructure.
 * Public subnets only by default for cost efficiency.
 */
export class Vpc extends Construct {
  public readonly vpc: ec2.Vpc;

  constructor(scope: Construct, id: string, props: VpcProps = {}) {
    super(scope, id);

    const { maxAzs = 2, enableNat = false, cidr = "10.0.0.0/16" } = props;

    const subnetConfiguration: ec2.SubnetConfiguration[] = [
      {
        name: "Public",
        subnetType: ec2.SubnetType.PUBLIC,
        cidrMask: 24,
        mapPublicIpOnLaunch: true,
      },
    ];

    if (enableNat) {
      subnetConfiguration.push({
        name: "Private",
        subnetType: ec2.SubnetType.PRIVATE_WITH_EGRESS,
        cidrMask: 24,
      });
    }

    this.vpc = new ec2.Vpc(this, "Vpc", {
      ipAddresses: ec2.IpAddresses.cidr(cidr),
      maxAzs,
      natGateways: enableNat ? 1 : 0,
      subnetConfiguration,
      enableDnsHostnames: true,
      enableDnsSupport: true,
    });

    cdk.Tags.of(this).add("Component", "Vpc");
  }
}
