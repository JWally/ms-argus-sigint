import * as ec2 from "aws-cdk-lib/aws-ec2";
import { Construct } from "constructs";

/**
 * Predefined security group templates for probe infrastructure.
 */
export enum SecurityGroupTemplate {
  /** TCP probe: HTTP 80, HTTPS 443, health 8080 */
  TCP_PROBE = "TCP_PROBE",
  /** TLS probe: same as TCP_PROBE */
  TLS_PROBE = "TLS_PROBE",
  /** STUN server: UDP/TCP on configurable port (default 3478) */
  STUN = "STUN",
}

export interface SecurityGroupProps {
  vpc: ec2.IVpc;
  template: SecurityGroupTemplate;
  /** STUN port override. Default: 3478 */
  stunPort?: number;
}

/**
 * Factory for creating security groups with predefined templates.
 */
export class SecurityGroups {
  public static create(scope: Construct, id: string, props: SecurityGroupProps): ec2.SecurityGroup {
    const sg = new ec2.SecurityGroup(scope, id, {
      vpc: props.vpc,
      description: `Security group for ${props.template}`,
      allowAllOutbound: true,
    });

    switch (props.template) {
      case SecurityGroupTemplate.TCP_PROBE:
      case SecurityGroupTemplate.TLS_PROBE:
        sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(80), "ACME HTTP-01 challenge");
        sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(443), "HTTPS probe endpoint");
        sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(8080), "Health check");
        break;

      case SecurityGroupTemplate.STUN: {
        const port = props.stunPort ?? 3478;
        sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.udp(port), "STUN UDP");
        sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(port), "STUN TCP");
        sg.addIngressRule(ec2.Peer.anyIpv4(), ec2.Port.tcp(8080), "Health check");
        break;
      }
    }

    return sg;
  }
}
