import * as cdk from "aws-cdk-lib";
import * as events from "aws-cdk-lib/aws-events";
import * as targets from "aws-cdk-lib/aws-events-targets";
import { Construct } from "constructs";

import { Lambdas } from "./lambdas";

export interface EventRulesProps {
  stackName: string;
  lambdas: Lambdas;
}

/**
 * EventBridge rules for EC2 instance state changes.
 *
 * Rules:
 *   - instanceLaunch: Fires when EC2 instance enters "running"
 *   - instanceTerminate: Fires when EC2 instance enters "shutting-down" or "terminated"
 *
 * Lambda reads instance tags to determine which subdomain to register,
 * so these rules are shared across all probe services.
 */
export class EventRules extends Construct {
  public readonly instanceLaunch: events.Rule;
  public readonly instanceTerminate: events.Rule;

  constructor(scope: Construct, id: string, props: EventRulesProps) {
    super(scope, id);

    const { stackName, lambdas } = props;

    // Instance Launch Rule
    this.instanceLaunch = new events.Rule(this, "InstanceLaunch", {
      ruleName: `${stackName}-instance-launch`,
      description: "Triggers DNS registration when EC2 instance starts running",
      eventPattern: {
        source: ["aws.ec2"],
        detailType: ["EC2 Instance State-change Notification"],
        detail: { state: ["running"] },
      },
    });

    this.instanceLaunch.addTarget(
      new targets.LambdaFunction(lambdas.dnsRegister, { retryAttempts: 2 })
    );

    // Instance Termination Rule
    this.instanceTerminate = new events.Rule(this, "InstanceTerminate", {
      ruleName: `${stackName}-instance-terminate`,
      description: "Triggers DNS deregistration when EC2 instance terminates",
      eventPattern: {
        source: ["aws.ec2"],
        detailType: ["EC2 Instance State-change Notification"],
        detail: { state: ["shutting-down", "terminated"] },
      },
    });

    this.instanceTerminate.addTarget(
      new targets.LambdaFunction(lambdas.dnsDeregister, { retryAttempts: 2 })
    );

    cdk.Tags.of(this).add("Component", "EventRules");
  }
}
