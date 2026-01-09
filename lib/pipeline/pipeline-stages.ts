import { Stage, StageProps } from "aws-cdk-lib";
import { Construct } from "constructs";
import { AppStack } from "../stacks/app";
import { PipelineStageConfig, HOSTED_ZONE_DOMAIN } from "./constants";

export interface AppStageProps extends StageProps {
  /** Stage configuration from pipeline constants */
  stageConfig: PipelineStageConfig;
}

/**
 * CDK Pipeline Stage wrapper for AppStack.
 *
 * Handles stage-specific configuration including:
 * - Subdomain prefixes (qa-*, uat-*, no prefix for prod)
 * - Feature flags per stage
 * - Scaling parameters
 */
export class AppStage extends Stage {
  public readonly appStack: AppStack;

  constructor(scope: Construct, id: string, props: AppStageProps) {
    super(scope, id, props);

    const { stageConfig } = props;
    const stageLower = stageConfig.name.toLowerCase();

    // Determine subdomain prefix: "qa-", "uat-", or "" for prod
    const subdomainPrefix = stageLower === "prod" ? "" : `${stageLower}-`;

    this.appStack = new AppStack(this, "ProbeStack", {
      env: props.env,
      stackName: `argus-sigint-${stageLower}`,
      stage: stageLower,
      hostedZoneDomain: HOSTED_ZONE_DOMAIN,
      description: `Argus SIGINT Probe Services - ${stageConfig.name}`,

      // Pass subdomain prefix for stage-specific DNS
      subdomainPrefix,

      features: stageConfig.features,

      vpc: {
        maxAzs: 2,
        enableNat: false,
      },

      // Stage-specific scaling
      scaling: stageConfig.scaling,

      // Use CDK Docker assets to build images during synth/deploy phase
      // This ensures images exist BEFORE ASG instances launch
      autoBuildImages: true,
    });
  }
}
