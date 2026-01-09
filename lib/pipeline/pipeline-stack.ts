import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";
import * as codebuild from "aws-cdk-lib/aws-codebuild";
import { PolicyStatement } from "aws-cdk-lib/aws-iam";
import {
  CodePipeline,
  CodePipelineSource,
  CodeBuildStep,
  ManualApprovalStep,
} from "aws-cdk-lib/pipelines";

import { AppStage } from "./pipeline-stages";
import {
  PIPELINE_STAGES,
  GITHUB_REPO,
  GITHUB_BRANCH,
  CODESTAR_CONNECTION_ARN,
  PIPELINE_NAME,
} from "./constants";

export type PipelineStackProps = cdk.StackProps;

/**
 * CDK Pipeline for Argus SIGINT probe services.
 *
 * Deploys: QA → (approval) → UAT → (approval) → Prod
 *
 * Each stage gets:
 * - Stage-prefixed DNS (qa-tcp-probe.wolcott.io, uat-tcp-probe.wolcott.io, tcp-probe.wolcott.io)
 * - Own VPC, ASGs, DynamoDB tables, ECR repos
 *
 * Docker Image Build:
 * The pipeline includes a Docker build step that builds and pushes images to each stage's
 * ECR repositories AFTER the stage infrastructure is deployed. On first deployment,
 * the ASGs will wait for images to be available.
 */
export class PipelineStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props: PipelineStackProps = {}) {
    super(scope, id, props);

    // =========================================================================
    // Source
    // =========================================================================
    const source = CodePipelineSource.connection(GITHUB_REPO, GITHUB_BRANCH, {
      connectionArn: CODESTAR_CONNECTION_ARN,
    });

    // =========================================================================
    // Synth Step
    // =========================================================================
    const synthStep = new CodeBuildStep("Synth", {
      input: source,
      buildEnvironment: {
        buildImage: codebuild.LinuxBuildImage.STANDARD_7_0,
        environmentVariables: {
          NODE_VERSION: { value: "20" },
          CODESTAR_CONNECTION_ARN: { value: CODESTAR_CONNECTION_ARN },
        },
      },
      commands: [
        "n $NODE_VERSION",
        "npm ci",
        "npm run build",
        "npx cdk synth",
      ],
      primaryOutputDirectory: "cdk.out",
      rolePolicyStatements: [
        new PolicyStatement({
          actions: ["route53:ListHostedZonesByName"],
          resources: ["*"],
        }),
        new PolicyStatement({
          actions: [
            "ec2:DescribeAvailabilityZones",
            "ec2:DescribeVpcs",
            "ec2:DescribeSubnets",
            "ec2:DescribeRouteTables",
          ],
          resources: ["*"],
        }),
      ],
    });

    // =========================================================================
    // Pipeline
    // =========================================================================
    const pipeline = new CodePipeline(this, "Pipeline", {
      pipelineName: PIPELINE_NAME,
      crossAccountKeys: true,
      synth: synthStep,
      dockerEnabledForSynth: true, // Enable Docker for any Docker asset builds
    });

    // =========================================================================
    // Deployment Stages
    // =========================================================================
    PIPELINE_STAGES.forEach((stageConfig, index) => {
      const stage = new AppStage(this, stageConfig.name, {
        env: {
          account: this.account,
          region: stageConfig.region,
        },
        stageConfig,
      });

      const deployedStage = pipeline.addStage(stage);

      // Docker images are built via CDK Docker assets during synth/deploy phase
      // This ensures images exist BEFORE ASG instances launch

      // Add manual approval between stages (except after the last one)
      if (index < PIPELINE_STAGES.length - 1) {
        const nextStage = PIPELINE_STAGES[index + 1]!;
        deployedStage.addPost(
          new ManualApprovalStep(`PromoteFrom${stageConfig.name}`, {
            comment: `Approve deployment from ${stageConfig.name} to ${nextStage.name}`,
          })
        );
      }
    });

    // =========================================================================
    // Tags
    // =========================================================================
    cdk.Tags.of(this).add("Application", PIPELINE_NAME);
    cdk.Tags.of(this).add("ManagedBy", "CDK-Pipeline");
  }
}
