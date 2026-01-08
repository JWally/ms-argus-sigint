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
    // Validate CodeStar Connection
    // =========================================================================
    if (!CODESTAR_CONNECTION_ARN) {
      console.warn(`
╔════════════════════════════════════════════════════════════════════════════╗
║  WARNING: CODESTAR_CONNECTION_ARN environment variable is not set!         ║
║                                                                            ║
║  To deploy the pipeline, you need a GitHub CodeStar Connection:            ║
║  1. Go to AWS Console -> CodePipeline -> Settings -> Connections           ║
║  2. Create a new GitHub connection (or use an existing one)                ║
║  3. Set the environment variable:                                          ║
║     export CODESTAR_CONNECTION_ARN="arn:aws:codestar-connections:..."      ║
║  4. Re-run the deployment                                                  ║
╚════════════════════════════════════════════════════════════════════════════╝
`);
      throw new Error("CODESTAR_CONNECTION_ARN environment variable is required for pipeline deployment");
    }

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
      const stageLower = stageConfig.name.toLowerCase();

      const stage = new AppStage(this, stageConfig.name, {
        env: {
          account: this.account,
          region: stageConfig.region,
        },
        stageConfig,
      });

      const deployedStage = pipeline.addStage(stage);

      // Add Docker build step after each stage deployment
      // This builds and pushes images to the stage's ECR repos
      const dockerBuildStep = new CodeBuildStep(`DockerBuild-${stageConfig.name}`, {
        buildEnvironment: {
          buildImage: codebuild.LinuxBuildImage.AMAZON_LINUX_2_ARM_3,
          computeType: codebuild.ComputeType.SMALL,
          privileged: true,
          environmentVariables: {
            AWS_ACCOUNT: { value: this.account },
            AWS_REGION: { value: stageConfig.region },
            STAGE_NAME: { value: stageLower },
          },
        },
        commands: [
          // Authenticate to ECR
          "aws ecr get-login-password --region $AWS_REGION | docker login --username AWS --password-stdin $AWS_ACCOUNT.dkr.ecr.$AWS_REGION.amazonaws.com",

          // Set ECR repo URIs based on stage
          "export TCP_PROBE_REPO=$AWS_ACCOUNT.dkr.ecr.$AWS_REGION.amazonaws.com/argus-sigint-$STAGE_NAME/tcp-probe",
          "export STUN_REPO=$AWS_ACCOUNT.dkr.ecr.$AWS_REGION.amazonaws.com/argus-sigint-$STAGE_NAME/stun",

          // Get git SHA for tagging
          "export GIT_SHA=$(echo $CODEBUILD_RESOLVED_SOURCE_VERSION | cut -c1-7)",
          "echo \"Building images for stage $STAGE_NAME with tag: $GIT_SHA\"",

          // Build and push tcp-probe
          "echo '=== Building tcp-probe ==='",
          "docker build --platform linux/arm64 -t $TCP_PROBE_REPO:latest -t $TCP_PROBE_REPO:$GIT_SHA src-go/tcp-probe",
          "docker push $TCP_PROBE_REPO:latest",
          "docker push $TCP_PROBE_REPO:$GIT_SHA",

          // Build and push stun
          "echo '=== Building stun ==='",
          "docker build --platform linux/arm64 -t $STUN_REPO:latest -t $STUN_REPO:$GIT_SHA src-go/stun",
          "docker push $STUN_REPO:latest",
          "docker push $STUN_REPO:$GIT_SHA",

          "echo '=== Docker builds complete for $STAGE_NAME ==='",
        ],
        rolePolicyStatements: [
          new PolicyStatement({
            actions: [
              "ecr:GetAuthorizationToken",
              "ecr:BatchCheckLayerAvailability",
              "ecr:GetDownloadUrlForLayer",
              "ecr:BatchGetImage",
              "ecr:PutImage",
              "ecr:InitiateLayerUpload",
              "ecr:UploadLayerPart",
              "ecr:CompleteLayerUpload",
            ],
            resources: ["*"],
          }),
        ],
      });

      // Docker build runs after stage deployment (so ECR repos exist)
      deployedStage.addPost(dockerBuildStep);

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
