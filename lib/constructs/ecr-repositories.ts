import * as cdk from "aws-cdk-lib";
import * as ecr from "aws-cdk-lib/aws-ecr";
import { Construct } from "constructs";

export interface EcrRepositoriesProps {
  stackName: string;
  stage: string;
}

/**
 * ECR repositories for probe service Docker images.
 */
export class EcrRepositories extends Construct {
  public readonly tcpProbe: ecr.Repository;
  public readonly stun: ecr.Repository;

  constructor(scope: Construct, id: string, props: EcrRepositoriesProps) {
    super(scope, id);

    const { stackName, stage } = props;
    const retainOnDelete = stage === "prod";

    this.tcpProbe = new ecr.Repository(this, "TcpProbe", {
      repositoryName: `${stackName}/tcp-probe`,
      removalPolicy: retainOnDelete ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
      emptyOnDelete: !retainOnDelete,
      imageScanOnPush: true,
      lifecycleRules: [
        {
          rulePriority: 1,
          description: "Keep last 10 images",
          maxImageCount: 10,
        },
      ],
    });

    this.stun = new ecr.Repository(this, "Stun", {
      repositoryName: `${stackName}/stun`,
      removalPolicy: retainOnDelete ? cdk.RemovalPolicy.RETAIN : cdk.RemovalPolicy.DESTROY,
      emptyOnDelete: !retainOnDelete,
      imageScanOnPush: true,
      lifecycleRules: [
        {
          rulePriority: 1,
          description: "Keep last 10 images",
          maxImageCount: 10,
        },
      ],
    });
  }
}
