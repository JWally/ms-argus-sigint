/**
 * Pipeline configuration constants
 */

export interface PipelineStageConfig {
  name: string;
  region: string;
  /** Feature flags for this stage */
  features: {
    tcpProbe: boolean;
    tlsProbe: boolean;
    stun: boolean;
    tlsFingerprint: boolean;
  };
  /** ASG scaling for this stage */
  scaling?: {
    minCapacity?: number;
    maxCapacity?: number;
  };
}

/**
 * Pipeline stages: QA → UAT → Prod
 * Each stage gets its own VPC, ASGs, and stage-prefixed DNS
 */
export const PIPELINE_STAGES: PipelineStageConfig[] = [
  {
    name: "QA",
    region: "us-west-2",
    features: {
      tcpProbe: true,
      tlsProbe: false,
      stun: true,
      tlsFingerprint: true,
    },
    scaling: {
      minCapacity: 1,
      maxCapacity: 2,
    },
  },
  {
    name: "UAT",
    region: "us-west-2",
    features: {
      tcpProbe: true,
      tlsProbe: false,
      stun: true,
      tlsFingerprint: true,
    },
    scaling: {
      minCapacity: 1,
      maxCapacity: 3,
    },
  },
  {
    name: "Prod",
    region: "us-west-2",
    features: {
      tcpProbe: true,
      tlsProbe: false,
      stun: true,
      tlsFingerprint: true,
    },
    scaling: {
      minCapacity: 2,
      maxCapacity: 5,
    },
  },
];

// GitHub source configuration
export const GITHUB_REPO = "JWally/ms-argus-sigint";
export const GITHUB_BRANCH = "main";

// CodeStar Connection ARN - set via environment variable for portability
export const CODESTAR_CONNECTION_ARN: string | undefined = process.env.CODESTAR_CONNECTION_ARN;

// Hosted zone for DNS records
export const HOSTED_ZONE_DOMAIN = "wolcott.io";

// Pipeline name
export const PIPELINE_NAME = "argus-sigint";
