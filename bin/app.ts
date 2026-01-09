#!/usr/bin/env node
import "source-map-support/register";
import * as cdk from "aws-cdk-lib";
import { AppStack } from "../lib/stacks/app";
import { PipelineStack } from "../lib/pipeline/pipeline-stack";

const app = new cdk.App();

const defaultEnv: cdk.Environment = {
  account: process.env.CDK_DEFAULT_ACCOUNT ?? "713324594279",
  region: process.env.CDK_DEFAULT_REGION ?? "us-west-2",
};

// =========================================================================
// Pipeline Stack (deploys QA → UAT → Prod)
// =========================================================================
// Only deploy pipeline if CodeStar connection is configured
if (process.env.CODESTAR_CONNECTION_ARN) {
  new PipelineStack(app, "argus-sigint-pipeline", {
    env: defaultEnv,
    stackName: "argus-sigint-pipeline",
    description: "Argus SIGINT CI/CD Pipeline (QA → UAT → Prod)",
  });
}

// =========================================================================
// Development Stack (standalone, for local development)
// =========================================================================
new AppStack(app, "ms-argus-sigint-dev-jw", {
  env: defaultEnv,
  stackName: "ms-argus-sigint-dev-jw",
  stage: "dev",
  hostedZoneDomain: "wolcott.io",
  description: "Probe Services - Development",

  // Dev uses "dev-" prefix for subdomains
  subdomainPrefix: "dev-",

  features: {
    tcpProbe: true,
    tlsProbe: false,
    stun: true,
    tlsFingerprint: true,
  },

  vpc: {
    maxAzs: 2,
    enableNat: false,
  },

  scaling: {
    minCapacity: 1,
    maxCapacity: 2,
  },
});

app.synth();
