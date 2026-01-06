#!/usr/bin/env node
import "source-map-support/register";
import * as cdk from "aws-cdk-lib";
import { AppStack } from "../lib/stacks/app";

const app = new cdk.App();

const devEnv: cdk.Environment = {
  account: process.env.CDK_DEFAULT_ACCOUNT ?? "713324594279",
  region: "us-west-2",
};

/**
 * Development Stack
 */
new AppStack(app, "probe-dev", {
  env: devEnv,
  stackName: "probe-dev",
  stage: "dev",
  hostedZoneDomain: "wolcott.io",
  description: "Probe Services - Development",

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
});

app.synth();
