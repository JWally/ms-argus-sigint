# ms-argus-tcp-probe

Modular device profiling infrastructure for VPN/proxy detection using TCP/TLS fingerprinting.

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              AppStack                                        │
├──────────────┬──────────────┬──────────────┬──────────────┬─────────────────┤
│     VPC      │    Tables    │   Lambdas    │  EventRules  │  ProbeService   │
│              │              │              │              │                 │
│ Public       │ DnsRegistry  │ dns-register │ Launch Rule  │ EC2 ASG         │
│ Subnets      │ (DynamoDB)   │ dns-deregist │ Term Rule    │ Go Service      │
│              │              │ dns-cleanup  │              │ DNS Tags        │
└──────────────┴──────────────┴──────────────┴──────────────┴─────────────────┘
```

## Flow

1. **EC2 Instance Launches** → EventBridge triggers `dns-register` Lambda
2. **Lambda reads DNS tags** from instance (`dns:subdomain`, `dns:fullDomain`, `dns:hostedZoneId`)
3. **Creates Route53 health check** → Creates DNS A record with MultiValue routing
4. **Stores mapping in DynamoDB** for cleanup tracking
5. **Instance terminates** → EventBridge triggers `dns-deregister` Lambda
6. **Stack delete** → Custom resource triggers `dns-cleanup` Lambda

## Project Structure

```
├── bin/
│   └── app.ts              # CDK app entry point
├── lib/
│   ├── constructs/         # Reusable CDK constructs
│   │   ├── vpc.ts
│   │   ├── tables.ts
│   │   ├── lambdas.ts
│   │   ├── event-rules.ts
│   │   ├── dns-cleanup.ts
│   │   ├── probe-service.ts
│   │   └── security-groups.ts
│   ├── helpers/
│   │   └── go-service-init.ts
│   └── stacks/
│       └── app.ts          # Main stack
├── src-lambda/
│   └── handlers/           # Lambda source code
└── src-go/
    └── tcp-probe/          # Go probe service
```

## Adding a New Probe Service

1. Create Go source in `src-go/<service-name>/main.go`
2. Add feature flag to `AppStackProps.features`
3. Add `ProbeService` block in `lib/stacks/app.ts`:

```typescript
if (enabledFeatures.myProbe) {
  new ProbeService(this, "MyProbe", {
    vpc: vpc.vpc,
    subdomain: "my-probe",
    hostedZone,
    certBucket,
    goSourcePath: "src-go/my-probe/main.go",
    securityGroupTemplate: SecurityGroupTemplate.TCP_PROBE,
    dependsOn: serviceDependencies,
  });
}
```

## Commands

```bash
npm run build       # Compile TypeScript
npm run synth       # Synthesize CloudFormation
npm run deploy:dev  # Deploy dev stack
npm run diff:dev    # Show changes
npm run destroy:dev # Destroy dev stack
```

## Instance Tags

Instances are tagged for DNS registration:

| Tag                | Example               | Purpose             |
| ------------------ | --------------------- | ------------------- |
| `dns:subdomain`    | `tcp-probe`           | Service identifier  |
| `dns:fullDomain`   | `tcp-probe.oicu.info` | Route53 record name |
| `dns:hostedZoneId` | `Z02318...`           | Route53 zone        |

## Health Checks

- Route53 health check on port 8080 `/health`
- 10 second intervals, 2 failure threshold
- Unhealthy instances removed from DNS rotation
