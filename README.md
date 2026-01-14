# ms-argus-sigint

Modular device profiling infrastructure for VPN/proxy detection using TCP/TLS fingerprinting, STUN, and browser fingerprinting signals.

## Services

| Service | Description | Subdomain |
|---------|-------------|-----------|
| **TCP Probe** | Cross-layer RTT analysis for proxy/VPN detection | `tcp-probe.*` |
| **TLS Fingerprint** | JA3/JA4 fingerprints + third-party cookies + favicon cache | `id.*` |
| **STUN** | STUN binding for NAT type and IP detection | `stun.*` |
| **TLS Probe** | TLS-specific probe (shares tcp-probe image) | `tls-probe.*` |

## Architecture

```
┌─────────────────────────────────────────────────────────────────────────────────┐
│                               AppStack                                           │
├──────────────┬──────────────┬──────────────┬───────────────┬───────────────────┤
│     VPC      │    Tables    │   Lambdas    │   Services    │      Edge         │
│              │              │              │               │                   │
│ Public       │ DnsRegistry  │ dns-register │ TCP Probe     │ TlsFingerprintEdge│
│ Subnets      │ (DynamoDB)   │ dns-deregist │ STUN          │ (CloudFront)      │
│              │              │ dns-cleanup  │ TLS Probe     │ - JA3/JA4         │
│              │              │              │ (EC2 ASG)     │ - Cookies         │
│              │              │              │               │ - Favicon Cache   │
└──────────────┴──────────────┴──────────────┴───────────────┴───────────────────┘
```

## Project Structure

```
├── bin/
│   └── app.ts                    # CDK app entry point
├── lib/
│   ├── constructs/               # Reusable CDK constructs
│   │   ├── vpc.ts
│   │   ├── tables.ts
│   │   ├── lambdas.ts
│   │   ├── event-rules.ts
│   │   ├── security-groups.ts
│   │   └── ecr-repositories.ts
│   ├── services/                 # Service constructs
│   │   ├── dns-cleanup.ts        # Custom resource for DNS cleanup
│   │   └── tls-fingerprint-edge.ts  # CloudFront-based TLS fingerprinting
│   ├── helpers/
│   │   ├── asg-ec2-go-launcher.ts   # ProbeService (EC2 ASG + Go container)
│   │   ├── docker-service-init.ts
│   │   └── go-service-init.ts
│   ├── pipeline/                 # CI/CD pipeline
│   │   ├── pipeline-stack.ts     # CodePipeline definition
│   │   ├── pipeline-stages.ts    # QA → UAT → Prod stages
│   │   └── constants.ts
│   └── stacks/
│       └── app.ts                # Main application stack
├── src-lambda/
│   └── handlers/                 # Lambda handlers
│       ├── dns-register.ts       # EC2 launch → DNS registration
│       ├── dns-deregister.ts     # EC2 terminate → DNS removal
│       └── dns-cleanup.ts        # Stack delete → full cleanup
└── src-go/
    ├── tcp-probe/                # TCP RTT probe (Go + Docker)
    │   ├── main.go
    │   └── Dockerfile
    └── stun/                     # STUN server (Go + Docker)
        ├── main.go
        └── Dockerfile
```

---

## TCP Probe Service

Collects TCP-level metrics for proxy/VPN detection based on cross-layer RTT analysis.

**Signals collected:**
- TCP RTT (kernel-level, to immediate peer)
- TLS handshake duration
- HTTP first byte timing
- MSS/MTU (reduced by VPN tunnel overhead)
- Client Hints (Sec-CH-UA-* headers)

**Output:**
```json
{
  "tcp_rtt_us": 12500,
  "tls_handshake_us": 45000,
  "snd_mss": 1360,
  "pmtu": 1400,
  "proxy_score": 0.75,
  "vpn_score": 0.82
}
```

---

## TLS Fingerprint Edge Service

CloudFront-based service providing:

1. **JA3/JA4 Fingerprints** - TLS fingerprints from CloudFront headers
2. **Third-Party Cookies** - Persistent cross-site tracking cookie
3. **Favicon Cache Fingerprinting** - Device identification via browser cache

**Output:**
```json
{
  "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
  "new": false,
  "ip": "203.0.113.42",
  "asn": "AS12345",
  "country": "US",
  "ja3": "771,4865-4866-4867...",
  "ja4": "t13d1516h2_8daaf6152771..."
}
```

---

## Flow

1. **EC2 Instance Launches** → EventBridge triggers `dns-register` Lambda
2. **Lambda reads DNS tags** from instance (`dns:subdomain`, `dns:fullDomain`, `dns:hostedZoneId`)
3. **Creates Route53 health check** → Creates DNS A record with MultiValue routing
4. **Stores mapping in DynamoDB** for cleanup tracking
5. **Instance terminates** → EventBridge triggers `dns-deregister` Lambda
6. **Stack delete** → Custom resource triggers `dns-cleanup` Lambda

---

## Feature Flags

Configure services in `bin/app.ts`:

```typescript
new AppStack(app, "my-stack", {
  features: {
    tcpProbe: true,       // TCP RTT probe service
    tlsProbe: false,      // TLS-specific probe
    stun: true,           // STUN binding service
    tlsFingerprint: true, // CloudFront JA3/JA4 + cookies
  },
  scaling: {
    minCapacity: 2,
    maxCapacity: 5,
  },
});
```

---

## Commands

```bash
# Build
npm run build         # Compile TypeScript

# Deploy
npm run deploy:dev    # Deploy dev stack
npm run deploy:dev:approve  # Deploy without approval prompt
npm run diff:dev      # Show changes
npm run destroy:dev   # Destroy dev stack

# Synth
npm run synth         # Synthesize all stacks
npm run synth:dev     # Synthesize dev stack only

# Docker
npm run docker:build      # Build and push Docker images
npm run docker:build:dev  # Build for dev stack

# Test
npm test              # Run tests
npm run test:watch    # Watch mode
npm run test:coverage # Coverage report

# Code Quality
npm run lint          # Run ESLint
npm run lint:fix      # Fix lint issues
npm run format        # Format with Prettier
npm run format:check  # Check formatting

# Cleanup
npm run clean         # Remove dist, cdk.out, coverage
```

---

## Instance Tags

Instances are tagged for DNS registration:

| Tag | Example | Purpose |
|-----|---------|---------|
| `dns:subdomain` | `tcp-probe` | Service identifier |
| `dns:fullDomain` | `tcp-probe.argus.pw` | Route53 record name |
| `dns:hostedZoneId` | `Z02318...` | Route53 zone |

---

## Health Checks

- Route53 health check on port 8080 `/health`
- 10 second intervals, 2 failure threshold
- Unhealthy instances removed from DNS rotation

---

## Pipeline

The project includes a CI/CD pipeline (`argus-sigint-pipeline`) that deploys:

1. **QA** - Automatic deployment on main branch push
2. **UAT** - Manual approval required
3. **Prod** - Manual approval required

Pipeline shares Docker images built once across all stages via ECR.

---

## Adding a New Probe Service

1. Create Go source in `src-go/<service-name>/`
2. Add Dockerfile in same directory
3. Add feature flag to `AppStackProps.features`
4. Add `ProbeService` block in `lib/stacks/app.ts`:

```typescript
if (enabledFeatures.myProbe && myProbeRepo) {
  new ProbeService(this, "MyProbe", {
    vpc: vpc.vpc,
    subdomain: getSubdomain("my-probe"),
    hostedZone,
    certBucket,
    ecrRepository: myProbeRepo,
    imageTag: myProbeImageTag,
    securityGroupTemplate: SecurityGroupTemplate.TCP_PROBE,
    dependsOn: serviceDependencies,
    minCapacity: defaultMinCapacity,
    maxCapacity: defaultMaxCapacity,
  });
}
```
