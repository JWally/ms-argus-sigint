# TODO

## Domain Migration

**Priority:** Medium
**Status:** Pending

### Current State
All sigint services are deployed to `wolcott.io`:
- TLS Fingerprint: `{prefix}id.wolcott.io`
- TCP Probe: `{prefix}tcp-probe.wolcott.io`
- STUN: `{prefix}stun.wolcott.io:3478`

Where prefix is: `dev-`, `qa-`, `uat-`, or empty for prod.

### Desired State
Migrate to `argus.pw` or `argus.tc` domain for consistency with ms-argus-web.

### Files to Update
1. `lib/pipeline/constants.ts` - Change `HOSTED_ZONE_DOMAIN`
2. `bin/app.ts` - Change `hostedZoneDomain` for dev stacks

### Prerequisites
- ACM certificate for new domain (wildcard cert recommended: `*.argus.pw` or `*.argus.tc`)
- Route53 hosted zone for the domain
- Update ms-argus-web sigint config to point to new domain

### Migration Steps
1. Request/verify ACM cert in us-east-1 (for CloudFront) and us-west-2 (for ALBs)
2. Update constants in this repo
3. Deploy to dev first, test
4. Run pipeline to deploy QA → UAT → Prod
5. Update ms-argus-web default sigint domain
6. Deprecate old wolcott.io endpoints after migration window

---

## Other TODOs

### STUN Server Enhancements
- [ ] Add TURN server support for stricter NAT environments
- [ ] Log STUN binding requests for analytics

### TCP Probe Enhancements
- [ ] Add more proxy/VPN detection heuristics
- [ ] Consider adding HTTP/3 fingerprinting when available

### TLS Fingerprint
- [ ] Add JA4+ (JA4S, JA4H) when CloudFront supports it
- [ ] Consider adding JARM for server fingerprinting (reverse direction)
