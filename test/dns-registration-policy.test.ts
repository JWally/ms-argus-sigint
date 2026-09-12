import {
  healthCheckCallerReference,
  isOwnedDnsRegistration,
  normalizeHostedZoneId,
} from "../src-lambda/dns-registration-policy";

describe("DNS registration ownership policy", () => {
  test("normalizes Route 53 hosted-zone paths", () => {
    expect(normalizeHostedZoneId("/hostedzone/Z123456789")).toBe("Z123456789");
    expect(normalizeHostedZoneId("Z123456789")).toBe("Z123456789");
  });

  test("accepts only instances owned by this stack and hosted zone", () => {
    expect(
      isOwnedDnsRegistration(
        { ownerStackName: "ms-argus-sigint-dev-jw", hostedZoneId: "Z123456789" },
        { stackName: "ms-argus-sigint-dev-jw", hostedZoneId: "/hostedzone/Z123456789" }
      )
    ).toBe(true);
    expect(
      isOwnedDnsRegistration(
        { ownerStackName: "ms-argus-sigint-wolcott", hostedZoneId: "Z123456789" },
        { stackName: "ms-argus-sigint-dev-jw", hostedZoneId: "Z123456789" }
      )
    ).toBe(false);
    expect(
      isOwnedDnsRegistration(
        { ownerStackName: "ms-argus-sigint-dev-jw", hostedZoneId: "ZOTHER" },
        { stackName: "ms-argus-sigint-dev-jw", hostedZoneId: "Z123456789" }
      )
    ).toBe(false);
    expect(
      isOwnedDnsRegistration(
        { hostedZoneId: "Z123456789" },
        { stackName: "ms-argus-sigint-dev-jw", hostedZoneId: "Z123456789" }
      )
    ).toBe(false);
  });

  test("uses a stable, stack-scoped health-check caller reference", () => {
    const first = healthCheckCallerReference("i-0123456789abcdef0");
    const retry = healthCheckCallerReference("i-0123456789abcdef0");

    expect(first).toBe("sigint:i-0123456789abcdef0");
    expect(retry).toBe(first);
  });
});
