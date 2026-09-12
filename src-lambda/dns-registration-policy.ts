export interface DnsRegistrationOwner {
  ownerStackName?: string;
  hostedZoneId: string;
}

export interface DnsRegistrationBoundary {
  stackName: string;
  hostedZoneId: string;
}

export function normalizeHostedZoneId(hostedZoneId: string): string {
  return hostedZoneId.replace(/^\/hostedzone\//, "");
}

export function isOwnedDnsRegistration(
  candidate: DnsRegistrationOwner,
  boundary: DnsRegistrationBoundary
): boolean {
  return (
    candidate.ownerStackName === boundary.stackName &&
    normalizeHostedZoneId(candidate.hostedZoneId) === normalizeHostedZoneId(boundary.hostedZoneId)
  );
}

export function healthCheckCallerReference(instanceId: string): string {
  return `sigint:${instanceId}`;
}
