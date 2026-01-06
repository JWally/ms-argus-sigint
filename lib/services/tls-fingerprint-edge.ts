// lib/services/third-party-cookie.ts
import * as cdk from "aws-cdk-lib";
import * as cloudfront from "aws-cdk-lib/aws-cloudfront";
import * as origins from "aws-cdk-lib/aws-cloudfront-origins";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as route53 from "aws-cdk-lib/aws-route53";
import * as route53Targets from "aws-cdk-lib/aws-route53-targets";
import * as acm from "aws-cdk-lib/aws-certificatemanager";
import { Construct } from "constructs";

export interface ThirdPartyCookieProps {
  /** Hosted zone for custom domain */
  hostedZone: route53.IHostedZone;
  /** Subdomain for cookie service (e.g., "id" -> id.oicu.info) */
  subdomain?: string;
  /** Cookie name. Default: "_fpid" */
  cookieName?: string;
  /** Cookie max age in seconds. Default: 400 days (max allowed) */
  cookieMaxAge?: number;
}

/**
 * CloudFront distribution that sets a persistent third-party cookie.
 * 
 * The cookie is:
 * - HttpOnly: false (JS readable for fingerprinting)
 * - Secure: true (HTTPS only)
 * - SameSite: None (allows cross-site)
 * - Domain scoped to your domain
 * 
 * Use as a tracking pixel or fetch from any site to get persistent ID.
 */
export class TlsFingerprintEdge extends Construct {
  public readonly distribution: cloudfront.Distribution;
  public readonly endpoint: string;
  public readonly cookieName: string;

  constructor(scope: Construct, id: string, props: ThirdPartyCookieProps) {
    super(scope, id);

    const {
      hostedZone,
      subdomain = "id",
      cookieName = "_fpid",
      cookieMaxAge = 400 * 24 * 60 * 60, // 400 days (Chrome's max)
    } = props;

    this.cookieName = cookieName;
    const fullDomain = `${subdomain}.${hostedZone.zoneName}`;

    // Certificate for custom domain (must be in us-east-1 for CloudFront)
    const certificate = new acm.DnsValidatedCertificate(this, "Cert", {
      domainName: fullDomain,
      hostedZone,
      region: "us-east-1", // Required for CloudFront
    });

    // CloudFront Function - sets/reads cookie, returns visitor ID
    const cookieFn = new cloudfront.Function(this, "CookieFn", {
      functionName: `${cdk.Stack.of(this).stackName}-cookie-${id}`,
      code: cloudfront.FunctionCode.fromInline(`
function handler(event) {
  var request = event.request;
  var cookieName = "${cookieName}";
  var maxAge = ${cookieMaxAge};
  var domain = "${hostedZone.zoneName}";
  
  // Check for existing cookie
  var cookies = request.cookies || {};
  var existingId = cookies[cookieName] ? cookies[cookieName].value : null;
  
  // Generate new ID if none exists
  var visitorId = existingId;
  if (!visitorId) {
    // Simple UUID-like ID (CloudFront Functions have limited APIs)
    var chars = 'abcdef0123456789';
    visitorId = '';
    for (var i = 0; i < 32; i++) {
      if (i === 8 || i === 12 || i === 16 || i === 20) visitorId += '-';
      visitorId += chars.charAt(Math.floor(Math.random() * chars.length));
    }
  }
  
  // Get client info from CloudFront headers
  var h = request.headers;
  var clientAddr = (h['cloudfront-viewer-address'] || {}).value || '';
  var clientIp = clientAddr.replace(/:\\d+$/, '');
  
  var data = {
    id: visitorId,
    new: !existingId,
    ip: clientIp || null,
    country: (h['cloudfront-viewer-country'] || {}).value || null,
    ja3: (h['cloudfront-viewer-ja3-fingerprint'] || {}).value || null,
    ja4: (h['cloudfront-viewer-ja4-fingerprint'] || {}).value || null
  };
  
  // Cookie attributes for CloudFront Functions v2 API
  // SameSite=None + Secure required for cross-site cookies
  var cookieAttrs = 'Max-Age=' + maxAge + '; Path=/; Domain=.' + domain + '; Secure; SameSite=None';

  return {
    statusCode: 200,
    statusDescription: 'OK',
    headers: {
      'content-type': { value: 'application/json' },
      'cache-control': { value: 'no-store, no-cache, must-revalidate' },
      'access-control-allow-origin': { value: '*' },
      'access-control-allow-credentials': { value: 'true' },
      'access-control-allow-methods': { value: 'GET, OPTIONS' },
      'access-control-expose-headers': { value: 'Set-Cookie' }
    },
    cookies: {
      [cookieName]: { value: visitorId, attributes: cookieAttrs }
    },
    body: JSON.stringify(data)
  };
}
`),
      runtime: cloudfront.FunctionRuntime.JS_2_0,
      comment: "Sets persistent third-party tracking cookie",
    });

    // Dummy S3 origin (never hit, function handles everything)
    const dummyBucket = new s3.Bucket(this, "DummyOrigin", {
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
    });

    // Cache policy - no caching (CloudFront Function handles cookies at viewer request stage)
    const cachePolicy = new cloudfront.CachePolicy(this, "CachePolicy", {
      cachePolicyName: `${cdk.Stack.of(this).stackName}-cookie-${id}`,
      comment: "Third-party cookie - no cache",
      defaultTtl: cdk.Duration.seconds(0),
      maxTtl: cdk.Duration.seconds(1),
      minTtl: cdk.Duration.seconds(0),
      cookieBehavior: cloudfront.CacheCookieBehavior.none(),
    });

    // Origin request policy with viewer headers
    const originRequestPolicy = new cloudfront.OriginRequestPolicy(this, "OriginRequestPolicy", {
      originRequestPolicyName: `${cdk.Stack.of(this).stackName}-cookie-headers-${id}`,
      comment: "Include fingerprint and geo headers",
      headerBehavior: cloudfront.OriginRequestHeaderBehavior.allowList(
        "CloudFront-Viewer-JA3-Fingerprint",
        "CloudFront-Viewer-JA4-Fingerprint",
        "CloudFront-Viewer-Address",
        "CloudFront-Viewer-Country"
      ),
      cookieBehavior: cloudfront.OriginRequestCookieBehavior.all(),
    });

    // Distribution
    this.distribution = new cloudfront.Distribution(this, "Distribution", {
      defaultBehavior: {
        origin: origins.S3BucketOrigin.withOriginAccessControl(dummyBucket),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.HTTPS_ONLY,
        allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD_OPTIONS,
        cachePolicy,
        originRequestPolicy,
        functionAssociations: [
          {
            function: cookieFn,
            eventType: cloudfront.FunctionEventType.VIEWER_REQUEST,
          },
        ],
      },
      domainNames: [fullDomain],
      certificate,
      priceClass: cloudfront.PriceClass.PRICE_CLASS_100,
      comment: "Third-Party Cookie Service",
      enabled: true,
      httpVersion: cloudfront.HttpVersion.HTTP2_AND_3,
      enableIpv6: false,
    });

    // DNS record
    new route53.ARecord(this, "ARecord", {
      zone: hostedZone,
      recordName: subdomain,
      target: route53.RecordTarget.fromAlias(
        new route53Targets.CloudFrontTarget(this.distribution)
      ),
    });

    this.endpoint = `https://${fullDomain}/`;

    new cdk.CfnOutput(this, "Endpoint", {
      value: this.endpoint,
      description: "Third-party cookie endpoint",
    });

    new cdk.CfnOutput(this, "CookieName", {
      value: cookieName,
      description: "Cookie name to read from JS",
    });

    cdk.Tags.of(this).add("Component", "ThirdPartyCookie");
  }
}