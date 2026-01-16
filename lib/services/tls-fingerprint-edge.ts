// lib/services/tls-fingerprint-edge.ts
import * as cdk from "aws-cdk-lib";
import * as cloudfront from "aws-cdk-lib/aws-cloudfront";
import * as origins from "aws-cdk-lib/aws-cloudfront-origins";
import * as s3 from "aws-cdk-lib/aws-s3";
import * as s3deploy from "aws-cdk-lib/aws-s3-deployment";
import * as route53 from "aws-cdk-lib/aws-route53";
import * as route53Targets from "aws-cdk-lib/aws-route53-targets";
import * as acm from "aws-cdk-lib/aws-certificatemanager";
import { Construct } from "constructs";

// Minimal 1x1 transparent ICO file (62 bytes) - base64 encoded
const FAVICON_ICO_BASE64 =
  "AAABAAEAAQEAAAEAGAAwAAAAFgAAACgAAAABAAAAAgAAAAEAGAAAAAAACAAAAAAAAAAA" +
  "AAAAAAAAAAAAAAAAAAAAAP//AAD//wAA";

export interface FaviconCacheConfig {
  /** Enable favicon cache fingerprinting. Default: true */
  enabled?: boolean;
  /** Number of favicon bits (2^n unique IDs). Default: 32 */
  bits?: number;
  /** Path prefix for favicon files. Default: "/fav" */
  pathPrefix?: string;
}

export interface ThirdPartyCookieProps {
  /** Hosted zone for custom domain */
  hostedZone: route53.IHostedZone;
  /** Subdomain for cookie service (e.g., "id" -> id.oicu.info) */
  subdomain?: string;
  /** Cookie name. Default: "_fpid" */
  cookieName?: string;
  /** Cookie max age in seconds. Default: 400 days (max allowed) */
  cookieMaxAge?: number;
  /** Favicon cache fingerprinting configuration */
  faviconCache?: FaviconCacheConfig;
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
  public readonly faviconEndpoint?: string;
  public readonly faviconBits: number;

  constructor(scope: Construct, id: string, props: ThirdPartyCookieProps) {
    super(scope, id);

    const {
      hostedZone,
      subdomain = "id",
      cookieName = "_fpid",
      cookieMaxAge = 400 * 24 * 60 * 60, // 400 days (Chrome's max)
      faviconCache = {},
    } = props;

    const {
      enabled: faviconEnabled = true,
      bits: faviconBits = 32,
      pathPrefix: faviconPath = "/fav",
    } = faviconCache;

    this.faviconBits = faviconBits;

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
    asn: (h['cloudfront-viewer-asn'] || {}).value || null,
    country: (h['cloudfront-viewer-country'] || {}).value || null,
    ja3: (h['cloudfront-viewer-ja3-fingerprint'] || {}).value || null,
    ja4: (h['cloudfront-viewer-ja4-fingerprint'] || {}).value || null
  };

  // Cookie attributes for CloudFront Functions v2 API
  // SameSite=None + Secure required for cross-site cookies
  var cookieAttrs = 'Max-Age=' + maxAge + '; Path=/; Domain=.' + domain + '; Secure; SameSite=None';

  // Get Origin header for CORS - must echo specific origin when using credentials
  // Cannot use wildcard '*' with Access-Control-Allow-Credentials: true
  var origin = (h['origin'] || {}).value || '*';

  return {
    statusCode: 200,
    statusDescription: 'OK',
    headers: {
      'content-type': { value: 'application/json' },
      'cache-control': { value: 'no-store, no-cache, must-revalidate' },
      'access-control-allow-origin': { value: origin },
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

    // S3 origin bucket - used for favicon cache files
    const originBucket = new s3.Bucket(this, "OriginBucket", {
      removalPolicy: cdk.RemovalPolicy.DESTROY,
      autoDeleteObjects: true,
      blockPublicAccess: s3.BlockPublicAccess.BLOCK_ALL,
    });

    // Deploy favicon ICO files for cache fingerprinting
    if (faviconEnabled) {
      const faviconS3Prefix = faviconPath.replace(/^\//, "");

      new s3deploy.BucketDeployment(this, "FaviconDeployment", {
        sources: [
          s3deploy.Source.data(
            `${faviconS3Prefix}/manifest.json`,
            JSON.stringify({ bits: faviconBits, version: 1 })
          ),
          // Deploy each ICO file (32 by default = 2^32 unique IDs)
          ...Array.from({ length: faviconBits }, (_, i) =>
            s3deploy.Source.data(
              `${faviconS3Prefix}/${i}.ico`,
              Buffer.from(FAVICON_ICO_BASE64, "base64").toString("binary")
            )
          ),
        ],
        destinationBucket: originBucket,
        prune: false, // Don't delete other files
        cacheControl: [
          s3deploy.CacheControl.maxAge(cdk.Duration.days(365)),
          s3deploy.CacheControl.setPublic(),
        ],
        contentType: "image/x-icon",
      });
    }

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
        "CloudFront-Viewer-Country",
        "CloudFront-Viewer-ASN"
      ),
      cookieBehavior: cloudfront.OriginRequestCookieBehavior.all(),
    });

    // Favicon cache policy - immutable, long-term caching
    const faviconCachePolicy = faviconEnabled
      ? new cloudfront.CachePolicy(this, "FaviconCachePolicy", {
          cachePolicyName: `${cdk.Stack.of(this).stackName}-favicon-${id}`,
          comment: "Favicon cache fingerprinting - immutable",
          defaultTtl: cdk.Duration.days(365),
          maxTtl: cdk.Duration.days(365),
          minTtl: cdk.Duration.days(365),
          cookieBehavior: cloudfront.CacheCookieBehavior.none(),
          queryStringBehavior: cloudfront.CacheQueryStringBehavior.none(),
          headerBehavior: cloudfront.CacheHeaderBehavior.none(),
          enableAcceptEncodingGzip: false,
          enableAcceptEncodingBrotli: false,
        })
      : undefined;

    // Favicon response headers - CORS + immutable cache
    const faviconResponseHeadersPolicy = faviconEnabled
      ? new cloudfront.ResponseHeadersPolicy(this, "FaviconResponseHeaders", {
          responseHeadersPolicyName: `${cdk.Stack.of(this).stackName}-favicon-headers-${id}`,
          comment: "Favicon cache - CORS + immutable",
          corsBehavior: {
            accessControlAllowOrigins: ["*"],
            accessControlAllowMethods: ["GET", "HEAD", "OPTIONS"],
            accessControlAllowHeaders: ["*"],
            accessControlAllowCredentials: false,
            originOverride: true,
          },
          customHeadersBehavior: {
            customHeaders: [
              {
                header: "Cache-Control",
                value: "public, max-age=31536000, immutable",
                override: true,
              },
              {
                header: "X-Favicon-Bit",
                value: "true",
                override: true,
              },
            ],
          },
        })
      : undefined;

    // Build additional behaviors for favicon route
    const additionalBehaviors: Record<string, cloudfront.BehaviorOptions> = {};

    if (faviconEnabled && faviconCachePolicy && faviconResponseHeadersPolicy) {
      additionalBehaviors[`${faviconPath}/*`] = {
        origin: origins.S3BucketOrigin.withOriginAccessControl(originBucket),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.HTTPS_ONLY,
        allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD_OPTIONS,
        cachedMethods: cloudfront.CachedMethods.CACHE_GET_HEAD_OPTIONS,
        cachePolicy: faviconCachePolicy,
        responseHeadersPolicy: faviconResponseHeadersPolicy,
        compress: false, // Don't compress tiny ICO files
      };

      this.faviconEndpoint = `https://${fullDomain}${faviconPath}/`;
    }

    // Distribution
    this.distribution = new cloudfront.Distribution(this, "Distribution", {
      defaultBehavior: {
        origin: origins.S3BucketOrigin.withOriginAccessControl(originBucket),
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
      additionalBehaviors,
      domainNames: [fullDomain],
      certificate,
      priceClass: cloudfront.PriceClass.PRICE_CLASS_100,
      comment: "TLS Fingerprint + Favicon Cache Service",
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

    if (this.faviconEndpoint) {
      new cdk.CfnOutput(this, "FaviconEndpoint", {
        value: this.faviconEndpoint,
        description: "Favicon cache endpoint (e.g., /fav/0.ico ... /fav/31.ico)",
      });

      new cdk.CfnOutput(this, "FaviconBits", {
        value: String(faviconBits),
        description: "Number of favicon bits for ID encoding",
      });
    }

    cdk.Tags.of(this).add("Component", "TlsFingerprintEdge");
  }
}