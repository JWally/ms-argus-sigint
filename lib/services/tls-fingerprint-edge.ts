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
 * Response format: base64(json_payload) + "." + siphash24_hex(canonical, key)
 * canonical = "id|ip|asn|ts" — geo fields are advisory, not signed.
 * ts (Unix epoch seconds) enables replay prevention in the API (90s window).
 * SipHash-2-4 key (first 16 bytes of stored 64-char hex) in CloudFront KeyValueStore.
 *
 * Cookie is HttpOnly:false, Secure, SameSite:None — cross-site persistent ID.
 */
export class TlsFingerprintEdge extends Construct {
  public readonly distribution: cloudfront.Distribution;
  public readonly endpoint: string;
  public readonly cookieName: string;
  public readonly faviconEndpoint?: string;
  public readonly faviconBits: number;
  public readonly hmacKvs: cloudfront.KeyValueStore;

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
    const stackName = cdk.Stack.of(this).stackName;

    // Certificate for custom domain (must be in us-east-1 for CloudFront)
    const certificate = new acm.DnsValidatedCertificate(this, "Cert", {
      domainName: fullDomain,
      hostedZone,
      region: "us-east-1",
    });

    // KeyValueStore for HMAC signing key
    // Populate after deploy: aws cloudfront-keyvaluestore put-key \
    //   --kvs-arn <KvsArn output> --key hmac-key --value <32-byte hex>
    this.hmacKvs = new cloudfront.KeyValueStore(this, "HmacKvs", {
      keyValueStoreName: `${stackName}-hmac-${id}`,
      comment: "HMAC-SHA256 signing key for CF token integrity",
    });

    // CloudFront Function — sets cookie, returns signed token
    // Token format: base64(json) + "." + hmac_sha256_hex(canonical, key)
    // canonical = "id|ip|asn|ts" — geo fields are advisory, not signed
    // API verifies: HMAC + ts freshness (90s) + ip match
    const cookieFn = new cloudfront.Function(this, "CookieFn", {
      functionName: `${stackName}-cookie-${id}`,
      runtime: cloudfront.FunctionRuntime.JS_2_0,
      comment: "Sets persistent third-party cookie, returns HMAC-signed token",
      keyValueStore: this.hmacKvs,
      code: cloudfront.FunctionCode.fromInline(`
import cf from 'cloudfront';

var _store=cf.kvs('${this.hmacKvs.keyValueStoreId}');

// SipHash-2-4 fully inlined: scalar state variables, no array allocation in hot path.
// 128-bit key (first 16 bytes of stored 64-char hex) → 64-bit tag (16-char hex).
// ~23% CFF compute utilization at edge for a typical 70-char canonical string.
var _sip=(function(){
  function hx(h){var b=[];for(var i=0;i<h.length;i+=2)b.push(parseInt(h.substr(i,2),16));return b;}
  return function(kh,msg){
    var k=hx(kh.substr(0,32));
    var k0l=(k[0]|(k[1]<<8)|(k[2]<<16)|(k[3]<<24))>>>0,k0h=(k[4]|(k[5]<<8)|(k[6]<<16)|(k[7]<<24))>>>0;
    var k1l=(k[8]|(k[9]<<8)|(k[10]<<16)|(k[11]<<24))>>>0,k1h=(k[12]|(k[13]<<8)|(k[14]<<16)|(k[15]<<24))>>>0;
    var v0l=(k0l^0x736f6d65)>>>0,v0h=(k0h^0x70736575)>>>0;
    var v1l=(k1l^0x646f7261)>>>0,v1h=(k1h^0x6e646f6d)>>>0;
    var v2l=(k0l^0x6c796765)>>>0,v2h=(k0h^0x6e657261)>>>0;
    var v3l=(k1l^0x74656462)>>>0,v3h=(k1h^0x79746573)>>>0;
    var mb=[],cc,l=msg.length;
    for(var i=0;i<l;i++){cc=msg.charCodeAt(i);if(cc<128)mb.push(cc);else if(cc<2048)mb.push(0xc0|(cc>>6),0x80|(cc&63));else mb.push(0xe0|(cc>>12),0x80|((cc>>6)&63),0x80|(cc&63));}
    var ml=mb.length;while(mb.length%8!==7)mb.push(0);mb.push(ml&255);
    var tl,ci,wl,wh;
    for(var i=0;i<mb.length;i+=8){
      wl=(mb[i]|(mb[i+1]<<8)|(mb[i+2]<<16)|(mb[i+3]<<24))>>>0;
      wh=(mb[i+4]|(mb[i+5]<<8)|(mb[i+6]<<16)|(mb[i+7]<<24))>>>0;
      v3l=(v3l^wl)>>>0;v3h=(v3h^wh)>>>0;
      tl=(v0l+v1l)>>>0;ci=tl<v0l?1:0;v0l=tl;v0h=(v0h+v1h+ci)>>>0;tl=(v2l+v3l)>>>0;ci=tl<v2l?1:0;v2l=tl;v2h=(v2h+v3h+ci)>>>0;tl=((v1l<<13)|(v1h>>>19))>>>0;v1h=((v1h<<13)|(v1l>>>19))>>>0;v1l=tl;tl=((v3l<<16)|(v3h>>>16))>>>0;v3h=((v3h<<16)|(v3l>>>16))>>>0;v3l=tl;v1l=(v1l^v0l)>>>0;v1h=(v1h^v0h)>>>0;v3l=(v3l^v2l)>>>0;v3h=(v3h^v2h)>>>0;tl=v0l;v0l=v0h;v0h=tl;tl=(v2l+v1l)>>>0;ci=tl<v2l?1:0;v2l=tl;v2h=(v2h+v1h+ci)>>>0;tl=(v0l+v3l)>>>0;ci=tl<v0l?1:0;v0l=tl;v0h=(v0h+v3h+ci)>>>0;tl=((v1l<<17)|(v1h>>>15))>>>0;v1h=((v1h<<17)|(v1l>>>15))>>>0;v1l=tl;tl=((v3l<<21)|(v3h>>>11))>>>0;v3h=((v3h<<21)|(v3l>>>11))>>>0;v3l=tl;v1l=(v1l^v2l)>>>0;v1h=(v1h^v2h)>>>0;v3l=(v3l^v0l)>>>0;v3h=(v3h^v0h)>>>0;tl=v2l;v2l=v2h;v2h=tl;
      tl=(v0l+v1l)>>>0;ci=tl<v0l?1:0;v0l=tl;v0h=(v0h+v1h+ci)>>>0;tl=(v2l+v3l)>>>0;ci=tl<v2l?1:0;v2l=tl;v2h=(v2h+v3h+ci)>>>0;tl=((v1l<<13)|(v1h>>>19))>>>0;v1h=((v1h<<13)|(v1l>>>19))>>>0;v1l=tl;tl=((v3l<<16)|(v3h>>>16))>>>0;v3h=((v3h<<16)|(v3l>>>16))>>>0;v3l=tl;v1l=(v1l^v0l)>>>0;v1h=(v1h^v0h)>>>0;v3l=(v3l^v2l)>>>0;v3h=(v3h^v2h)>>>0;tl=v0l;v0l=v0h;v0h=tl;tl=(v2l+v1l)>>>0;ci=tl<v2l?1:0;v2l=tl;v2h=(v2h+v1h+ci)>>>0;tl=(v0l+v3l)>>>0;ci=tl<v0l?1:0;v0l=tl;v0h=(v0h+v3h+ci)>>>0;tl=((v1l<<17)|(v1h>>>15))>>>0;v1h=((v1h<<17)|(v1l>>>15))>>>0;v1l=tl;tl=((v3l<<21)|(v3h>>>11))>>>0;v3h=((v3h<<21)|(v3l>>>11))>>>0;v3l=tl;v1l=(v1l^v2l)>>>0;v1h=(v1h^v2h)>>>0;v3l=(v3l^v0l)>>>0;v3h=(v3h^v0h)>>>0;tl=v2l;v2l=v2h;v2h=tl;
      v0l=(v0l^wl)>>>0;v0h=(v0h^wh)>>>0;
    }
    v2l^=255;
    tl=(v0l+v1l)>>>0;ci=tl<v0l?1:0;v0l=tl;v0h=(v0h+v1h+ci)>>>0;tl=(v2l+v3l)>>>0;ci=tl<v2l?1:0;v2l=tl;v2h=(v2h+v3h+ci)>>>0;tl=((v1l<<13)|(v1h>>>19))>>>0;v1h=((v1h<<13)|(v1l>>>19))>>>0;v1l=tl;tl=((v3l<<16)|(v3h>>>16))>>>0;v3h=((v3h<<16)|(v3l>>>16))>>>0;v3l=tl;v1l=(v1l^v0l)>>>0;v1h=(v1h^v0h)>>>0;v3l=(v3l^v2l)>>>0;v3h=(v3h^v2h)>>>0;tl=v0l;v0l=v0h;v0h=tl;tl=(v2l+v1l)>>>0;ci=tl<v2l?1:0;v2l=tl;v2h=(v2h+v1h+ci)>>>0;tl=(v0l+v3l)>>>0;ci=tl<v0l?1:0;v0l=tl;v0h=(v0h+v3h+ci)>>>0;tl=((v1l<<17)|(v1h>>>15))>>>0;v1h=((v1h<<17)|(v1l>>>15))>>>0;v1l=tl;tl=((v3l<<21)|(v3h>>>11))>>>0;v3h=((v3h<<21)|(v3l>>>11))>>>0;v3l=tl;v1l=(v1l^v2l)>>>0;v1h=(v1h^v2h)>>>0;v3l=(v3l^v0l)>>>0;v3h=(v3h^v0h)>>>0;tl=v2l;v2l=v2h;v2h=tl;
    tl=(v0l+v1l)>>>0;ci=tl<v0l?1:0;v0l=tl;v0h=(v0h+v1h+ci)>>>0;tl=(v2l+v3l)>>>0;ci=tl<v2l?1:0;v2l=tl;v2h=(v2h+v3h+ci)>>>0;tl=((v1l<<13)|(v1h>>>19))>>>0;v1h=((v1h<<13)|(v1l>>>19))>>>0;v1l=tl;tl=((v3l<<16)|(v3h>>>16))>>>0;v3h=((v3h<<16)|(v3l>>>16))>>>0;v3l=tl;v1l=(v1l^v0l)>>>0;v1h=(v1h^v0h)>>>0;v3l=(v3l^v2l)>>>0;v3h=(v3h^v2h)>>>0;tl=v0l;v0l=v0h;v0h=tl;tl=(v2l+v1l)>>>0;ci=tl<v2l?1:0;v2l=tl;v2h=(v2h+v1h+ci)>>>0;tl=(v0l+v3l)>>>0;ci=tl<v0l?1:0;v0l=tl;v0h=(v0h+v3h+ci)>>>0;tl=((v1l<<17)|(v1h>>>15))>>>0;v1h=((v1h<<17)|(v1l>>>15))>>>0;v1l=tl;tl=((v3l<<21)|(v3h>>>11))>>>0;v3h=((v3h<<21)|(v3l>>>11))>>>0;v3l=tl;v1l=(v1l^v2l)>>>0;v1h=(v1h^v2h)>>>0;v3l=(v3l^v0l)>>>0;v3h=(v3h^v0h)>>>0;tl=v2l;v2l=v2h;v2h=tl;
    tl=(v0l+v1l)>>>0;ci=tl<v0l?1:0;v0l=tl;v0h=(v0h+v1h+ci)>>>0;tl=(v2l+v3l)>>>0;ci=tl<v2l?1:0;v2l=tl;v2h=(v2h+v3h+ci)>>>0;tl=((v1l<<13)|(v1h>>>19))>>>0;v1h=((v1h<<13)|(v1l>>>19))>>>0;v1l=tl;tl=((v3l<<16)|(v3h>>>16))>>>0;v3h=((v3h<<16)|(v3l>>>16))>>>0;v3l=tl;v1l=(v1l^v0l)>>>0;v1h=(v1h^v0h)>>>0;v3l=(v3l^v2l)>>>0;v3h=(v3h^v2h)>>>0;tl=v0l;v0l=v0h;v0h=tl;tl=(v2l+v1l)>>>0;ci=tl<v2l?1:0;v2l=tl;v2h=(v2h+v1h+ci)>>>0;tl=(v0l+v3l)>>>0;ci=tl<v0l?1:0;v0l=tl;v0h=(v0h+v3h+ci)>>>0;tl=((v1l<<17)|(v1h>>>15))>>>0;v1h=((v1h<<17)|(v1l>>>15))>>>0;v1l=tl;tl=((v3l<<21)|(v3h>>>11))>>>0;v3h=((v3h<<21)|(v3l>>>11))>>>0;v3l=tl;v1l=(v1l^v2l)>>>0;v1h=(v1h^v2h)>>>0;v3l=(v3l^v0l)>>>0;v3h=(v3h^v0h)>>>0;tl=v2l;v2l=v2h;v2h=tl;
    tl=(v0l+v1l)>>>0;ci=tl<v0l?1:0;v0l=tl;v0h=(v0h+v1h+ci)>>>0;tl=(v2l+v3l)>>>0;ci=tl<v2l?1:0;v2l=tl;v2h=(v2h+v3h+ci)>>>0;tl=((v1l<<13)|(v1h>>>19))>>>0;v1h=((v1h<<13)|(v1l>>>19))>>>0;v1l=tl;tl=((v3l<<16)|(v3h>>>16))>>>0;v3h=((v3h<<16)|(v3l>>>16))>>>0;v3l=tl;v1l=(v1l^v0l)>>>0;v1h=(v1h^v0h)>>>0;v3l=(v3l^v2l)>>>0;v3h=(v3h^v2h)>>>0;tl=v0l;v0l=v0h;v0h=tl;tl=(v2l+v1l)>>>0;ci=tl<v2l?1:0;v2l=tl;v2h=(v2h+v1h+ci)>>>0;tl=(v0l+v3l)>>>0;ci=tl<v0l?1:0;v0l=tl;v0h=(v0h+v3h+ci)>>>0;tl=((v1l<<17)|(v1h>>>15))>>>0;v1h=((v1h<<17)|(v1l>>>15))>>>0;v1l=tl;tl=((v3l<<21)|(v3h>>>11))>>>0;v3h=((v3h<<21)|(v3l>>>11))>>>0;v3l=tl;v1l=(v1l^v2l)>>>0;v1h=(v1h^v2h)>>>0;v3l=(v3l^v0l)>>>0;v3h=(v3h^v0h)>>>0;tl=v2l;v2l=v2h;v2h=tl;
    var fl=(v0l^v1l^v2l^v3l)>>>0,fh=(v0h^v1h^v2h^v3h)>>>0;
    var hs='';hs+=('0'+(fl&255).toString(16)).slice(-2);hs+=('0'+((fl>>8)&255).toString(16)).slice(-2);hs+=('0'+((fl>>16)&255).toString(16)).slice(-2);hs+=('0'+(fl>>>24).toString(16)).slice(-2);hs+=('0'+(fh&255).toString(16)).slice(-2);hs+=('0'+((fh>>8)&255).toString(16)).slice(-2);hs+=('0'+((fh>>16)&255).toString(16)).slice(-2);hs+=('0'+(fh>>>24).toString(16)).slice(-2);
    return hs;
  };
})();

async function handler(event) {
  var request = event.request;
  var cookieName = "${cookieName}";
  var maxAge = ${cookieMaxAge};
  var domain = "${hostedZone.zoneName}";

  // Read signing key from KVS
  var hmacKeyHex;
  try {
    hmacKeyHex = await _store.get('hmac-key');
  } catch(e) {
    return {
      statusCode: 503,
      statusDescription: 'Service Unavailable',
      headers: { 'cache-control': { value: 'no-store' } },
      body: ''
    };
  }

  // Read or generate visitor ID
  var cookies = request.cookies || {};
  var existingId = cookies[cookieName] ? cookies[cookieName].value : null;
  var visitorId = existingId;
  if (!visitorId) {
    var chars = 'abcdef0123456789';
    visitorId = '';
    for (var i = 0; i < 32; i++) {
      if (i===8||i===12||i===16||i===20) visitorId+='-';
      visitorId += chars.charAt(Math.floor(Math.random()*chars.length));
    }
  }

  var h = request.headers;
  var clientAddr = (h['cloudfront-viewer-address']||{}).value||'';
  var clientIp = clientAddr.replace(/:\\d+$/,'');

  var payload = {
    id: visitorId,
    new: !existingId,
    ip: clientIp||null,
    asn: (h['cloudfront-viewer-asn']||{}).value||null,
    country: (h['cloudfront-viewer-country']||{}).value||null,
    city: (h['cloudfront-viewer-city']||{}).value||null,
    lat: (h['cloudfront-viewer-latitude']||{}).value||null,
    lon: (h['cloudfront-viewer-longitude']||{}).value||null,
    tz: (h['cloudfront-viewer-time-zone']||{}).value||null,
    ts: Math.floor(Date.now()/1000)
  };

  var b64 = btoa(JSON.stringify(payload));
  // Sign only critical fields — geo/tz are advisory, not security-sensitive.
  // API verifies: SipHash-2-4(key[0:16], id|ip|asn|ts) + ts freshness (90s) + ip match.
  var canonical = (payload.id||'') + '|' + (payload.ip||'') + '|' + (payload.asn||'') + '|' + payload.ts;
  var sig = _sip(hmacKeyHex, canonical);
  var token = b64 + '.' + sig;

  var cookieAttrs = 'Max-Age='+maxAge+'; Path=/; Domain=.'+domain+'; Secure; SameSite=None';
  var origin = (h['origin']||{}).value||'*';

  return {
    statusCode: 200,
    statusDescription: 'OK',
    headers: {
      'content-type':                    { value: 'text/plain' },
      'cache-control':                   { value: 'no-store, no-cache, must-revalidate' },
      'access-control-allow-origin':     { value: origin },
      'access-control-allow-credentials':{ value: 'true' },
      'access-control-allow-methods':    { value: 'GET, OPTIONS' }
    },
    cookies: {
      [cookieName]: { value: visitorId, attributes: cookieAttrs }
    },
    body: token
  };
}
`),
    });

    // S3 origin bucket - used for favicon cache files only
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
          ...Array.from({ length: faviconBits }, (_, i) =>
            s3deploy.Source.data(
              `${faviconS3Prefix}/${i}.ico`,
              Buffer.from(FAVICON_ICO_BASE64, "base64").toString("binary")
            )
          ),
        ],
        destinationBucket: originBucket,
        prune: false,
        cacheControl: [
          s3deploy.CacheControl.maxAge(cdk.Duration.days(365)),
          s3deploy.CacheControl.setPublic(),
        ],
        contentType: "image/x-icon",
      });
    }

    // Cache policy - no caching for the cookie endpoint
    const cachePolicy = new cloudfront.CachePolicy(this, "CachePolicy", {
      cachePolicyName: `${stackName}-cookie-${id}`,
      comment: "Third-party cookie - no cache",
      defaultTtl: cdk.Duration.seconds(0),
      maxTtl: cdk.Duration.seconds(1),
      minTtl: cdk.Duration.seconds(0),
      cookieBehavior: cloudfront.CacheCookieBehavior.none(),
    });

    // Origin request policy — only geo/network headers needed for the token payload
    const originRequestPolicy = new cloudfront.OriginRequestPolicy(
      this,
      "OriginRequestPolicy",
      {
        originRequestPolicyName: `${stackName}-cookie-headers-${id}`,
        comment: "Geo and network headers for signed token payload",
        headerBehavior: cloudfront.OriginRequestHeaderBehavior.allowList(
          "CloudFront-Viewer-Address",
          "CloudFront-Viewer-ASN",
          "CloudFront-Viewer-Country",
          "CloudFront-Viewer-City",
          "CloudFront-Viewer-Latitude",
          "CloudFront-Viewer-Longitude",
          "CloudFront-Viewer-Time-Zone"
        ),
        cookieBehavior: cloudfront.OriginRequestCookieBehavior.all(),
      }
    );

    // Favicon cache policy - immutable, long-term caching
    const faviconCachePolicy = faviconEnabled
      ? new cloudfront.CachePolicy(this, "FaviconCachePolicy", {
          cachePolicyName: `${stackName}-favicon-${id}`,
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
          responseHeadersPolicyName: `${stackName}-favicon-headers-${id}`,
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

    // Additional behaviors for favicon route
    const additionalBehaviors: Record<string, cloudfront.BehaviorOptions> = {};

    if (faviconEnabled && faviconCachePolicy && faviconResponseHeadersPolicy) {
      additionalBehaviors[`${faviconPath}/*`] = {
        origin: origins.S3BucketOrigin.withOriginAccessControl(originBucket),
        viewerProtocolPolicy: cloudfront.ViewerProtocolPolicy.HTTPS_ONLY,
        allowedMethods: cloudfront.AllowedMethods.ALLOW_GET_HEAD_OPTIONS,
        cachedMethods: cloudfront.CachedMethods.CACHE_GET_HEAD_OPTIONS,
        cachePolicy: faviconCachePolicy,
        responseHeadersPolicy: faviconResponseHeadersPolicy,
        compress: false,
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
      description: "Third-party cookie / signed token endpoint",
    });

    new cdk.CfnOutput(this, "CookieName", {
      value: cookieName,
      description: "Cookie name (_fpid)",
    });

    new cdk.CfnOutput(this, "HmacKvsArn", {
      value: this.hmacKvs.keyValueStoreArn,
      description:
        "KVS ARN — populate with: aws cloudfront-keyvaluestore put-key --kvs-arn <arn> --key hmac-key --value <32-byte-hex> --if-match <etag>",
    });

    if (this.faviconEndpoint) {
      new cdk.CfnOutput(this, "FaviconEndpoint", {
        value: this.faviconEndpoint,
        description: "Favicon cache endpoint",
      });

      new cdk.CfnOutput(this, "FaviconBits", {
        value: String(faviconBits),
        description: "Number of favicon bits",
      });
    }

    cdk.Tags.of(this).add("Component", "TlsFingerprintEdge");
  }
}
