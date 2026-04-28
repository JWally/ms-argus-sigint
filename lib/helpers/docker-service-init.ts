export interface DockerServiceConfig {
  /** Name of the systemd service */
  serviceName: string;
  /** ECR repository URI (e.g., 123456789.dkr.ecr.us-west-2.amazonaws.com/repo) */
  ecrRepositoryUri: string;
  /** Image tag. Default: "latest" */
  imageTag?: string;
  /** Environment variables for the container (static values baked into user data) */
  environment: Record<string, string>;
  /** AWS region for ECR login */
  awsRegion: string;
  /** Use host networking. Default: true (required for TCP fingerprinting) */
  hostNetwork?: boolean;
  /** Linux capabilities to add */
  capabilities?: string[];
  /**
   * Secrets to fetch from AWS Secrets Manager at instance boot time.
   * The secret value is fetched via AWS CLI and passed to the container as an
   * environment variable. The secret ARN (not the value) appears in the CF template.
   */
  runtimeSecrets?: { envVar: string; secretArn: string }[];
}

/**
 * Generates user data scripts for Docker-based EC2 services.
 *
 * Handles:
 * - Installing Docker on Amazon Linux 2023
 * - Authenticating to ECR
 * - Pulling and running the container
 * - Creating systemd service for container management
 */
export class DockerServiceInit {
  public static generate(config: DockerServiceConfig): string {
    const {
      serviceName,
      ecrRepositoryUri,
      imageTag = "latest",
      environment,
      awsRegion,
      hostNetwork = true,
      capabilities = [],
      runtimeSecrets = [],
    } = config;

    // Build docker run flags for static env vars
    const staticEnvFlags = Object.entries(environment)
      .map(([key, value]) => `-e ${key}="${value}"`)
      .join(" ");

    // Runtime secrets are fetched at boot; reference as shell variables
    const secretEnvFlags = runtimeSecrets
      .map(({ envVar }) => `-e ${envVar}="$${envVar}"`)
      .join(" ");

    const envFlags = [staticEnvFlags, secretEnvFlags].filter(Boolean).join(" ");

    const capFlags = capabilities.map((cap) => `--cap-add=${cap}`).join(" ");
    const networkFlag = hostNetwork ? "--network=host" : "";
    const fullImage = `${ecrRepositoryUri}:${imageTag}`;

    // Fetch secrets from Secrets Manager at boot (before Docker starts)
    const secretFetchCommands =
      runtimeSecrets.length > 0
        ? `\necho "=== Fetching runtime secrets ==="\n` +
          runtimeSecrets
            .map(
              ({ envVar, secretArn }) =>
                `${envVar}=$(aws secretsmanager get-secret-value --secret-id "${secretArn}" --query SecretString --output text --region ${awsRegion})\n` +
                `echo "${envVar} fetched successfully"`
            )
            .join("\n") +
          "\n"
        : "";

    // Note: No shebang - userData.addCommands() adds one automatically
    // Use heredoc for systemd file to let CloudFormation resolve tokens
    return `set -euo pipefail
exec > >(tee /var/log/user-data.log) 2>&1

echo "=== Installing Docker ==="
dnf install -y docker
systemctl enable docker
systemctl start docker

# Extract ECR registry from the full image URI
FULL_IMAGE="${fullImage}"
ECR_REGISTRY=$(echo "$FULL_IMAGE" | cut -d'/' -f1)

echo "=== Authenticating to ECR ==="
aws ecr get-login-password --region ${awsRegion} | docker login --username AWS --password-stdin $ECR_REGISTRY

echo "=== Pulling image $FULL_IMAGE ==="
docker pull $FULL_IMAGE
${secretFetchCommands}
echo "=== Creating systemd service for ${serviceName} ==="
cat > /etc/systemd/system/${serviceName}.service << 'SERVICEEOF'
[Unit]
Description=${serviceName} Docker container
After=docker.service
Requires=docker.service

[Service]
Type=simple
Restart=always
RestartSec=5
SERVICEEOF

# Append the ExecStart line with resolved variables
cat >> /etc/systemd/system/${serviceName}.service << EOF
ExecStartPre=-/usr/bin/docker stop ${serviceName}
ExecStartPre=-/usr/bin/docker rm ${serviceName}
ExecStart=/usr/bin/docker run --rm --name ${serviceName} ${networkFlag} ${capFlags} ${envFlags} $FULL_IMAGE
ExecStop=/usr/bin/docker stop ${serviceName}

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable ${serviceName}
systemctl start ${serviceName}

echo "=== ${serviceName} Started ==="

echo "=== Installing probe watchdog ==="
cat > /usr/local/bin/probe-watchdog.sh << 'WATCHEOF'
#!/bin/bash
# Watchdog: probe localhost:8080/health every minute. After 3 consecutive
# failures, mark this instance Unhealthy in its ASG so it gets replaced.
# The Go service's /health endpoint self-probes :443 (the actual TLS listener)
# so a 503 here means the TLS service is dead even though the HTTP health
# server is up.
set -euo pipefail
FAIL_FILE=/var/lib/probe-watchdog.fails
[[ -f "$FAIL_FILE" ]] || echo "0" > "$FAIL_FILE"
fails=$(cat "$FAIL_FILE")
if curl -fsS -m 3 http://127.0.0.1:8080/health > /dev/null 2>&1; then
  echo "0" > "$FAIL_FILE"
  exit 0
fi
fails=$((fails + 1))
echo "$fails" > "$FAIL_FILE"
echo "$(date -u +%FT%TZ) probe-watchdog: health check failed (consecutive=$fails)"
if [[ "$fails" -ge 3 ]]; then
  TOKEN=$(curl -fsS -m 2 -X PUT "http://169.254.169.254/latest/api/token" \
    -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
  iid=$(curl -fsS -m 2 -H "X-aws-ec2-metadata-token: $TOKEN" \
    http://169.254.169.254/latest/meta-data/instance-id)
  region=$(curl -fsS -m 2 -H "X-aws-ec2-metadata-token: $TOKEN" \
    http://169.254.169.254/latest/meta-data/placement/region)
  echo "$(date -u +%FT%TZ) probe-watchdog: marking $iid Unhealthy"
  aws autoscaling set-instance-health \
    --instance-id "$iid" \
    --health-status Unhealthy \
    --region "$region" || true
  echo "0" > "$FAIL_FILE"
fi
WATCHEOF
chmod +x /usr/local/bin/probe-watchdog.sh

cat > /etc/systemd/system/probe-watchdog.service << 'WSEOF'
[Unit]
Description=Probe service watchdog (verifies TLS :443 via self-probing /health)
After=docker.service ${serviceName}.service

[Service]
Type=oneshot
ExecStart=/usr/local/bin/probe-watchdog.sh
WSEOF

cat > /etc/systemd/system/probe-watchdog.timer << 'WTEOF'
[Unit]
Description=Run probe watchdog every 60 seconds

[Timer]
OnBootSec=180
OnUnitActiveSec=60
Unit=probe-watchdog.service

[Install]
WantedBy=timers.target
WTEOF

systemctl daemon-reload
systemctl enable probe-watchdog.timer
systemctl start probe-watchdog.timer

echo "=== Watchdog enabled (3 failures over 3 min → ASG replace) ==="
`;
  }
}
