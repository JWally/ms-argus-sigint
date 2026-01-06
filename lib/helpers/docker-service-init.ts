export interface DockerServiceConfig {
  /** Name of the systemd service */
  serviceName: string;
  /** ECR repository URI (e.g., 123456789.dkr.ecr.us-west-2.amazonaws.com/repo) */
  ecrRepositoryUri: string;
  /** Image tag. Default: "latest" */
  imageTag?: string;
  /** Environment variables for the container */
  environment: Record<string, string>;
  /** AWS region for ECR login */
  awsRegion: string;
  /** Use host networking. Default: true (required for TCP fingerprinting) */
  hostNetwork?: boolean;
  /** Linux capabilities to add */
  capabilities?: string[];
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
    } = config;

    // Build docker run flags
    const envFlags = Object.entries(environment)
      .map(([key, value]) => `-e ${key}="${value}"`)
      .join(" ");

    const capFlags = capabilities.map((cap) => `--cap-add=${cap}`).join(" ");
    const networkFlag = hostNetwork ? "--network=host" : "";
    const fullImage = `${ecrRepositoryUri}:${imageTag}`;

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
`;
  }
}
