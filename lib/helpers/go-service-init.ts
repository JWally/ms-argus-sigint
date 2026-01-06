import { readFileSync } from "fs";
import { join } from "path";

export interface GoServiceConfig {
  /** Path to the Go source file, relative to project root */
  sourcePath: string;
  /** Name of the systemd service */
  serviceName: string;
  /** Directory where the binary will be installed */
  installDir: string;
  /** Environment variables for the systemd service */
  environment: Record<string, string>;
  /** Directory for certificates (if using autocert) */
  certDir?: string;
  /** Linux capabilities (e.g., CAP_NET_BIND_SERVICE) */
  capabilities?: string[];
}

/**
 * Generates user data scripts for Go-based EC2 services.
 *
 * Handles:
 * - Installing Go on Amazon Linux 2023
 * - Writing source code from external file
 * - Building the binary
 * - Creating and starting systemd service
 */
export class GoServiceInit {
  public static generate(config: GoServiceConfig): string {
    const goSource = readFileSync(join(process.cwd(), config.sourcePath), "utf-8");
    const goSourceBase64 = Buffer.from(goSource).toString("base64");

    const envLines = Object.entries(config.environment)
      .map(([key, value]) => `Environment=${key}=${value}`)
      .join("\n");

    const capabilitiesLine = config.capabilities?.length
      ? `AmbientCapabilities=${config.capabilities.join(" ")}`
      : "";

    const certDirSetup = config.certDir ? `mkdir -p ${config.certDir}` : "";

    return `#!/bin/bash
set -euo pipefail
exec > >(tee /var/log/user-data.log) 2>&1

echo "=== Installing Go ==="
dnf install -y golang

export HOME=/root
export GOPATH=/root/go
export GOMODCACHE=/root/go/pkg/mod
mkdir -p $GOPATH $GOMODCACHE

echo "=== Creating ${config.serviceName} service ==="
mkdir -p ${config.installDir}
${certDirSetup}
cd ${config.installDir}

echo "${goSourceBase64}" | base64 -d > main.go

echo "=== Downloading dependencies ==="
go mod init ${config.serviceName}
go mod tidy

echo "=== Building ==="
go build -o server main.go

echo "=== Creating systemd service ==="
cat > /etc/systemd/system/${config.serviceName}.service << 'SVCEOF'
[Unit]
Description=${config.serviceName}
After=network.target

[Service]
Type=simple
ExecStart=${config.installDir}/server
Restart=always
RestartSec=5
User=root
${capabilitiesLine}
${envLines}

[Install]
WantedBy=multi-user.target
SVCEOF

systemctl daemon-reload
systemctl enable ${config.serviceName}
systemctl start ${config.serviceName}

echo "=== ${config.serviceName} Started ==="
`;
  }
}
