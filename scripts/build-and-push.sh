#!/bin/bash
set -euo pipefail

# Configuration
AWS_REGION="${AWS_REGION:-us-west-2}"
AWS_ACCOUNT="${AWS_ACCOUNT:-$(aws sts get-caller-identity --query Account --output text)}"
STACK_NAME="${STACK_NAME:-probe-dev}"
IMAGE_TAG="${IMAGE_TAG:-latest}"

ECR_BASE="${AWS_ACCOUNT}.dkr.ecr.${AWS_REGION}.amazonaws.com"
TCP_PROBE_REPO="${ECR_BASE}/${STACK_NAME}/tcp-probe"
STUN_REPO="${ECR_BASE}/${STACK_NAME}/stun"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Get git short SHA for tagging
GIT_SHA=$(git -C "$PROJECT_ROOT" rev-parse --short HEAD 2>/dev/null || echo "unknown")

echo "=== Configuration ==="
echo "AWS Account: $AWS_ACCOUNT"
echo "AWS Region:  $AWS_REGION"
echo "Stack Name:  $STACK_NAME"
echo "Image Tag:   $IMAGE_TAG"
echo "Git SHA:     $GIT_SHA"
echo ""

echo "=== Authenticating to ECR ==="
aws ecr get-login-password --region "$AWS_REGION" | \
    docker login --username AWS --password-stdin "$ECR_BASE"

# Create/use a buildx builder that supports multi-platform
echo ""
echo "=== Setting up buildx builder ==="
docker buildx create --name arm-builder --use 2>/dev/null || docker buildx use arm-builder 2>/dev/null || true

echo ""
echo "=== Building and pushing tcp-probe (ARM64) ==="
docker buildx build \
    --platform linux/arm64 \
    --push \
    -t "${TCP_PROBE_REPO}:${IMAGE_TAG}" \
    -t "${TCP_PROBE_REPO}:${GIT_SHA}" \
    "${PROJECT_ROOT}/src-go/tcp-probe"

echo ""
echo "=== Building and pushing stun (ARM64) ==="
docker buildx build \
    --platform linux/arm64 \
    --push \
    -t "${STUN_REPO}:${IMAGE_TAG}" \
    -t "${STUN_REPO}:${GIT_SHA}" \
    "${PROJECT_ROOT}/src-go/stun"

echo ""
echo "=== Done ==="
echo "TCP Probe: ${TCP_PROBE_REPO}:${IMAGE_TAG}"
echo "STUN:      ${STUN_REPO}:${IMAGE_TAG}"
