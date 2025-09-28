#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <image-tag> [namespace]" >&2
  echo "Example: $0 ghcr.io/meetinity/api-gateway:2024.05.01 staging" >&2
  exit 1
fi

IMAGE_REFERENCE="$1"
NAMESPACE="${2:-${KUBE_NAMESPACE:-default}}"
APP_NAME="${APP_NAME:-meetinity-api-gateway}"
DEPLOYMENT_NAME="${DEPLOYMENT_NAME:-${APP_NAME}-blue}"
CONFIGMAP_MANIFEST="${CONFIGMAP_MANIFEST:-deploy/k8s/configmap.yaml}"

kubectl apply -n "$NAMESPACE" -f "$CONFIGMAP_MANIFEST"

kubectl set image deployment/${DEPLOYMENT_NAME} api-gateway="$IMAGE_REFERENCE" -n "$NAMESPACE" --record
kubectl annotate deployment/${DEPLOYMENT_NAME} rollout.meetinity.io/updated-at="$(date -u +%Y-%m-%dT%H:%M:%SZ)" -n "$NAMESPACE" --overwrite

kubectl rollout status deployment/${DEPLOYMENT_NAME} -n "$NAMESPACE"

echo "Rolling deployment of ${DEPLOYMENT_NAME} to image ${IMAGE_REFERENCE} completed."
