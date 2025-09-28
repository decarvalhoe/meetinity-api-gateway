#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <image-tag> [namespace]" >&2
  echo "Example: $0 ghcr.io/meetinity/api-gateway:2024.05.01 production" >&2
  exit 1
fi

IMAGE_REFERENCE="$1"
NAMESPACE="${2:-${KUBE_NAMESPACE:-default}}"
APP_NAME="${APP_NAME:-meetinity-api-gateway}"
SERVICE_NAME="${SERVICE_NAME:-${APP_NAME}}"
HPA_NAME="${HPA_NAME:-${APP_NAME}}"
DEPLOYMENT_TEMPLATE="${DEPLOYMENT_TEMPLATE:-deploy/k8s/deployment.yaml}"
CONFIGMAP_MANIFEST="${CONFIGMAP_MANIFEST:-deploy/k8s/configmap.yaml}"

kubectl apply -n "$NAMESPACE" -f "$CONFIGMAP_MANIFEST"

ACTIVE_COLOR=$(kubectl get svc "$SERVICE_NAME" -n "$NAMESPACE" -o jsonpath='{.metadata.annotations.gateway\.meetinity\.io/active-color}' 2>/dev/null || echo "blue")
if [[ "$ACTIVE_COLOR" == "blue" ]]; then
  NEW_COLOR="green"
else
  NEW_COLOR="blue"
fi

TMP_MANIFEST=$(mktemp)
trap 'rm -f "$TMP_MANIFEST"' EXIT

sed \
  -e "s/meetinity-api-gateway-blue/${APP_NAME}-${NEW_COLOR}/g" \
  -e "s/color: blue/color: ${NEW_COLOR}/g" \
  -e "s#ghcr.io/meetinity/api-gateway:latest#${IMAGE_REFERENCE}#g" \
  "$DEPLOYMENT_TEMPLATE" > "$TMP_MANIFEST"

kubectl apply -n "$NAMESPACE" -f "$TMP_MANIFEST"

kubectl rollout status deployment/${APP_NAME}-${NEW_COLOR} -n "$NAMESPACE"

kubectl patch svc "$SERVICE_NAME" -n "$NAMESPACE" \
  --type merge \
  -p "{\"metadata\":{\"annotations\":{\"gateway.meetinity.io/active-color\":\"${NEW_COLOR}\"}},\"spec\":{\"selector\":{\"app\":\"${APP_NAME}\",\"color\":\"${NEW_COLOR}\"}}}"

if kubectl get hpa "$HPA_NAME" -n "$NAMESPACE" >/dev/null 2>&1; then
  kubectl patch hpa "$HPA_NAME" -n "$NAMESPACE" --type merge -p "{\"spec\":{\"scaleTargetRef\":{\"name\":\"${APP_NAME}-${NEW_COLOR}\"}}}"
fi

if kubectl get deployment/${APP_NAME}-${ACTIVE_COLOR} -n "$NAMESPACE" >/dev/null 2>&1; then
  kubectl scale deployment/${APP_NAME}-${ACTIVE_COLOR} --replicas=0 -n "$NAMESPACE"
fi

echo "Blue/green deployment complete. Active color is ${NEW_COLOR}."
