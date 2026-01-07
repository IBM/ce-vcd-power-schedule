#!/usr/bin/env bash
set -euo pipefail

PROJECT_NAME="ce-vcd-power-schedule"
JOB_POWER_ON_NAME="ce-vcd-poweron-schedule--job"
IBM_APIKEY=${IBM_APIKEY:-}
IBM_REGION=${IBM_REGION:-eu-de}
REGISTRY_IMAGE="icr.io/$PROJECT_NAME/$PROJECT_NAME:latest"
RESOURCE_GROUP=${RESOURCE_GROUP:-}

if [[ -z "$RESOURCE_GROUP" ]]; then echo "ERROR: RESOURCE_GROUP is required."; exit 1; fi


ibmcloud login --apikey "$IBM_APIKEY" -r "$IBM_REGION" -g "$RESOURCE_GROUP" >/dev/null 2>&1

ibmcloud ce project select --name "$PROJECT_NAME" >/dev/null 2>&1

REGISTRY_IMAGE=$(ibmcloud ce job get --name "$JOB_POWER_ON_NAME" -o json | jq -r '.buildRun.output_image')

if [[ -z "$REGISTRY_IMAGE" ]]; then echo "ERROR: REGISTRY_IMAGE not found."; exit 1; fi

# Extract domain and namespace, excluding 'private.'
domain=$(echo "$REGISTRY_IMAGE" | cut -d / -f1 | sed 's/^private\.//')
ns=$(echo "$REGISTRY_IMAGE" | cut -d / -f2)


echo "[+] Deleting images from registry: $domain, namespace: $ns"
ibmcloud cr region-set $domain
if ibmcloud cr namespace-list | grep $ns >/dev/null 2>&1; then
   ibmcloud cr namespace-rm -f $ns
fi

ibmcloud ce project delete -f --hard --wait --name "$PROJECT_NAME"
