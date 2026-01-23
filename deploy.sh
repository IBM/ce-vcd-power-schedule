#!/usr/bin/env bash
# This script deploys a Power Schedule application to IBM Cloud Code Engine.
# It handles setting up necessary resources, secrets, config maps,
# builds, and jobs for powering on and off virtual machines in a specified
# Virtual Data Center (VDC) based on a provided schedule.
set -euo pipefail

PROJECT_NAME="ce-vcd-power-schedule"
RESOURCE_GROUP=${RESOURCE_GROUP:-} # Resource group where resources will be created
JOB_POWER_ON_NAME="ce-vcd-poweron-schedule--job" # Name for the power-on job
JOB_POWER_OFF_NAME="ce-vcd-poweroff-schedule--job"  # Name for the power-off job
CONFIGMAP_FILE_NAME="entities-and-exclusions--cm"  # Name for the config map containing the schedule template
CONFIGMAP_NAME="config--cm" # Name for the main config map
SECRET_NAME="crendentials" # Name for the secret containing IBM API key
IBM_APIKEY=${IBM_APIKEY:-}  # IBM API key for authentication
IBM_REGION=${IBM_REGION:-eu-de} # IBM Cloud region
DIRECTOR_SITE_NAME=${DIRECTOR_SITE_NAME:-IBM VCFaaS Multitenant - FRA} # Name of the Director site
VIRTUAL_DATA_CENTER=${VIRTUAL_DATA_CENTER:-} # Name of the Virtual Data Center
TASK_TIMEOUT_SECONDS=${TASK_TIMEOUT_SECONDS:-900} # Timeout for tasks in seconds

# Check for required environment variables
if [[ -z "$IBM_APIKEY" ]]; then echo "ERROR: IBM_APIKEY is required."; exit 1; fi
if [[ -z "$IBM_REGION" ]]; then echo "ERROR: IBM_REGION is required."; exit 1; fi
if [[ -z "$RESOURCE_GROUP" ]]; then echo "ERROR: RESOURCE_GROUP is required."; exit 1; fi
if [[ -z "$DIRECTOR_SITE_NAME" ]]; then echo "ERROR: DIRECTOR_SITE_NAME is required."; exit 1; fi
if [[ -z "$VIRTUAL_DATA_CENTER" ]]; then echo "ERROR: VIRTUAL_DATA_CENTER is required."; exit 1; fi

# Check for schedule_template.yaml file
if [[ ! -f "schedule_template.yaml" ]]; then echo "ERROR: schedule_template.yaml not found."; exit 1; fi

# Login to IBM Cloud using the provided API key
ibmcloud login --apikey "$IBM_APIKEY" -r "$IBM_REGION"

# Ensure the resource group exists
if ! ibmcloud resource group "$RESOURCE_GROUP" >/dev/null 2>&1; then
  ibmcloud resource group-create "$RESOURCE_GROUP"
fi

# Set the resource group context
ibmcloud target -g "$RESOURCE_GROUP"

# Ensure the project exists, create if not
if ibmcloud ce project get --name "$PROJECT_NAME" >/dev/null 2>&1; then
  ibmcloud ce project select --name "$PROJECT_NAME"
else
  ibmcloud ce project create --name "$PROJECT_NAME"
  ibmcloud ce project select --name "$PROJECT_NAME"
fi

echo "[+] Project: $PROJECT_NAME selected"

# Update or create the secret containing IBM API key
if ibmcloud ce secret get --name "$SECRET_NAME" >/dev/null 2>&1; then
  ibmcloud ce secret update --name "$SECRET_NAME" --from-literal IBM_APIKEY="$IBM_APIKEY"
else
  ibmcloud ce secret create --name "$SECRET_NAME" --from-literal IBM_APIKEY="$IBM_APIKEY"
fi

echo "[+] Secret ready: $SECRET_NAME"

# Update or create the config map with the schedule
if ibmcloud ce configmap get --name "$CONFIGMAP_FILE_NAME" >/dev/null 2>&1; then
  ibmcloud ce configmap update --name "$CONFIGMAP_FILE_NAME" --from-file schedule.yaml=schedule_template.yaml
else
  ibmcloud ce configmap create --name "$CONFIGMAP_FILE_NAME" --from-file schedule.yaml=schedule_template.yaml
fi

echo "[+] ConfigMap ready: $CONFIGMAP_FILE_NAME"

# Update or create the main config map with necessary environment variables
if ibmcloud ce configmap get --name "$CONFIGMAP_NAME" >/dev/null 2>&1; then
  ibmcloud ce configmap update \
    --name "$CONFIGMAP_NAME" \
    --from-literal DIRECTOR_SITE_NAME="$DIRECTOR_SITE_NAME" \
    --from-literal VIRTUAL_DATA_CENTER="$VIRTUAL_DATA_CENTER" \
    --from-literal IBM_REGION="$IBM_REGION" \
    --from-literal TASK_TIMEOUT_SECONDS="$TASK_TIMEOUT_SECONDS" \
    --from-literal LOG_LEVEL="Info"
else
  ibmcloud ce configmap create \
    --name "$CONFIGMAP_NAME" \
    --from-literal DIRECTOR_SITE_NAME="$DIRECTOR_SITE_NAME" \
    --from-literal VIRTUAL_DATA_CENTER="$VIRTUAL_DATA_CENTER" \
    --from-literal IBM_REGION="$IBM_REGION" \
    --from-literal LOG_LEVEL="Info"
fi

echo "[+] ConfigMap ready: $CONFIGMAP_NAME"

ibmcloud cr region-set icr.io >/dev/null 2>&1
# Create and configure the power-on job
ibmcloud ce job delete -f --inf --name "$JOB_POWER_ON_NAME"
ibmcloud ce job create \
  --name "$JOB_POWER_ON_NAME" \
  --mode "task" \
  --env-from-secret "$SECRET_NAME" \
  --mount-configmap /app/config="$CONFIGMAP_FILE_NAME" \
  --env-from-configmap "$CONFIGMAP_NAME" \
  --cpu 0.25 --memory "0.5G" \
  --argument "powerOn" \
  --build-source . \
  --build-strategy dockerfile \
  --wait

echo "[+] Job ready: $JOB_POWER_ON_NAME"

REGISTRY_IMAGE=$(ibmcloud ce job get --name "$JOB_POWER_ON_NAME" -o json | jq -r '.buildRun.output_image')
OUTPUT_SECRET=$(ibmcloud ce job get --name "$JOB_POWER_ON_NAME" -o json | jq -r '.buildRun.output_secret')

# Create and configure the power-off job
ibmcloud ce job delete -f --inf --name "$JOB_POWER_OFF_NAME"
ibmcloud ce job create \
  --name "$JOB_POWER_OFF_NAME" \
  --mode "task" \
  --image "$REGISTRY_IMAGE" \
  --registry-secret "$OUTPUT_SECRET" \
  --env-from-secret "$SECRET_NAME" \
  --mount-configmap /app/config="$CONFIGMAP_FILE_NAME" \
  --env-from-configmap "$CONFIGMAP_NAME" \
  --cpu 0.25 --memory "0.5G" \
  --argument "powerOff"

echo "[+] Job ready: $JOB_POWER_OFF_NAME"

# Create cron jobs for scheduling power-on and power-off tasks
ibmcloud ce subscription cron delete -f --inf --name "poweron-working-days--cron"
ibmcloud ce subscription cron create \
  --name "poweron-working-days--cron" \
  --destination-type job \
  --destination "$JOB_POWER_ON_NAME" \
  --schedule '0 7 * * 1-5'

ibmcloud ce subscription cron delete -f --inf --name "poweroff-working-days--cron"
ibmcloud ce subscription cron create \
  --name "poweroff-working-days--cron" \
  --destination-type job \
  --destination "$JOB_POWER_OFF_NAME" \
  --schedule '0 19 * * 1-5'

echo "[+] Done."
