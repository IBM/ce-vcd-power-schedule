# ce-vcd-power-schedule

Lightweight tool to start/stop vApp and VM in IBM Cloud VCFaaS (VMware Cloud Director) based on cron schedules and exclusion rules.

## Prerequisites

Before using the project, ensure you have:

- An **IBM Cloud account** with access to PowerVS resources. See [Required permissions](#-required-permissions)
- **IBM Cloud CLI** installed
  - Linux: `curl -fsSL https://clis.cloud.ibm.com/install/linux | sh`
  - MacOS: `curl -fsSL https://clis.cloud.ibm.com/install/osx | sh`
  - Windows™: `iex (New-Object Net.WebClient).DownloadString('https://clis.cloud.ibm.com/install/powershell')`
  - WSL2 on Windows™: `curl -fsSL https://clis.cloud.ibm.com/install/linux | sh`
- **IBM Cloud CLI Code Engine plugin** installed (`ibmcloud plugin install ce`)
- **IBM Cloud CLI Container Registry plugin** installed (`ibmcloud plugin install cr`)
- A **resource group** to deploy resources
- A **Virtual Data Center** in IBM Cloud VMware Cloud Foundation as a Service
- At least one vApp or VM within the VDC
- **jq** and **bash** available in your environment

---

## Required permissions

You must have at least the following roles. You can check your access by going to

- Manage > Access (IAM) > [Users](<[https://](https://cloud.ibm.com/iam/users)>) > User > Access or
- Manage > Access (IAM) > [Access groups](https://cloud.ibm.com/iam/groups) > Access

| Service                 | Roles   |
| ----------------------- | ------- |
| **Resource group only** | Editor  |
| **Code Engine**         | Manager |
| **VCF as a Service**    | Manager |

---

## Setup

**1. Clone the repository:**

   ```bash
   git clone https://github.com/IBM/ce-vcd-power-schedule.git
   cd ce-vcd-power-schedule
   ```

**2. Export following environment variables**:

  ```bash
  export DIRECTOR_SITE_NAME=      # "IBM VCFaaS Multitenant - WDC" or "IBM VCFaaS Multitenant - FRA"
  export VIRTUAL_DATA_CENTER=     # Name of Virtual Data Center
  export RESOURCE_GROUP=          # Resource group name used to deploy resources
  export IBM_REGION=              # "us-east" or "eu-de"
  export IBM_APIKEY=              # IBM Cloud API key used to deploy resources and stored into Code Engine secret
  ```

**3. Run `deploy.sh` script**

  ```bash
  ./deploy.sh
  ```

**4. Modify Code Engine config-map `entities-and-exclusions--cm` accordingly**

  ```yaml
  entities: # List virtual entities being managed.
    - type: vApp # Type can be vApp or vm
      name: "vApp Name" # Name of vApp or VM to manage
    - type: vm
      name: "VM Name"
  exclusions: # Specifies certain conditions under which the scheduled tasks should not run.
    timezone: Europe/Rome # time zone to use
    dates: # List of single dates
      - date: '2025-12-25'
        annual: true # true if the date occurs every year, false if it is only valid for the specified year
    ranges: # List of date ranges
      - from: '2025-08-10'
        to: '2025-08-24'
        annual: true
      - from: '2025-12-25'
        to: '2025-12-31'
        annual: false
  ```

**5. By default, two periodic timer event subscription (cron-like) are created automatically. Update them accordingly.**

  - `poweron-working-days--cron` (planning for start-up during working days at 7 AM UTC)
  - `poweroff-working-days--cron` (planning for shutdown during working days at 7 PM UTC)

---

## Cleaning Up Resources

**1. Run `clean.sh` script**

  ```bash
  ./clean.sh
  ```

---

## Local test

```bash
go mod tidy
go run ./cmd/ce-vcd-power-schedule
```

## Local Build

```bash
go build -o bin/ce-vcd-power-schedule ./cmd/ce-vcd-power-schedule/main.go
```
