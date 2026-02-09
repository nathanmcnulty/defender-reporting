# Azure Container Apps Deployment Option

## Overview
Azure Container Apps hosts the vulnerability dashboard with built-in Entra ID
authentication (Easy Auth) and a proper web serving layer, restricted to a
specific security group.

## Why Container Apps?
- **Built-in Entra ID SSO** via Easy Auth (ingress-level authentication)
- **Security group restriction** — only assigned groups/users can access
- **Free tier available** (first 180,000 vCPU-seconds, 360,000 GiB-seconds/month free)
- **No Node.js dependency** unlike Static Web Apps CLI deployment
- **Scales to zero** — no cost when not accessed
- **HTTPS by default** with managed certificates
- **Custom domains** supported

## Architecture
1. **Caddy** container downloads the latest dashboard HTML from blob storage
   using the Container Apps managed identity, then serves it from an EmptyDir volume
2. **Easy Auth** configured with Entra ID for tenant-restricted SSO, group-gated
   (implicit flow, no client secret)
3. **Scale-to-zero** ensures the container always fetches the latest dashboard
   blob on the next request after idle timeout

### Why Not Init Container?
Container Apps runs the identity sidecar (which provides the managed identity
token endpoint) **after** init containers complete. This means init containers
cannot use managed identity for authentication. The download logic runs in the
Caddy container's startup script instead, where the identity endpoint is available.

### Why Not Blob Storage Mount?
Container Apps does **NOT** support Azure Blob Storage volume mounts — only Azure
Files (SMB/NFS) and ephemeral storage. Since the storage account uses Entra ID
auth only (`allowSharedKeyAccess = false`), Azure Files SMB won't work either
(requires shared key).

## Implementation
Implemented as an optional step in `Setup-AzureResources.ps1` via the
`-IncludeContainerApp` and `-SecurityGroup` parameters.

### Usage
```powershell
.\Setup-AzureResources.ps1 -ResourceGroupName "rg-defender-reporting" `
    -AutomationAccountName "aa-defender-reporting" `
    -StorageAccountName "stdefenderreporting" `
    -IncludeContainerApp -SecurityGroup "Dashboard Viewers"
```

### What Gets Provisioned (Steps 15-20)
- **Step 15**: Resolves security group (accepts Object ID or display name)
- **Step 16**: Container Apps Environment (no Log Analytics)
- **Step 17**: Container App with:
  - `caddy:alpine` downloads blob at startup via managed identity, then serves it
  - Base64-encoded startup script avoids JSON/shell escaping issues
  - EmptyDir volume for dashboard storage
  - System-assigned Managed Identity
  - Scale: 0-1 replicas
- **Step 18**: Storage Blob Data Reader RBAC for Container App MI
- **Step 19**: Entra ID App Registration with:
  - Implicit flow (`enableIdTokenIssuance`), no client secret
  - Delegated permissions: openid, email, profile (with admin consent)
  - Service principal with `appRoleAssignmentRequired = true`
  - Security group assignment for access control
- **Step 20**: Easy Auth configuration on the Container App

### Dashboard Refresh Flow
1. Automation runbook uploads updated `VulnerabilityDashboard.html` to blob
2. Container App is idle → scales to zero after ~5-10 minutes
3. Next browser request triggers cold start
4. Caddy startup script acquires managed identity token and downloads blob
5. Caddy serves the updated dashboard

### Prerequisites
- `Microsoft.Graph.Authentication` PowerShell module
- Application Administrator role in Entra ID (for app registration)
- An existing Entra ID security group for access control

## Tasks
- [x] Create Container App with Caddy (no custom Dockerfile needed)
- [x] Provision via ARM REST API in Setup-AzureResources.ps1 (Steps 15-20)
- [x] Configure Easy Auth with Entra ID (tenant + group restriction)
- [x] Caddy startup script fetches dashboard from blob via managed identity
- [ ] Test end-to-end: runbook updates blob → container serves new dashboard
- [ ] Compare costs with current blob storage approach
- [ ] Add custom domain support (optional future enhancement)

## References
- [Container Apps overview](https://learn.microsoft.com/en-us/azure/container-apps/overview)
- [Container Apps Easy Auth](https://learn.microsoft.com/en-us/azure/container-apps/authentication)
- [Container Apps storage mounts](https://learn.microsoft.com/en-us/azure/container-apps/storage-mounts)
- [Container Apps free tier](https://learn.microsoft.com/en-us/azure/container-apps/billing)
