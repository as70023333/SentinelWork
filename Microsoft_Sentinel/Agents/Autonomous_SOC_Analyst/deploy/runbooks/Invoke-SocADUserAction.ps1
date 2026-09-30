<#
.SYNOPSIS
    Autonomous SOC Analyst - disable / enable an on-prem Active Directory user.

.DESCRIPTION
    Runs in Azure Automation on a Hybrid Runbook Worker that is joined to your domain.
    It is started by a webhook that the SOC agent calls (AD_AUTOMATION_WEBHOOK_URL) with:

        { "action": "disable" | "enable",
          "userPrincipalName": "jdoe@contoso.com",
          "samAccountName": "jdoe",
          "reason": "...",
          "requestedBy": "autonomous-soc-analyst" }

    Defense in depth: even if the agent's policy were misconfigured, this runbook refuses
    to touch protected (adminCount=1) accounts such as Domain Admins.

.NOTES
    Requirements on the Hybrid Worker: RSAT ActiveDirectory PowerShell module, and a Run As
    credential (or the worker's computer account) delegated "Read/Write userAccountControl"
    on the OUs that hold standard users. Do NOT grant it Domain Admin.
#>
param(
    [Parameter(Mandatory = $false)]
    [object] $WebhookData
)

$ErrorActionPreference = 'Stop'

if (-not $WebhookData -or -not $WebhookData.RequestBody) {
    throw 'This runbook must be started by its webhook.'
}

$body = $WebhookData.RequestBody | ConvertFrom-Json
$action = [string]$body.action
$upn = [string]$body.userPrincipalName
$sam = [string]$body.samAccountName

if ($action -notin @('disable', 'enable')) {
    throw "Unsupported action '$action'. Expected 'disable' or 'enable'."
}
if ($sam -and $sam -notmatch '^[A-Za-z0-9._$-]{1,64}$') {
    throw "Refusing unexpected samAccountName value."
}
if (-not $sam -and $upn -notmatch '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+$') {
    throw "Refusing unexpected userPrincipalName value."
}

Import-Module ActiveDirectory

if ($sam) {
    $user = Get-ADUser -Identity $sam -Properties adminCount, Enabled, UserPrincipalName
}
else {
    $user = Get-ADUser -Filter "UserPrincipalName -eq '$upn'" -Properties adminCount, Enabled, UserPrincipalName
}
if (-not $user) {
    throw "User not found in Active Directory."
}
if ($user -is [array]) {
    throw "More than one user matched; refusing to act."
}
if ($user.adminCount -eq 1) {
    throw "Refusing to change protected account $($user.SamAccountName) (adminCount=1). Handle manually."
}

if ($action -eq 'disable') {
    Disable-ADAccount -Identity $user
}
else {
    Enable-ADAccount -Identity $user
}

$result = [ordered]@{
    action            = $action
    samAccountName    = $user.SamAccountName
    userPrincipalName = $user.UserPrincipalName
    reason            = [string]$body.reason
    requestedBy       = [string]$body.requestedBy
    completedUtc      = (Get-Date).ToUniversalTime().ToString('o')
}
Write-Output ($result | ConvertTo-Json -Compress)
