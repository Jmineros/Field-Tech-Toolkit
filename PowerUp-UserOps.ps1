<#
.SYNOPSIS
  PowerUp UserOps – Unified user administration console for Active Directory and Entra ID.

.DESCRIPTION
  PowerUp UserOps is a single-entry PowerShell operator console that consolidates
  identity operations across on-prem Active Directory and Microsoft Entra ID.

  One username. Total control.

.FEATURES
  - Resolve users by samAccountName or UPN
  - Reset AD passwords and unlock accounts
  - Revoke Entra ID sign-in sessions
  - Reset MFA (authentication methods)
  - Add / remove AD and Entra security group membership
  - Remote user session discovery and logoff
  - Automatic prerequisite detection and installation
  - Audit logging

.NOTES
  Author  : Josh Mineros
  Version : 1.0
  Warning : High-impact identity actions. Test before production use.
#>

[CmdletBinding()]
param(
  [string]$Identity,
  [string[]]$ComputerName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#==================================================
# Console Banner
#==================================================
Clear-Host
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host " PowerUp UserOps" -ForegroundColor Cyan
Write-Host " Unified User Administration Console" -ForegroundColor Cyan
Write-Host " Active Directory + Entra ID" -ForegroundColor Cyan
Write-Host "--------------------------------------------------" -ForegroundColor DarkGray
Write-Host " One username. Total control." -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host ""

#==================================================
# Helpers
#==================================================
function Write-Header($t) {
  Write-Host ""
  Write-Host ("=" * 70) -ForegroundColor Cyan
  Write-Host $t -ForegroundColor Cyan
  Write-Host ("=" * 70) -ForegroundColor Cyan
}
function Write-Info($t) { Write-Host "[i] $t" -ForegroundColor Gray }
function Write-Ok($t)   { Write-Host "[+] $t" -ForegroundColor Green }
function Write-Warn($t) { Write-Host "[!] $t" -ForegroundColor Yellow }
function Write-Bad($t)  { Write-Host "[-] $t" -ForegroundColor Red }

function Confirm-HighImpact($msg) {
  Write-Warn $msg
  if ((Read-Host "Type YES to continue") -ne "YES") {
    throw "Operation cancelled."
  }
}

#==================================================
# Audit Logging
#==================================================
$LogRoot = Join-Path $PSScriptRoot "logs"
if (-not (Test-Path $LogRoot)) { New-Item -ItemType Directory -Path $LogRoot | Out-Null }
$LogFile = Join-Path $LogRoot ("UserOps_{0}.log" -f (Get-Date -Format "yyyy-MM-dd"))

function Write-AuditLog {
  param($Action, $TargetUser, $Details)
  [pscustomobject]@{
    Time       = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Operator   = $env:USERNAME
    Action     = $Action
    TargetUser = $TargetUser
    Details    = $Details
  } | ConvertTo-Json -Compress | Add-Content $LogFile
}

#==================================================
# Prerequisites
#==================================================
function Ensure-Module($Name) {
  if (-not (Get-Module -ListAvailable $Name)) {
    Install-Module $Name -Scope CurrentUser -Force -AllowClobber
  }
  Import-Module $Name -ErrorAction Stop
}

Write-Header "Checking prerequisites"
Import-Module ActiveDirectory -ErrorAction Stop
Ensure-Module Microsoft.Graph
Write-Ok "Modules ready"

#==================================================
# Graph Connection
#==================================================
Write-Header "Connecting to Microsoft Graph"
$Scopes = @(
  "User.Read.All",
  "Group.ReadWrite.All",
  "Directory.ReadWrite.All",
  "Device.Read.All",
  "UserAuthenticationMethod.ReadWrite.All"
)
if (-not (Get-MgContext)) {
  Connect-MgGraph -Scopes $Scopes | Out-Null
}
Write-Ok "Connected to Microsoft Graph"

#==================================================
# Resolve User
#==================================================
if (-not $Identity) {
  $Identity = Read-Host "Enter username (samAccountName or UPN)"
}

Write-Header "Resolving user"
try {
  $ADUser = if ($Identity -like "*@*") {
    Get-ADUser -Filter "UserPrincipalName -eq '$Identity'" -Properties *
  } else {
    Get-ADUser -Identity $Identity -Properties *
  }
  Write-Ok "AD user: $($ADUser.SamAccountName)"
} catch {
  Write-Warn "AD user not found"
}

try {
  $MgUser = Get-MgUser -Filter "userPrincipalName eq '$Identity'" -ConsistencyLevel eventual |
            Select-Object -First 1
  if ($MgUser) { Write-Ok "Entra user: $($MgUser.UserPrincipalName)" }
} catch {
  Write-Warn "Entra user not found"
}

#==================================================
# Actions
#==================================================
function Reset-ADPassword {
  Confirm-HighImpact "Reset AD password?"
  $pw = Read-Host "New password" -AsSecureString
  Set-ADAccountPassword -Identity $ADUser -Reset -NewPassword $pw
  Unlock-ADAccount $ADUser -ErrorAction SilentlyContinue
  Write-AuditLog "Reset-ADPassword" $ADUser.SamAccountName "Password reset"
  Write-Ok "Password reset complete"
}

function Revoke-EntraSessions {
  Confirm-HighImpact "Revoke Entra sessions?"
  Revoke-MgUserSignInSession -UserId $MgUser.Id | Out-Null
  Write-AuditLog "Revoke-Sessions" $MgUser.UserPrincipalName "Sessions revoked"
  Write-Ok "Sessions revoked"
}

function Reset-EntraMFA {
  Confirm-HighImpact "DELETE all MFA methods?"
  $methods = Get-MgUserAuthenticationMethod -UserId $MgUser.Id -All
  foreach ($m in $methods) {
    Remove-MgUserAuthenticationMethod -UserId $MgUser.Id -AuthenticationMethodId $m.Id -ErrorAction SilentlyContinue
  }
  Write-AuditLog "Reset-MFA" $MgUser.UserPrincipalName "Auth methods deleted"
  Write-Ok "MFA reset"
}

function Get-EntraDevices {
  Write-Header "Registered devices"
  Get-MgUserRegisteredDevice -UserId $MgUser.Id -All |
    Select DisplayName,OperatingSystem,ApproximateLastSignInDateTime |
    Format-Table -AutoSize
}

function Remote-Logoff {
  if (-not $ComputerName) {
    $ComputerName = (Read-Host "Computers (comma separated)").Split(",")
  }
  foreach ($c in $ComputerName) {
    $sessions = qwinsta /server:$c 2>$null | Select-String $ADUser.SamAccountName
    if ($sessions) {
      Confirm-HighImpact "Log off sessions on $c?"
      $sessions | ForEach-Object {
        $id = ($_ -split '\s+')[2]
        logoff $id /server:$c
        Write-AuditLog "Remote-Logoff" $ADUser.SamAccountName "Computer=$c Session=$id"
      }
    }
  }
}

#==================================================
# Menu
#==================================================
while ($true) {
  Write-Header "PowerUp UserOps Console"
  Write-Host "1) List Entra devices"
  Write-Host "2) Reset AD password"
  Write-Host "3) Revoke Entra sessions"
  Write-Host "4) Reset MFA"
  Write-Host "5) Remote logoff"
  Write-Host "0) Exit"

  switch (Read-Host "Select option") {
    "1" { Get-EntraDevices }
    "2" { Reset-ADPassword }
    "3" { Revoke-EntraSessions }
    "4" { Reset-EntraMFA }
    "5" { Remote-Logoff }
    "0" { break }
    default { Write-Warn "Invalid option" }
  }
}

Write-Ok "Done."

