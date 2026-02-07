<#
.SYNOPSIS
  One-script user admin console for AD + Entra ID (Microsoft Graph).

.DESCRIPTION
  - Resolves a user from a single identifier (samAccountName or UPN)
  - Provides actions:
      * List Entra devices
      * Reset AD password
      * Revoke Entra sign-in sessions
      * Reset MFA (delete auth methods)  [HIGH IMPACT]
      * Remote logoff from Windows machines
      * Add/Remove group membership (AD and Entra)

.NOTES
  Run as a privileged account. Use carefully.
  Tested pattern only; you should validate in a lab before production use.
#>

[CmdletBinding()]
param(
  [Parameter(Mandatory=$false)]
  [string]$Identity,

  # For remote logoff: list of computers to attempt
  [Parameter(Mandatory=$false)]
  [string[]]$ComputerName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

#region --- Helpers: Console + Safety ---

function Write-Header($text) {
  Write-Host ""
  Write-Host ("=" * 70)
  Write-Host $text -ForegroundColor Cyan
  Write-Host ("=" * 70)
}

function Write-Warn($text) { Write-Host "[!]" -NoNewline -ForegroundColor Yellow; Write-Host " $text" }
function Write-Info($text) { Write-Host "[i]" -NoNewline -ForegroundColor Gray;   Write-Host " $text" }
function Write-Ok($text)   { Write-Host "[+]" -NoNewline -ForegroundColor Green;  Write-Host " $text" }
function Write-Bad($text)  { Write-Host "[-]" -NoNewline -ForegroundColor Red;    Write-Host " $text" }

function Confirm-HighImpact([string]$Message) {
  Write-Warn $Message
  $confirm = Read-Host "Type YES to continue"
  if ($confirm -ne "YES") { throw "Cancelled by user." }
}

#endregion

#region --- Prereqs: Modules ---

function Ensure-Module {
  param(
    [Parameter(Mandatory)] [string]$Name,
    [string]$MinimumVersion = $null
  )

  $installed = Get-Module -ListAvailable -Name $Name | Sort-Object Version -Descending | Select-Object -First 1
  if (-not $installed) {
    Write-Info "Module '$Name' not found. Installing for CurrentUser..."
    Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber
  } elseif ($MinimumVersion -and ([version]$installed.Version -lt [version]$MinimumVersion)) {
    Write-Info "Module '$Name' found but version is $($installed.Version). Updating..."
    Update-Module -Name $Name -Force
  }

  Import-Module $Name -ErrorAction Stop
  Write-Ok "Loaded module: $Name"
}

function Ensure-Prerequisites {
  Write-Header "Checking prerequisites"

  # AD module usually comes from RSAT; can't be installed from PSGallery.
  try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Ok "Loaded module: ActiveDirectory"
  } catch {
    Write-Bad "ActiveDirectory module not available. Install RSAT (Active Directory) on this machine."
    throw
  }

  Ensure-Module -Name Microsoft.Graph -MinimumVersion "2.0.0"

  # Optional Intune endpoints (in Graph, but beta might be needed for some device info)
  # We'll keep it simple and use v1.0 where possible.
}

#endregion

#region --- Graph Connection ---

function Connect-Graph {
  Write-Header "Connecting to Microsoft Graph"

  # Minimal set; expand as needed.
  $scopes = @(
    "User.Read.All",
    "Group.ReadWrite.All",
    "Directory.ReadWrite.All",
    "Device.Read.All",
    "UserAuthenticationMethod.ReadWrite.All"
  )

  # Connect only if not already connected
  $ctx = Get-MgContext -ErrorAction SilentlyContinue
  if (-not $ctx) {
    Write-Info "Requesting Graph scopes: $($scopes -join ', ')"
    Connect-MgGraph -Scopes $scopes | Out-Null
    $ctx = Get-MgContext
  }

  Write-Ok "Graph connected as: $($ctx.Account) (Tenant: $($ctx.TenantId))"
}

#endregion

#region --- User Resolution (AD + Entra) ---

function Resolve-User {
  param([Parameter(Mandatory)][string]$Identity)

  Write-Header "Resolving user: $Identity"

  # 1) Resolve AD user
  $adUser = $null
  try {
    if ($Identity -like "*@*") {
      $adUser = Get-ADUser -Filter "UserPrincipalName -eq '$Identity'" -Properties MemberOf, Enabled, LockedOut, PasswordLastSet, LastLogonDate
    } else {
      $adUser = Get-ADUser -Identity $Identity -Properties MemberOf, Enabled, LockedOut, PasswordLastSet, LastLogonDate
    }
    Write-Ok "AD user: $($adUser.SamAccountName) / $($adUser.UserPrincipalName)"
  } catch {
    Write-Warn "AD user not found or not accessible."
  }

  # 2) Resolve Entra user via Graph
  $mgUser = $null
  try {
    if ($Identity -like "*@*") {
      $mgUser = Get-MgUser -Filter "userPrincipalName eq '$Identity'" -ConsistencyLevel eventual -CountVariable ct
      $mgUser = $mgUser | Select-Object -First 1
    } else {
      # try by mailNickname or onPremisesSamAccountName (may be null depending on sync)
      $mgUser = Get-MgUser -Filter "onPremisesSamAccountName eq '$Identity'" -ConsistencyLevel eventual -CountVariable ct
      $mgUser = $mgUser | Select-Object -First 1
      if (-not $mgUser) {
        $mgUser = Get-MgUser -Filter "mailNickname eq '$Identity'" -ConsistencyLevel eventual -CountVariable ct | Select-Object -First 1
      }
    }

    if ($mgUser) {
      Write-Ok "Entra user: $($mgUser.DisplayName) / $($mgUser.UserPrincipalName)"
    } else {
      Write-Warn "Entra user not found."
    }
  } catch {
    Write-Warn "Graph user lookup failed: $($_.Exception.Message)"
  }

  [pscustomobject]@{
    Identity = $Identity
    ADUser   = $adUser
    MgUser   = $mgUser
  }
}

#endregion

#region --- Actions: Devices ---

function Get-EntraDevicesForUser {
  param([Parameter(Mandatory)][object]$MgUser)

  Write-Header "Devices for user (Entra)"
  # Registered devices: /users/{id}/registeredDevices
  $devices = Get-MgUserRegisteredDevice -UserId $MgUser.Id -All -ErrorAction Stop
  if (-not $devices) { Write-Info "No registered devices found."; return }

  $devices |
    Select-Object Id, DisplayName, OperatingSystem, OperatingSystemVersion, TrustType, ApproximateLastSignInDateTime |
    Format-Table -AutoSize
}

#endregion

#region --- Actions: Password Reset (AD) ---

function Reset-ADPassword {
  param(
    [Parameter(Mandatory)][object]$ADUser
  )

  Write-Header "Reset AD password"
  $newPass = Read-Host "Enter new password (hidden)" -AsSecureString

  Confirm-HighImpact "This will reset the AD password for $($ADUser.SamAccountName)."

  Set-ADAccountPassword -Identity $ADUser.DistinguishedName -Reset -NewPassword $newPass
  Unlock-ADAccount -Identity $ADUser.DistinguishedName -ErrorAction SilentlyContinue

  # Optionally: force change at next logon
  $force = Read-Host "Force change password at next logon? (Y/N)"
  if ($force -match '^(Y|y)') {
    Set-ADUser -Identity $ADUser.DistinguishedName -ChangePasswordAtLogon $true
  }

  Write-Ok "AD password reset complete."
}

#endregion

#region --- Actions: Entra Session + MFA Reset ---

function Revoke-EntraSessions {
  param([Parameter(Mandatory)][object]$MgUser)

  Write-Header "Revoke Entra sign-in sessions"
  Confirm-HighImpact "This will revoke refresh tokens and sign-in sessions for $($MgUser.UserPrincipalName). Users will be prompted to sign in again."
  Revoke-MgUserSignInSession -UserId $MgUser.Id | Out-Null
  Write-Ok "Sign-in sessions revoked."
}

function Reset-EntraMFA {
  param([Parameter(Mandatory)][object]$MgUser)

  Write-Header "Reset MFA (delete authentication methods)"
  Confirm-HighImpact "This is HIGH IMPACT. It deletes the user's registered authentication methods in Entra ID."

  # List methods
  $methods = Get-MgUserAuthenticationMethod -UserId $MgUser.Id -All
  if (-not $methods) { Write-Info "No auth methods found."; return }

  Write-Info "Current auth methods:"
  $methods | Select-Object Id, AdditionalProperties | Format-Table -AutoSize

  # Delete each method (except password method which is not deletable here)
  foreach ($m in $methods) {
    try {
      # Some method types have dedicated cmdlets; generic remove works by id for many.
      Remove-MgUserAuthenticationMethod -UserId $MgUser.Id -AuthenticationMethodId $m.Id -ErrorAction Stop
      Write-Ok "Deleted auth method: $($m.Id)"
    } catch {
      Write-Warn "Could not delete auth method $($m.Id): $($_.Exception.Message)"
    }
  }

  Write-Ok "MFA reset attempt complete. Consider revoking sessions too."
}

#endregion

#region --- Actions: Group Membership ---

function Add-ADGroupMemberByName {
  param(
    [Parameter(Mandatory)][object]$ADUser
  )

  Write-Header "Add to AD security group"
  $group = Read-Host "Enter AD group name (sAMAccountName or DN)"
  Add-ADGroupMember -Identity $group -Members $ADUser.SamAccountName
  Write-Ok "Added $($ADUser.SamAccountName) to $group"
}

function Remove-ADGroupMemberByName {
  param(
    [Parameter(Mandatory)][object]$ADUser
  )

  Write-Header "Remove from AD security group"
  $group = Read-Host "Enter AD group name (sAMAccountName or DN)"
  Remove-ADGroupMember -Identity $group -Members $ADUser.SamAccountName -Confirm:$false
  Write-Ok "Removed $($ADUser.SamAccountName) from $group"
}

function Add-EntraGroupMember {
  param([Parameter(Mandatory)][object]$MgUser)

  Write-Header "Add to Entra group"
  $groupIdOrName = Read-Host "Enter Entra group ID or display name"

  # Resolve group
  $g = $null
  if ($groupIdOrName -match '^[0-9a-fA-F-]{36}$') {
    $g = Get-MgGroup -GroupId $groupIdOrName
  } else {
    $g = Get-MgGroup -Filter "displayName eq '$groupIdOrName'" -ConsistencyLevel eventual | Select-Object -First 1
  }
  if (-not $g) { throw "Group not found." }

  New-MgGroupMemberByRef -GroupId $g.Id -BodyParameter @{
    "@odata.id" = "https://graph.microsoft.com/v1.0/directoryObjects/$($MgUser.Id)"
  } | Out-Null

  Write-Ok "Added $($MgUser.UserPrincipalName) to Entra group: $($g.DisplayName)"
}

function Remove-EntraGroupMember {
  param([Parameter(Mandatory)][object]$MgUser)

  Write-Header "Remove from Entra group"
  $groupIdOrName = Read-Host "Enter Entra group ID or display name"

  $g = $null
  if ($groupIdOrName -match '^[0-9a-fA-F-]{36}$') {
    $g = Get-MgGroup -GroupId $groupIdOrName
  } else {
    $g = Get-MgGroup -Filter "displayName eq '$groupIdOrName'" -ConsistencyLevel eventual | Select-Object -First 1
  }
  if (-not $g) { throw "Group not found." }

  Remove-MgGroupMemberByRef -GroupId $g.Id -DirectoryObjectId $MgUser.Id
  Write-Ok "Removed $($MgUser.UserPrincipalName) from Entra group: $($g.DisplayName)"
}

#endregion

#region --- Actions: Remote Logoff ---

function Get-RemoteSessions {
  param([Parameter(Mandatory)][string]$Computer)

  # Uses qwinsta (fast and works widely). Requires rights on remote machine.
  $raw = qwinsta /server:$Computer 2>$null
  if (-not $raw) { return @() }

  # Parse qwinsta output (best-effort)
  $lines = $raw | Select-Object -Skip 1
  foreach ($line in $lines) {
    $clean = ($line -replace '\s{2,}', ' ').Trim()
    if (-not $clean) { continue }

    # columns can shift; best-effort split
    $parts = $clean.Split(' ')
    # Typical: SESSIONNAME USERNAME ID STATE TYPE DEVICE
    [pscustomobject]@{
      Computer = $Computer
      SessionName = $parts[0]
      UserName = if ($parts.Count -gt 1) { $parts[1] } else { $null }
      Id = if ($parts.Count -gt 2) { $parts[2] } else { $null }
      State = if ($parts.Count -gt 3) { $parts[3] } else { $null }
    }
  }
}

function Logoff-UserRemote {
  param(
    [Parameter(Mandatory)][string]$SamAccountName,
    [Parameter(Mandatory)][string[]]$Computers
  )

  Write-Header "Remote logoff"
  foreach ($c in $Computers) {
    try {
      Write-Info "Checking sessions on $c ..."
      $sessions = Get-RemoteSessions -Computer $c | Where-Object { $_.UserName -and $_.UserName -like "*$SamAccountName*" }

      if (-not $sessions) {
        Write-Info "No matching sessions on $c"
        continue
      }

      $sessions | Format-Table -AutoSize

      Confirm-HighImpact "Logoff matching sessions on $c for '$SamAccountName'?"
      foreach ($s in $sessions) {
        if ($s.Id) {
          logoff $s.Id /server:$c
          Write-Ok "Logged off session $($s.Id) on $c"
        }
      }
    } catch {
      Write-Warn "Remote logoff failed on $c: $($_.Exception.Message)"
    }
  }
}

#endregion

#region --- Main Menu ---

function Show-Menu {
  param([object]$ctx)

  $ad = $ctx.ADUser
  $mg = $ctx.MgUser

  Write-Header "User Admin Console"
  Write-Host "User: $($ctx.Identity)"
  if ($ad) { Write-Host " AD:   $($ad.SamAccountName) | Enabled=$($ad.Enabled) | LockedOut=$($ad.LockedOut) | LastLogon=$($ad.LastLogonDate)" }
  if ($mg) { Write-Host " Entra:$($mg.UserPrincipalName) | $($mg.DisplayName)" }
  Write-Host ""

  Write-Host "1) List Entra registered devices"
  Write-Host "2) Reset AD password"
  Write-Host "3) Revoke Entra sign-in sessions"
  Write-Host "4) Reset MFA (delete auth methods)"
  Write-Host "5) Remote logoff (provide computers)"
  Write-Host "6) Add to AD group"
  Write-Host "7) Remove from AD group"
  Write-Host "8) Add to Entra group"
  Write-Host "9) Remove from Entra group"
  Write-Host "0) Exit"
}

try {
  Ensure-Prerequisites
  Connect-Graph

  if (-not $Identity) {
    $Identity = Read-Host "Enter username (samAccountName) or UPN (user@domain.com)"
  }

  $ctx = Resolve-User -Identity $Identity

  while ($true) {
    Show-Menu -ctx $ctx
    $choice = Read-Host "Select an option"
    switch ($choice) {
      "1" {
        if (-not $ctx.MgUser) { Write-Warn "No Entra user resolved."; break }
        Get-EntraDevicesForUser -MgUser $ctx.MgUser
      }
      "2" {
        if (-not $ctx.ADUser) { Write-Warn "No AD user resolved."; break }
        Reset-ADPassword -ADUser $ctx.ADUser
      }
      "3" {
        if (-not $ctx.MgUser) { Write-Warn "No Entra user resolved."; break }
        Revoke-EntraSessions -MgUser $ctx.MgUser
      }
      "4" {
        if (-not $ctx.MgUser) { Write-Warn "No Entra user resolved."; break }
        Reset-EntraMFA -MgUser $ctx.MgUser
      }
      "5" {
        if (-not $ctx.ADUser) { Write-Warn "Need AD user samAccountName for session matching."; break }
        if (-not $ComputerName -or $ComputerName.Count -eq 0) {
          $raw = Read-Host "Enter computer names (comma-separated)"
          $ComputerName = $raw.Split(",") | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        }
        Logoff-UserRemote -SamAccountName $ctx.ADUser.SamAccountName -Computers $ComputerName
      }
      "6" {
        if (-not $ctx.ADUser) { Write-Warn "No AD user resolved."; break }
        Add-ADGroupMemberByName -ADUser $ctx.ADUser
      }
      "7" {
        if (-not $ctx.ADUser) { Write-Warn "No AD user resolved."; break }
        Remove-ADGroupMemberByName -ADUser $ctx.ADUser
      }
      "8" {
        if (-not $ctx.MgUser) { Write-Warn "No Entra user resolved."; break }
        Add-EntraGroupMember -MgUser $ctx.MgUser
      }
      "9" {
        if (-not $ctx.MgUser) { Write-Warn "No Entra user resolved."; break }
        Remove-EntraGroupMember -MgUser $ctx.MgUser
      }
      "0" { break }
      default { Write-Warn "Unknown option." }
    }
  }

  Write-Ok "Done."
} catch {
  Write-Bad $_.Exception.Message
  throw
}
