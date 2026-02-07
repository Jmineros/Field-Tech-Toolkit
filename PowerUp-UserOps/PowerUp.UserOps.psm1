Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# =========================
# Console + Logging Helpers
# =========================

function Write-Header([string]$t) {
  Write-Host ""
  Write-Host ("=" * 70) -ForegroundColor Cyan
  Write-Host $t -ForegroundColor Cyan
  Write-Host ("=" * 70) -ForegroundColor Cyan
}

function Write-Info([string]$t) { Write-Host "[i] $t" -ForegroundColor Gray }
function Write-Ok([string]$t)   { Write-Host "[+] $t" -ForegroundColor Green }
function Write-Warn([string]$t) { Write-Host "[!] $t" -ForegroundColor Yellow }
function Write-Bad([string]$t)  { Write-Host "[-] $t" -ForegroundColor Red }

function Confirm-HighImpact([string]$Message) {
  Write-Warn $Message
  $confirm = Read-Host "Type YES to continue"
  if ($confirm -ne "YES") { throw "Cancelled by user." }
}

function New-UserOpsLogger {
  param(
    [Parameter(Mandatory)][string]$RootPath
  )
  if (-not (Test-Path $RootPath)) { New-Item -ItemType Directory -Path $RootPath | Out-Null }

  $file = Join-Path $RootPath ("UserOps_{0}.log" -f (Get-Date -Format "yyyy-MM-dd"))
  return $file
}

function Write-AuditLog {
  param(
    [Parameter(Mandatory)][string]$LogFile,
    [Parameter(Mandatory)][string]$Action,
    [string]$TargetUser,
    [string]$Details
  )

  $entry = [pscustomobject]@{
    Timestamp  = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    Operator   = $env:USERNAME
    Action     = $Action
    TargetUser = $TargetUser
    Details    = $Details
  }

  $entry | ConvertTo-Json -Compress | Add-Content -Path $LogFile
}

# =========================
# Config
# =========================

function Get-UserOpsConfig {
  param([Parameter(Mandatory)][string]$ConfigPath)

  if (-not (Test-Path $ConfigPath)) {
    Write-Warn "Config not found: $ConfigPath"
    Write-Warn "Using defaults. (Tip: copy userops.config.example.json to userops.config.json)"
    return @{
      LogRoot = (Join-Path $PSScriptRoot "logs")
      GraphScopesSafe = @("User.Read.All","Group.ReadWrite.All","Directory.ReadWrite.All","Device.Read.All")
      GraphScopesNuclear = @("User.Read.All","Group.ReadWrite.All","Directory.ReadWrite.All","Device.Read.All","UserAuthenticationMethod.ReadWrite.All","AuditLog.Read.All")
      SignInLogLookbackHours = 72
      ComputerDiscovery = @{
        Enabled = $true
        SearchBase = ""          # optional OU DN
        MaxComputers = 60
        ThrottleLimit = 12
        RequireConfirmation = $true
      }
    }
  }

  $raw = Get-Content $ConfigPath -Raw
  return ($raw | ConvertFrom-Json -AsHashtable)
}

# =========================
# Prereqs
# =========================

function Ensure-Module {
  param(
    [Parameter(Mandatory)][string]$Name,
    [string]$MinimumVersion = $null
  )

  $installed = Get-Module -ListAvailable -Name $Name | Sort-Object Version -Descending | Select-Object -First 1
  if (-not $installed) {
    Write-Info "Module '$Name' not found. Installing for CurrentUser..."
    Install-Module -Name $Name -Scope CurrentUser -Force -AllowClobber
  } elseif ($MinimumVersion -and ([version]$installed.Version -lt [version]$MinimumVersion)) {
    Write-Info "Module '$Name' found ($($installed.Version)). Updating..."
    Update-Module -Name $Name -Force
  }

  Import-Module $Name -ErrorAction Stop
  Write-Ok "Loaded module: $Name"
}

function Ensure-Prerequisites {
  Write-Header "Checking prerequisites"

  try {
    Import-Module ActiveDirectory -ErrorAction Stop
    Write-Ok "Loaded module: ActiveDirectory"
  } catch {
    Write-Bad "ActiveDirectory module not available. Install RSAT: Active Directory tools."
    throw
  }

  Ensure-Module -Name Microsoft.Graph -MinimumVersion "2.0.0"
}

# =========================
# Graph
# =========================

function Connect-UserOpsGraph {
  param(
    [Parameter(Mandatory)][string[]]$Scopes
  )

  Write-Header "Connecting to Microsoft Graph"
  $ctx = Get-MgContext -ErrorAction SilentlyContinue
  if (-not $ctx) {
    Write-Info "Requesting scopes: $($Scopes -join ', ')"
    Connect-MgGraph -Scopes $Scopes | Out-Null
    $ctx = Get-MgContext
  } else {
    # If already connected, ensure we have required scopes (best-effort)
    $missing = @()
    foreach ($s in $Scopes) {
      if ($ctx.Scopes -notcontains $s) { $missing += $s }
    }
    if ($missing.Count -gt 0) {
      Write-Warn "Current Graph session missing scopes: $($missing -join ', ')"
      Write-Warn "Reconnecting with required scopes..."
      Disconnect-MgGraph | Out-Null
      Connect-MgGraph -Scopes $Scopes | Out-Null
      $ctx = Get-MgContext
    }
  }

  Write-Ok "Graph connected as: $($ctx.Account) (Tenant: $($ctx.TenantId))"
}

# =========================
# User Resolution
# =========================

function Resolve-UserOpsUser {
  param([Parameter(Mandatory)][string]$Identity)

  Write-Header "Resolving user: $Identity"

  $adUser = $null
  try {
    if ($Identity -like "*@*") {
      $adUser = Get-ADUser -Filter "UserPrincipalName -eq '$Identity'" -Properties MemberOf, Enabled, LockedOut, PasswordLastSet, LastLogonDate, LastLogonTimestamp, whenCreated
    } else {
      $adUser = Get-ADUser -Identity $Identity -Properties MemberOf, Enabled, LockedOut, PasswordLastSet, LastLogonDate, LastLogonTimestamp, whenCreated
    }
    if ($adUser) { Write-Ok "AD user: $($adUser.SamAccountName) / $($adUser.UserPrincipalName)" }
  } catch {
    Write-Warn "AD user not found or not accessible."
  }

  $mgUser = $null
  try {
    if ($Identity -like "*@*") {
      $mgUser = Get-MgUser -Filter "userPrincipalName eq '$Identity'" -ConsistencyLevel eventual | Select-Object -First 1
    } else {
      $mgUser = Get-MgUser -Filter "onPremisesSamAccountName eq '$Identity'" -ConsistencyLevel eventual | Select-Object -First 1
      if (-not $mgUser) {
        $mgUser = Get-MgUser -Filter "mailNickname eq '$Identity'" -ConsistencyLevel eventual | Select-Object -First 1
      }
    }
    if ($mgUser) { Write-Ok "Entra user: $($mgUser.DisplayName) / $($mgUser.UserPrincipalName)" }
  } catch {
    Write-Warn "Graph user lookup failed: $($_.Exception.Message)"
  }

  [pscustomobject]@{
    Identity = $Identity
    ADUser   = $adUser
    MgUser   = $mgUser
  }
}

# =========================
# Discovery: Where logged in?
# =========================

function Get-UserOpsEntraSignIns {
  param(
    [Parameter(Mandatory)][object]$MgUser,
    [int]$LookbackHours = 72
  )

  # Requires AuditLog.Read.All
  Write-Header "Where is the user logged in? (Entra sign-in logs)"
  $since = (Get-Date).ToUniversalTime().AddHours(-1 * $LookbackHours).ToString("o")

  try {
    # Filter by userId; time filter is supported but varies by tenant/endpoint behavior
    $filter = "userId eq '$($MgUser.Id)' and createdDateTime ge $since"
    $signins = Get-MgAuditLogSignIn -Filter $filter -Top 15 -ErrorAction Stop

    if (-not $signins) {
      Write-Info "No sign-in events found in last $LookbackHours hours."
      return @()
    }

    $signins |
      Select-Object `
        @{n="When(UTC)";e={$_.CreatedDateTime}},
        @{n="App";e={$_.AppDisplayName}},
        @{n="IP";e={$_.IpAddress}},
        @{n="Device";e={$_.DeviceDetail.DisplayName}},
        @{n="OS";e={$_.DeviceDetail.OperatingSystem}},
        @{n="Browser";e={$_.DeviceDetail.Browser}},
        @{n="Status";e={ if ($_.Status) { "$($_.Status.ErrorCode): $($_.Status.FailureReason)" } else { "" } }} |
      Format-Table -AutoSize

    return $signins
  } catch {
    Write-Warn "Sign-in log query failed (likely missing AuditLog.Read.All): $($_.Exception.Message)"
    return @()
  }
}

function Get-UserOpsAdHints {
  param([Parameter(Mandatory)][object]$AdUser)

  Write-Header "Where is the user logged in? (AD best-effort hints)"
  $llt = $null
  if ($AdUser.LastLogonTimestamp) {
    try { $llt = [DateTime]::FromFileTime($AdUser.LastLogonTimestamp) } catch { $llt = $null }
  }

  [pscustomobject]@{
    SamAccountName   = $AdUser.SamAccountName
    UPN              = $AdUser.UserPrincipalName
    Enabled          = $AdUser.Enabled
    LockedOut        = $AdUser.LockedOut
    LastLogonDate    = $AdUser.LastLogonDate
    LastLogonTS      = $llt
    PasswordLastSet  = $AdUser.PasswordLastSet
  } | Format-List
}

function Get-UserOpsCandidateComputers {
  param(
    [hashtable]$ComputerDiscoveryConfig
  )

  if (-not $ComputerDiscoveryConfig.Enabled) { return @() }

  $max = [int]$ComputerDiscoveryConfig.MaxComputers
  $searchBase = [string]$ComputerDiscoveryConfig.SearchBase

  Write-Header "Discovering candidate computers (AD)"
  try {
    $filter = "Enabled -eq 'True'"
    if ([string]::IsNullOrWhiteSpace($searchBase)) {
      $comps = Get-ADComputer -Filter $filter -Properties LastLogonDate | Sort-Object LastLogonDate -Descending | Select-Object -First $max
    } else {
      $comps = Get-ADComputer -SearchBase $searchBase -Filter $filter -Properties LastLogonDate | Sort-Object LastLogonDate -Descending | Select-Object -First $max
    }

    $names = $comps.Name | Where-Object { $_ } | Select-Object -Unique
    Write-Ok "Candidate computers: $($names.Count)"
    return $names
  } catch {
    Write-Warn "Computer discovery failed: $($_.Exception.Message)"
    return @()
  }
}

function Find-UserOpsLiveSessions {
  param(
    [Parameter(Mandatory)][string]$SamAccountName,
    [Parameter(Mandatory)][string[]]$Computers,
    [int]$ThrottleLimit = 12
  )

  Write-Header "Where is the user logged in? (LAN session scan)"
  Write-Info "Scanning up to $($Computers.Count) computers for sessions matching '$SamAccountName' (Throttle=$ThrottleLimit)"

  $results = [System.Collections.Concurrent.ConcurrentBag[object]]::new()

  $Computers | ForEach-Object -Parallel {
    param($c, $sam, $bag)

    try {
      $raw = qwinsta /server:$c 2>$null
      if (-not $raw) { return }

      foreach ($line in ($raw | Select-Object -Skip 1)) {
        $clean = ($line -replace '\s{2,}', ' ').Trim()
        if (-not $clean) { continue }
        if ($clean -notmatch $sam) { continue }

        $parts = $clean.Split(' ')
        $obj = [pscustomobject]@{
          Computer = $c
          Session  = $parts[0]
          User     = if ($parts.Count -gt 1) { $parts[1] } else { $null }
          Id       = if ($parts.Count -gt 2) { $parts[2] } else { $null }
          State    = if ($parts.Count -gt 3) { $parts[3] } else { $null }
        }
        $bag.Add($obj)
      }
    } catch { }
  } -ThrottleLimit $ThrottleLimit -ArgumentList $SamAccountName, $results

  $out = $results.ToArray()
  if (-not $out -or $out.Count -eq 0) {
    Write-Info "No active sessions found in scanned set."
    return @()
  }

  $out | Sort-Object Computer | Format-Table -AutoSize
  return $out
}

# =========================
# Actions
# =========================

function Get-EntraDevicesForUser {
  param([Parameter(Mandatory)][object]$MgUser)

  Write-Header "Devices for user (Entra registeredDevices)"
  $devices = Get-MgUserRegisteredDevice -UserId $MgUser.Id -All -ErrorAction Stop
  if (-not $devices) { Write-Info "No registered devices found."; return }

  $devices |
    Select-Object DisplayName, OperatingSystem, OperatingSystemVersion, TrustType, ApproximateLastSignInDateTime |
    Format-Table -AutoSize
}

function Reset-ADPassword {
  param(
    [Parameter(Mandatory)][object]$ADUser,
    [Parameter(Mandatory)][string]$LogFile
  )

  Write-Header "Reset AD password"
  $newPass = Read-Host "Enter new password (hidden)" -AsSecureString

  Confirm-HighImpact "This will reset the AD password for $($ADUser.SamAccountName)."
  Set-ADAccountPassword -Identity $ADUser.DistinguishedName -Reset -NewPassword $newPass
  Unlock-ADAccount -Identity $ADUser.DistinguishedName -ErrorAction SilentlyContinue

  $force = Read-Host "Force change password at next logon? (Y/N)"
  if ($force -match '^(Y|y)') {
    Set-ADUser -Identity $ADUser.DistinguishedName -ChangePasswordAtLogon $true
  }

  Write-AuditLog -LogFile $LogFile -Action "Reset-ADPassword" -TargetUser $ADUser.SamAccountName -Details "ForceChangeAtLogon=$force"
  Write-Ok "AD password reset complete."
}

function Revoke-EntraSessions {
  param(
    [Parameter(Mandatory)][object]$MgUser,
    [Parameter(Mandatory)][string]$LogFile
  )

  Write-Header "Revoke Entra sign-in sessions"
  Confirm-HighImpact "This will revoke sign-in sessions for $($MgUser.UserPrincipalName)."
  Revoke-MgUserSignInSession -UserId $MgUser.Id | Out-Null

  Write-AuditLog -LogFile $LogFile -Action "Revoke-EntraSessions" -TargetUser $MgUser.UserPrincipalName -Details "Revoke-MgUserSignInSession"
  Write-Ok "Sign-in sessions revoked."
}

function Reset-EntraMFA {
  param(
    [Parameter(Mandatory)][object]$MgUser,
    [Parameter(Mandatory)][string]$LogFile
  )

  Write-Header "Reset MFA (delete authentication methods)"
  Confirm-HighImpact "HIGH IMPACT: This deletes authentication methods for $($MgUser.UserPrincipalName)."

  $methods = Get-MgUserAuthenticationMethod -UserId $MgUser.Id -All
  if (-not $methods) { Write-Info "No auth methods found."; return }

  foreach ($m in $methods) {
    try {
      Remove-MgUserAuthenticationMethod -UserId $MgUser.Id -AuthenticationMethodId $m.Id -ErrorAction Stop
      Write-Ok "Deleted auth method: $($m.Id)"
    } catch {
      Write-Warn "Could not delete auth method $($m.Id): $($_.Exception.Message)"
    }
  }

  Write-AuditLog -LogFile $LogFile -Action "Reset-EntraMFA" -TargetUser $MgUser.UserPrincipalName -Details "Authentication methods deleted"
  Write-Ok "MFA reset complete."
}

function Add-ADGroupMemberByName {
  param(
    [Parameter(Mandatory)][object]$ADUser,
    [Parameter(Mandatory)][string]$LogFile
  )

  Write-Header "Add to AD security group"
  $group = Read-Host "Enter AD group name (sAMAccountName or DN)"
  Add-ADGroupMember -Identity $group -Members $ADUser.SamAccountName

  Write-AuditLog -LogFile $LogFile -Action "Add-ADGroupMember" -TargetUser $ADUser.SamAccountName -Details "Group=$group"
  Write-Ok "Added $($ADUser.SamAccountName) to $group"
}

function Remove-ADGroupMemberByName {
  param(
    [Parameter(Mandatory)][object]$ADUser,
    [Parameter(Mandatory)][string]$LogFile
  )

  Write-Header "Remove from AD security group"
  $group = Read-Host "Enter AD group name (sAMAccountName or DN)"
  Remove-ADGroupMember -Identity $group -Members $ADUser.SamAccountName -Confirm:$false

  Write-AuditLog -LogFile $LogFile -Action "Remove-ADGroupMember" -TargetUser $ADUser.SamAccountName -Details "Group=$group"
  Write-Ok "Removed $($ADUser.SamAccountName) from $group"
}

function Add-EntraGroupMember {
  param(
    [Parameter(Mandatory)][object]$MgUser,
    [Parameter(Mandatory)][string]$LogFile
  )

  Write-Header "Add to Entra group"
  $groupIdOrName = Read-Host "Enter Entra group ID or display name"

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

  Write-AuditLog -LogFile $LogFile -Action "Add-EntraGroupMember" -TargetUser $MgUser.UserPrincipalName -Details "Group=$($g.DisplayName) ($($g.Id))"
  Write-Ok "Added $($MgUser.UserPrincipalName) to Entra group: $($g.DisplayName)"
}

function Remove-EntraGroupMember {
  param(
    [Parameter(Mandatory)][object]$MgUser,
    [Parameter(Mandatory)][string]$LogFile
  )

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

  Write-AuditLog -LogFile $LogFile -Action "Remove-EntraGroupMember" -TargetUser $MgUser.UserPrincipalName -Details "Group=$($g.DisplayName) ($($g.Id))"
  Write-Ok "Removed $($MgUser.UserPrincipalName) from Entra group: $($g.DisplayName)"
}

function Logoff-UserRemote {
  param(
    [Parameter(Mandatory)][string]$SamAccountName,
    [Parameter(Mandatory)][string[]]$Computers,
    [Parameter(Mandatory)][string]$LogFile
  )

  Write-Header "Remote logoff"
  foreach ($c in $Computers) {
    try {
      Write-Info "Checking sessions on $c ..."
      $raw = qwinsta /server:$c 2>$null
      if (-not $raw) { continue }

      $lines = $raw | Select-Object -Skip 1
      $matches = @()

      foreach ($line in $lines) {
        $clean = ($line -replace '\s{2,}', ' ').Trim()
        if (-not $clean) { continue }
        if ($clean -notmatch $SamAccountName) { continue }

        $parts = $clean.Split(' ')
        $matches += [pscustomobject]@{
          Computer = $c
          SessionName = $parts[0]
          UserName = if ($parts.Count -gt 1) { $parts[1] } else { $null }
          Id = if ($parts.Count -gt 2) { $parts[2] } else { $null }
          State = if ($parts.Count -gt 3) { $parts[3] } else { $null }
        }
      }

      if (-not $matches -or $matches.Count -eq 0) { continue }

      $matches | Format-Table -AutoSize
      Confirm-HighImpact "Logoff matching sessions on $c for '$SamAccountName'?"

      foreach ($m in $matches) {
        if ($m.Id) {
          logoff $m.Id /server:$c
          Write-AuditLog -LogFile $LogFile -Action "RemoteLogoff" -TargetUser $SamAccountName -Details "Computer=$c SessionId=$($m.Id)"
          Write-Ok "Logged off session $($m.Id) on $c"
        }
      }
    } catch {
      Write-Warn "Remote logoff failed on $c: $($_.Exception.Message)"
    }
  }
}

# =========================
# Console UI
# =========================

function Select-UserOpsMode {
  param([string]$Mode)

  if ($Mode) { return $Mode }

  Write-Header "Select mode"
  Write-Host "1) Safe Mode    (password reset, group changes, device visibility, session revoke)"
  Write-Host "2) Nuclear Mode (includes MFA wipe + sign-in logs + aggressive session discovery)"
  $c = Read-Host "Choose 1 or 2"
  switch ($c) {
    "1" { return "Safe" }
    "2" { return "Nuclear" }
    default { return "Safe" }
  }
}

function Show-UserOpsMenu {
  param([string]$Mode)

  Write-Header "PowerUp UserOps Console ($Mode Mode)"
  Write-Host "1) Where is the user logged in? (discovery)"
  Write-Host "2) List Entra registered devices"
  Write-Host "3) Reset AD password"
  Write-Host "4) Revoke Entra sign-in sessions"
  if ($Mode -eq "Nuclear") {
    Write-Host "5) Reset MFA (delete auth methods)  [NUCLEAR]"
    Write-Host "6) Remote logoff (from discovered computers) [NUCLEAR]"
    Write-Host "7) Add to AD group"
    Write-Host "8) Remove from AD group"
    Write-Host "9) Add to Entra group"
    Write-Host "10) Remove from Entra group"
  } else {
    Write-Host "5) Add to AD group"
    Write-Host "6) Remove from AD group"
    Write-Host "7) Add to Entra group"
    Write-Host "8) Remove from Entra group"
  }
  Write-Host "0) Exit"
}

function Start-UserOpsConsole {
  [CmdletBinding()]
  param(
    [string]$Identity,
    [ValidateSet("Safe","Nuclear")]
    [string]$Mode,
    [string]$ConfigPath
  )

  Clear-Host
  Write-Host "==================================================" -ForegroundColor Cyan
  Write-Host " PowerUp UserOps" -ForegroundColor Cyan
  Write-Host " Active Directory + Entra ID" -ForegroundColor Cyan
  Write-Host " One username. Total control." -ForegroundColor Green
  Write-Host "==================================================" -ForegroundColor Cyan
  Write-Host ""

  $cfg = Get-UserOpsConfig -ConfigPath $ConfigPath

  Ensure-Prerequisites

  $Mode = Select-UserOpsMode -Mode $Mode

  $scopes = if ($Mode -eq "Nuclear") { $cfg.GraphScopesNuclear } else { $cfg.GraphScopesSafe }
  Connect-UserOpsGraph -Scopes $scopes

  if (-not $Identity) {
    $Identity = Read-Host "Enter username (samAccountName) or UPN (user@domain.com)"
  }

  $ctx = Resolve-UserOpsUser -Identity $Identity
  if (-not $ctx.ADUser -and -not $ctx.MgUser) { throw "Could not resolve user in AD or Entra." }

  $logFile = New-UserOpsLogger -RootPath $cfg.LogRoot
  Write-Ok "Audit log: $logFile"

  # Pre-compute candidate computers for Nuclear actions (optional)
  $candidateComputers = @()
  if ($Mode -eq "Nuclear" -and $cfg.ComputerDiscovery.Enabled -and $ctx.ADUser) {
    $candidateComputers = Get-UserOpsCandidateComputers -ComputerDiscoveryConfig $cfg.ComputerDiscovery
  }

  while ($true) {
    Show-UserOpsMenu -Mode $Mode
    $choice = Read-Host "Select option"

    try {
      if ($choice -eq "0") { break }

      switch ($choice) {
        "1" {
          # Discovery bundle
          if ($ctx.ADUser) { Get-UserOpsAdHints -AdUser $ctx.ADUser }

          if ($Mode -eq "Nuclear" -and $ctx.MgUser) {
            Get-UserOpsEntraSignIns -MgUser $ctx.MgUser -LookbackHours ([int]$cfg.SignInLogLookbackHours) | Out-Null
          } elseif ($ctx.MgUser) {
            Write-Info "Sign-in logs are available in Nuclear Mode (requires AuditLog.Read.All)."
          }

          if ($Mode -eq "Nuclear" -and $ctx.ADUser -and $candidateComputers.Count -gt 0) {
            if ($cfg.ComputerDiscovery.RequireConfirmation) {
              Confirm-HighImpact "Run LAN session scan on $($candidateComputers.Count) computers? (Can be noisy)"
            }
            Find-UserOpsLiveSessions -SamAccountName $ctx.ADUser.SamAccountName -Computers $candidateComputers -ThrottleLimit ([int]$cfg.ComputerDiscovery.ThrottleLimit) | Out-Null
          }
        }

        "2" {
          if (-not $ctx.MgUser) { Write-Warn "No Entra user resolved."; break }
          Get-EntraDevicesForUser -MgUser $ctx.MgUser
        }

        "3" {
          if (-not $ctx.ADUser) { Write-Warn "No AD user resolved."; break }
          Reset-ADPassword -ADUser $ctx.ADUser -LogFile $logFile
        }

        "4" {
          if (-not $ctx.MgUser) { Write-Warn "No Entra user resolved."; break }
          Revoke-EntraSessions -MgUser $ctx.MgUser -LogFile $logFile
        }

        default {
          if ($Mode -eq "Nuclear") {
            switch ($choice) {
              "5" {
                if (-not $ctx.MgUser) { Write-Warn "No Entra user resolved."; break }
                Reset-EntraMFA -MgUser $ctx.MgUser -LogFile $logFile
              }
              "6" {
                if (-not $ctx.ADUser) { Write-Warn "No AD user resolved."; break }
                if (-not $candidateComputers -or $candidateComputers.Count -eq 0) {
                  Write-Warn "No candidate computers found. Check config ComputerDiscovery."
                  break
                }
                Logoff-UserRemote -SamAccountName $ctx.ADUser.SamAccountName -Computers $candidateComputers -LogFile $logFile
              }
              "7" {
                if (-not $ctx.ADUser) { Write-Warn "No AD user resolved."; break }
                Add-ADGroupMemberByName -ADUser $ctx.ADUser -LogFile $logFile
              }
              "8" {
                if (-not $ctx.ADUser) { Write-Warn "No AD user resolved."; break }
                Remove-ADGroupMemberByName -ADUser $ctx.ADUser -LogFile $logFile
              }
              "9" {
                if (-not $ctx.MgUser) { Write-Warn "No Entra user resolved."; break }
                Add-EntraGroupMember -MgUser $ctx.MgUser -LogFile $logFile
              }
              "10" {
                if (-not $ctx.MgUser) { Write-Warn "No Entra user resolved."; break }
                Remove-EntraGroupMember -MgUser $ctx.MgUser -LogFile $logFile
              }
              default { Write-Warn "Unknown option." }
            }
          } else {
            switch ($choice) {
              "5" {
                if (-not $ctx.ADUser) { Write-Warn "No AD user resolved."; break }
                Add-ADGroupMemberByName -ADUser $ctx.ADUser -LogFile $logFile
              }
              "6" {
                if (-not $ctx.ADUser) { Write-Warn "No AD user resolved."; break }
                Remove-ADGroupMemberByName -ADUser $ctx.ADUser -LogFile $logFile
              }
              "7" {
                if (-not $ctx.MgUser) { Write-Warn "No Entra user resolved."; break }
                Add-EntraGroupMember -MgUser $ctx.MgUser -LogFile $logFile
              }
              "8" {
                if (-not $ctx.MgUser) { Write-Warn "No Entra user resolved."; break }
                Remove-EntraGroupMember -MgUser $ctx.MgUser -LogFile $logFile
              }
              default { Write-Warn "Unknown option." }
            }
          }
        }
      }
    } catch {
      Write-Bad $_.Exception.Message
      Write-AuditLog -LogFile $logFile -Action "ERROR" -TargetUser $Identity -Details $_.Exception.Message
    }
  }

  Write-Ok "Done."
}

Export-ModuleMember -Function Start-UserOpsConsole
