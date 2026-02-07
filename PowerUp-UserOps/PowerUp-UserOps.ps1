<#
.SYNOPSIS
  PowerUp UserOps – Unified user administration console for Active Directory and Entra ID.

.DESCRIPTION
  Entry script. Imports the PowerUp.UserOps module and runs the console UI.

.NOTES
  Author  : Josh Mineros
  Version : 2.0
#>

[CmdletBinding()]
param(
  [string]$Identity,
  [ValidateSet("Safe","Nuclear")]
  [string]$Mode,
  [string]$ConfigPath = "$PSScriptRoot\userops.config.json"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# Import local module (no install needed)
Import-Module (Join-Path $PSScriptRoot "PowerUp.UserOps.psd1") -Force

# Run console
Start-UserOpsConsole -Identity $Identity -Mode $Mode -ConfigPath $ConfigPath
