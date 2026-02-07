# PowerUp UserOps

**One username. Total control.**

PowerUp UserOps is a PowerShell operator console that unifies common user administration tasks across:
- **Active Directory (on-prem)**
- **Microsoft Entra ID (Microsoft Graph)**

## Features
### Safe Mode
- Resolve user by **samAccountName** or **UPN**
- List Entra registered devices
- Reset AD password + unlock
- Revoke Entra sign-in sessions
- Add/Remove AD + Entra group membership
- Audit logging

### Nuclear Mode
Includes everything in Safe Mode plus:
- Entra **sign-in logs** (requires `AuditLog.Read.All`)
- LAN session discovery (qwinsta scan of candidate computers)
- MFA reset (delete authentication methods) — **high impact**
- Remote logoff

## Requirements
- Windows PowerShell 5.1+ (or PowerShell 7+)
- RSAT: **ActiveDirectory** module installed
- Microsoft Graph PowerShell module (auto-installed)

## Configuration

This project uses a local JSON config file.

1. Copy the example config:
```powershell
copy userops.config.example.json userops.config.json

## Installation

Clone the repository:

```powershell
git clone https://github.com/<your-username>/PowerUp-UserOps.git
cd PowerUp-UserOps

## Usage
```powershell
.\PowerUp-UserOps.ps1 -Identity user@domain.com -Mode Nuclear

