# PowerUp UserOps

**One username. Total control.**

PowerUp UserOps is a PowerShell operator console that unifies common user administration tasks across:
- **Active Directory (on-prem)**
- **Microsoft Entra ID (Microsoft Graph)**

---

## Features

### Safe Mode
- Resolve user by **samAccountName** or **UPN**
- List Entra registered devices
- Reset AD password and unlock accounts
- Revoke Entra sign-in sessions
- Add / Remove AD and Entra group membership
- Audit logging

### Nuclear Mode
Includes everything in Safe Mode plus:
- Entra **sign-in logs** (requires `AuditLog.Read.All`)
- LAN session discovery (qwinsta scan of candidate computers)
- MFA reset (delete authentication methods) — **high impact**
- Forced remote logoff

---

## Requirements
- Windows PowerShell 5.1+ (or PowerShell 7+)
- RSAT: **ActiveDirectory** module installed
- Microsoft Graph PowerShell module (auto-installed)

---

## Installation

Clone the repository:

```powershell
git clone https://github.com/jmineros/PowerUp-UserOps.git
cd PowerUp-UserOps
