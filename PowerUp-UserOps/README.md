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

## Installation

Clone the repository:

```powershell
git clone https://github.com/jmineros/PowerUp-UserOps.git
cd PowerUp-UserOps

No global installation is required.  
The script loads the local module automatically.

---

## Configuration

This project uses a local JSON config file.

1. Copy the example config:

```powershell
copy userops.config.example.json userops.config.json


---

## Step 3 — Paste the Usage section

Paste this **below the Configuration section**:

```markdown
---

## Usage

Run interactively:

```powershell
.\PowerUp-UserOps.ps1

.\PowerUp-UserOps.ps1 -Identity user@domain.com
.\PowerUp-UserOps.ps1 -Identity jsmith -Mode Nuclear


---

## Step 4 — Paste Operating Modes

Paste this next:

```markdown
---

## Operating Modes

### Safe Mode (Default)

Designed for day-to-day support tasks with minimal blast radius:
- Password resets
- Session revocation
- Group management
- Device visibility

### Nuclear Mode

Designed for incident response and account compromise:
- MFA reset (authentication method deletion)
- Entra sign-in log visibility
- Active session discovery
- Forced remote logoff

All high-impact actions require explicit confirmation.

---

## Logging & Audit

All actions are written to structured JSON logs:


Each entry includes:
- Timestamp
- Operator username
- Target user
- Action performed
- Additional details

Logs are excluded from source control by default.

---

## Security Notes

This tool performs high-impact identity operations.

- Test in a lab environment first
- Ensure proper RBAC and Graph permissions
- Use Nuclear Mode only for incidents or escalations
- Treat audit logs as sensitive data

---

## License

MIT License

Complete README with installation, configuration, and usage
