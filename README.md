# Field-Tech-Toolkit (MinerosTech)
A specialized collection of scripts and documentation for on-site IT infrastructure support, system auditing, and network diagnostics.

## Professional Context
This toolkit is engineered for high-security and restricted environments where external media (USBs) is prohibited for data protection and security compliance. It prioritizes "Living off the Land" techniques—utilizing native Windows binaries (Batch and PowerShell) to perform non-invasive diagnostics and audits.

## Repository Contents

### 🛠️ Automation Scripts
- **Connectivity.bat**: A CCNA-aligned network diagnostic tool. It verifies Layer 1-3 connectivity by testing the local stack, default gateway, and external DNS resolution.
- **PrinterReset.bat**: A specialized utility for clearing corrupted print queues and resetting the Windows Print Spooler service—essential for resolving stuck jobs on Epson field printers.
- **SecurityCheck.ps1**: A proactive "Blue Team" audit script. It identifies local administrators, verifies firewall status, and logs recently installed software to ensure local security posture.

### 📋 Field Documentation
- **Site-Checklist.md**: A standardized SOP (Standard Operating Procedure) for field work. It ensures all physical hardware (RJ45, crimpers, testers) and administrative requirements (Security+ credentials) are verified before site arrival.

## Usage in Restricted Environments
For sites where USB access is blocked:
1. Open PowerShell on the target machine.
2. Navigate to this repository on a mobile device or separate workstation to obtain the "Raw" script URL.
3. Download and execute directly in memory:
   `iwr <Raw_Script_URL> | iex`

## Standards & Compliance
All tools are designed to align with Canadian network and privacy standards (PIPEDA/PCI DSS) by ensuring read-only data collection and zero-footprint operations where possible.
