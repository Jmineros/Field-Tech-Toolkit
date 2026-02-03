# Field-Tech-Toolkit (MinerosTech)
A collection of "Living off the Land" scripts for on-site IT support and system auditing.

## Professional Context
Designed for use in high-security or restricted environments where external media (USBs) is prohibited. These scripts utilize native Windows binaries (WMIC, PowerShell, Netsh) for rapid system documentation.

## Core Tools
- **SystemAudit.ps1**: Generates a hardware profile including Serial Number, OS version, and RAM specs.
- **Net-Troubleshoot.bat**: Diagnostic tool for verifying gateway connectivity and DNS resolution.
- **Battery-Report.bat**: Generates a native HTML health report for client laptops.

## How to use without USB
1. Open PowerShell on the target machine.
2. Copy the "Raw" link from GitHub Gist/Repo.
3. Execute via: `iwr <URL> | iex`
