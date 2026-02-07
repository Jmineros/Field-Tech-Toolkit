# Field-Tech-Toolkit (MinerosTech)

A specialized collection of scripts and documentation for **on-site IT infrastructure support**, **system auditing**, and **network diagnostics**.

---

## Professional Context

This toolkit is engineered for **high-security and restricted environments** where external media (USB drives) are prohibited due to data protection and compliance requirements.

It prioritizes **“Living off the Land” (LOLBins)** techniques—leveraging native Windows binaries (Batch and PowerShell) to perform **non-invasive diagnostics** and **read-only audits** without leaving artifacts behind.

---

## Repository Contents

### 🛠️ Automation Scripts

- **Connectivity.bat**  
  CCNA-aligned network diagnostic utility that validates **Layer 1–3 connectivity** by testing:
  - Local TCP/IP stack  
  - Default gateway reachability  
  - External DNS resolution  

- **PrinterReset.bat**  
  Field-focused remediation tool for clearing corrupted print queues and resetting the **Windows Print Spooler** service.  
  Commonly used for resolving stuck jobs on **Epson and industrial field printers**.

- **SecurityCheck.ps1**  
  Proactive *Blue Team* audit script that:
  - Enumerates local administrators  
  - Verifies Windows Firewall status  
  - Logs recently installed software  
  - Assesses baseline local security posture  

---

### 📋 Field Documentation

- **Site-Checklist.md**  
  A standardized **SOP (Standard Operating Procedure)** for field technicians, ensuring:
  - Required physical tools are present (RJ45, crimpers, cable testers)
  - Administrative prerequisites are verified (Security+, site access, approvals)
  - Pre-arrival checks are completed to reduce onsite risk and delays

---

## Usage in Restricted Environments

For sites where **USB access is blocked** or removable media is prohibited:

1. Open **PowerShell** on the target system
2. Navigate to this repository on a **mobile device or separate workstation**
3. Copy the **Raw** script URL
4. Execute directly in memory:

```powershell
iwr <Raw_Script_URL> | iex

---

## ✅ What to do next (very simple)

1. Paste the block above into `README.md`
2. Save the file
3. Refresh GitHub

### You should see:
- The PowerShell command in a grey box
- “Disclaimer” as a normal header
- No grey text below it

That’s it.  
You are **finished** with this section.

