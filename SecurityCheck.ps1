# MINEROSTECH BLUE TEAM SECURITY AUDIT
# Purpose: High-level overview of local security posture for freelance calls.

$reportPath = "$env:USERPROFILE\Desktop\Security_Check.txt"
Write-Output "--- SECURITY AUDIT: $($env:COMPUTERNAME) ---" > $reportPath
Write-Output "Generated: $(Get-Date)" >> $reportPath
Write-Output "--------------------------------------------" >> $reportPath

# 1. Check for Local Administrators
Write-Output "`n[1/3] CHECKING LOCAL ADMINISTRATORS" >> $reportPath
Write-Output "Authorized personnel only. Review any unknown accounts." >> $reportPath
Get-LocalGroupMember -Group "Administrators" | Select-Object Name, PrincipalSource | Out-File -Append $reportPath

# 2. Check Windows Firewall Status
Write-Output "`n[2/3] CHECKING FIREWALL STATUS" >> $reportPath
Get-NetFirewallProfile | Select-Object Name, Enabled | Out-File -Append $reportPath

# 3. List Recently Installed Programs (Last 30 Days)
Write-Output "`n[3/3] RECENTLY INSTALLED PROGRAMS (30 Days)" >> $reportPath
$limitDate = (Get-Date).AddDays(-30)
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | `
    Where-Object { $_.InstallDate -ge $limitDate.ToString("yyyyMMdd") } | `
    Select-Object DisplayName, InstallDate | Out-File -Append $reportPath

Write-Output "`nAudit Complete. Report saved to Desktop."
