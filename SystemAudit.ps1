# MinerosTech System Audit One-Liner
# Purpose: Generate a hardware and OS report in restricted environments.

$reportPath = "$env:USERPROFILE\Desktop\Audit_Report.txt"

Write-Output "--- SYSTEM AUDIT REPORT ---" > $reportPath
Write-Output "Generated on: $(Get-Date)" >> $reportPath
Write-Output "---------------------------" >> $reportPath

# System Info
Get-ComputerInfo | Select-Object CsName, OsName, OsVersion, CsModel, @{Name="RAM_GB"; Expression={[math]::Round($_.CsTotalPhysicalMemory / 1GB, 2)}} | Out-File -Append $reportPath

# Network Config
Write-Output "`n--- NETWORK CONFIG ---" >> $reportPath
Get-NetIPConfiguration | Out-File -Append $reportPath

Write-Output "`nReport saved to Desktop."
