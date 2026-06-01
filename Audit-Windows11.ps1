<#
.SYNOPSIS
    Windows 11 Endpoint Security Checklist Compliance Auditor
.DESCRIPTION
    Automates the verification of standard technical controls listed in the 
    Windows Endpoint Checklist spreadsheet and outputs the results to a single HTML document.
.NOTES
    Must be run in an elevated PowerShell session (Run as Administrator).
#>

# 0. Check for Administrator Privileges
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Error "CRITICAL: This script must be run as an Administrator. Please relaunch PowerShell as Administrator."
    Exit
}

# Define report path and metadata
$ReportPath = "$PSScriptRoot\Windows11_Audit_Report.html"
if ([string]::IsNullOrEmpty($PSScriptRoot)) { $ReportPath = "C:\Windows11_Audit_Report.html" }

$ReportTitle = "Windows 11 Endpoint Security Audit & Compliance Report"
$TimeStamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$ComputerName = $env:COMPUTERNAME

Write-Host "Initializing Security Audit for Host: $ComputerName..." -ForegroundColor Cyan

# 1. HTML & CSS Template Layout
$HTMLContent = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>$ReportTitle</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; background-color: #f4f6f9; color: #333; margin: 0; padding: 30px; }
        .container { max-width: 1200px; margin: 0 auto; background: #ffffff; padding: 35px; border-radius: 10px; box-shadow: 0 4px 20px rgba(0,0,0,0.08); }
        h1 { color: #002855; border-bottom: 4px solid #00509d; padding-bottom: 12px; font-size: 28px; margin-top: 0; }
        h2 { color: #00509d; margin-top: 40px; border-bottom: 2px solid #eef2f7; padding-bottom: 6px; font-size: 20px; }
        .meta-box { background: #eef2f7; padding: 15px 20px; border-left: 6px solid #00509d; margin-bottom: 30px; border-radius: 0 6px 6px 0; }
        .meta-box p { margin: 6px 0; font-size: 14px; }
        table { border-collapse: collapse; width: 100%; background: #ffffff; margin-top: 12px; margin-bottom: 20px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }
        th { background-color: #00509d; color: #ffffff; text-align: left; padding: 12px 14px; font-size: 14px; font-weight: 600; }
        td { padding: 10px 14px; border-bottom: 1px solid #eef2f7; font-size: 13.5px; vertical-align: top; }
        tr:nth-child(even) { background-color: #f8fafc; }
        tr:hover { background-color: #f1f5f9; }
        pre { background-color: #1e1e1e; color: #d4d4d4; padding: 15px; border-radius: 6px; overflow-x: auto; font-family: 'Consolas', 'Courier New', monospace; font-size: 13px; max-height: 350px; line-height: 1.5; }
        .badge { padding: 4px 8px; border-radius: 4px; font-weight: bold; font-size: 11.5px; display: inline-block; }
        .badge-enabled { background-color: #d1fae5; color: #065f46; }
        .badge-disabled { background-color: #fee2e2; color: #991b1b; }
        .footer { text-align: center; margin-top: 50px; font-size: 12px; color: #888; border-top: 1px solid #e5e5e5; padding-top: 20px; }
    </style>
</head>
<body>
<div class="container">
    <h1>$ReportTitle</h1>
    <div class="meta-box">
        <p><strong>Target Host Name:</strong> $ComputerName</p>
        <p><strong>Audit Execution Time:</strong> $TimeStamp</p>
        <p><strong>Platform:</strong> Microsoft Windows 11</p>
    </div>
"@

# Helper to bundle components cleanly
function Add-ReportSection {
    param([string]$SectionTitle, [string]$Content)
    return "<h2>$SectionTitle</h2>`n$Content"
}

# --- CONTROL 1: SYSTEM INFORMATION ---
Write-Host "1/15 Auditing System Information..." -ForegroundColor White
$SysInfoHTML = try {
    $os = Get-CimInstance Win32_OperatingSystem
    $cs = Get-CimInstance Win32_ComputerSystem
    $uptime = (Get-Date) - $os.LastBootUpTime
    $uptimeString = "{0} Days, {1} Hours, {2} Minutes" -f $uptime.Days, $uptime.Hours, $uptime.Minutes
    
    @"
    <table>
        <tr><th style='width:30%'>Property</th><th>Value</th></tr>
        <tr><td><strong>OS Name</strong></td><td>$($os.Caption)</td></tr>
        <tr><td><strong>Version / Build</strong></td><td>$($os.Version) (Build $($os.BuildNumber))</td></tr>
        <tr><td><strong>Architecture</strong></td><td>$($os.OSArchitecture)</td></tr>
        <tr><td><strong>System Uptime</strong></td><td>$uptimeString</td></tr>
        <tr><td><strong>Domain/Workgroup</strong></td><td>$($cs.Domain)</td></tr>
    </table>
"@
} catch { "<pre>Error gathering system info: $_</pre>" }
$HTMLContent += Add-ReportSection "1. System Information (OS Version, Build, Uptime)" $SysInfoHTML


# --- CONTROL 2: INSTALLED HOTFIXES / PATCHES ---
Write-Host "2/15 Auditing Installed Patches..." -ForegroundColor White
$HotfixHTML = try {
    $hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object HotFixID, Description, InstalledBy, InstalledOn -First 12
    if ($hotfixes) { $hotfixes | ConvertTo-Html -Fragment } 
    else { "<p>No recently registered hotfixes found via WMI Query.</p>" }
} catch { "<pre>Error checking patches: $_</pre>" }
$HTMLContent += Add-ReportSection "2. Installed Hotfixes & Updates (Latest 12)" $HotfixHTML


# --- CONTROL 3: USER ACCOUNTS STATUS ---
Write-Host "3/15 Auditing Local User Accounts..." -ForegroundColor White
$UserAccountsHTML = try {
    Get-LocalUser | Select-Object Name, Enabled, PasswordRequired, LastLogon, Description | ConvertTo-Html -Fragment
} catch { "<pre>Error checking local user accounts: $_</pre>" }
$HTMLContent += Add-ReportSection "3. Local User Accounts & Account Status" $UserAccountsHTML


# --- CONTROL 4: ADMINISTRATORS GROUP MEMBERS ---
Write-Host "4/15 Auditing Administrators Group..." -ForegroundColor White
$AdminMembersHTML = try {
    Get-LocalGroupMember -Group "Administrators" | Select-Object Name, PrincipalSource, ObjectClass | ConvertTo-Html -Fragment
} catch { "<pre>Error validating local Administrators group: $_</pre>" }
$HTMLContent += Add-ReportSection "4. Privileged Group Members (Administrators)" $AdminMembersHTML


# --- CONTROL 5: ACTIVE SESSIONS ---
Write-Host "5/15 Auditing Logged-on Users..." -ForegroundColor White
$ActiveSessionsHTML = try {
    $quser = C:\Windows\System32\query.exe user 2>&1 | Out-String
    "<pre>$quser</pre>"
} catch { "<pre>No active alternative user sessions or query command execution context issue: $_</pre>" }
$HTMLContent += Add-ReportSection "5. Active Interactive Sessions" $ActiveSessionsHTML


# --- CONTROL 6: PASSWORD POLICY ---
Write-Host "6/15 Auditing Password Security Policies..." -ForegroundColor White
$PasswordPolicyHTML = try {
    $netAccounts = net accounts 2>&1 | Out-String
    "<pre>$netAccounts</pre>"
} catch { "<pre>Error querying 'net accounts' system configuration: $_</pre>" }
$HTMLContent += Add-ReportSection "6. Account Password Policies" $PasswordPolicyHTML


# --- CONTROL 7: ANTIVIRUS / WINDOWS DEFENDER STATUS ---
Write-Host "7/15 Auditing Antivirus Controls..." -ForegroundColor White
$DefenderHTML = try {
    $def = Get-MpComputerStatus
    @"
    <table>
        <tr><th style='width:40%'>Antivirus Protection Engine Component</th><th>Status Value</th></tr>
        <tr><td>Antivirus Enabled</td><td>$($def.AntivirusEnabled)</td></tr>
        <tr><td>Antispyware Enabled</td><td>$($def.AntispywareEnabled)</td></tr>
        <tr><td>Real-Time Protection Status</td><td>$($def.RealTimeProtectionEnabled)</td></tr>
        <tr><td>Behavior Monitoring Status</td><td>$($def.BehaviorMonitorEnabled)</td></tr>
        <tr><td>IoAV Local Script Scan (Download File Tracking)</td><td>$($def.IoAVLocalScanEnabled)</td></tr>
        <tr><td>Defender Signature Update Version</td><td>$($def.AntivirusSignatureVersion)</td></tr>
        <tr><td>Last Signature Sync Timestamp</td><td>$($def.AntivirusSignatureLastUpdated)</td></tr>
    </table>
"@
} catch { "<pre>Error pulling Windows Defender configurations (Third-party EDR may be override active): $_</pre>" }
$HTMLContent += Add-ReportSection "7. Windows Defender & EDR Status" $DefenderHTML


# --- CONTROL 8: WINDOWS FIREWALL STATE ---
Write-Host "8/15 Auditing Firewall Profiles..." -ForegroundColor White
$FirewallHTML = try {
    Get-NetFirewallProfile | Select-Object Name, Enabled, ActionInbound, ActionOutbound | ConvertTo-Html -Fragment
} catch { "<pre>Error pulling Advanced Firewall Engine profiles: $_</pre>" }
$HTMLContent += Add-ReportSection "8. Windows Host Firewall Profile State" $FirewallHTML


# --- CONTROL 9: RUNNING SERVICES ---
Write-Host "9/15 Auditing Active Background Services..." -ForegroundColor White
$ServicesHTML = try {
    Get-Service | Where-Object {$_.Status -eq 'Running'} | Select-Object Name, DisplayName, Status | Sort-Object Name | Select-Object -First 25 | ConvertTo-Html -Fragment
} catch { "<pre>Error processing system services matrix: $_</pre>" }
$HTMLContent += Add-ReportSection "9. Core Active Services (First 25 Entries Sample)" $ServicesHTML


# --- CONTROL 10: ACTIVE PROCESS NETWORK CONNECTIONS ---
Write-Host "10/15 Auditing Socket Connections..." -ForegroundColor White
$NetworkConnsHTML = try {
    $connections = Get-NetTCPConnection -State Established -ErrorAction SilentlyContinue | 
        Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess -First 25
    if ($connections) { $connections | ConvertTo-Html -Fragment } 
    else { "<p>No active ESTABLISHED external sockets mapped at runtime.</p>" }
} catch { "<pre>Error parsing network connection tables: $_</pre>" }
$HTMLContent += Add-ReportSection "10. Processes with Established Network Sockets" $NetworkConnsHTML


# --- CONTROL 11: IP ADAPTERS AND CONFIGURATIONS ---
Write-Host "11/15 Auditing Network Interface Profiles..." -ForegroundColor White
$NetworkConfigHTML = try {
    Get-NetIPAddress -AddressFamily IPv4 | Where-Object {$_.IPAddress -notlike "127*"} | 
        Select-Object InterfaceAlias, IPAddress, InterfaceMetric | ConvertTo-Html -Fragment
} catch { "<pre>Error scanning IP Adapter assignments: $_</pre>" }
$HTMLContent += Add-ReportSection "11. Network Interface IP Assignments (IPv4 Address Matrix)" $NetworkConfigHTML


# --- CONTROL 12: SMB NETWORK SHARED FOLDERS ---
Write-Host "12/15 Auditing Network Shares..." -ForegroundColor White
$SharesHTML = try {
    Get-SmbShare | Select-Object Name, Path, Description, Special | ConvertTo-Html -Fragment
} catch { "<pre>Error auditing system file sharing directories: $_</pre>" }
$HTMLContent += Add-ReportSection "12. Shared Folders & Active Net Shares" $SharesHTML


# --- CONTROL 13: RECENT SECURITY EVENT LOGS ---
Write-Host "13/15 Extracting Critical Security Logs..." -ForegroundColor White
$EventLogsHTML = try {
    $logs = Get-WinEvent -LogName Security -MaxEvents 20 -ErrorAction SilentlyContinue | 
        Select-Object TimeCreated, Id, RecordId, TaskDisplayName | ConvertTo-Html -Fragment
    if ($logs) { $logs } else { "<p>Zero audit log entries found or Security logs restricted.</p>" }
} catch { "<pre>Log collection failure (Ensure standard Event Logging Service configuration): $_</pre>" }
$HTMLContent += Add-ReportSection "13. Host Security Event Log Summary (Last 20 Registered Events)" $EventLogsHTML


# --- CONTROL 14: DRIVE ENCRYPTION / BITLOCKER STATUS ---
Write-Host "14/15 Querying Disk Protection..." -ForegroundColor White
$BitLockerHTML = try {
    $bl = Get-BitLockerVolume -ErrorAction SilentlyContinue
    if ($bl) { $bl | Select-Object MountPoint, VolumeType, ProtectionStatus, EncryptionPercentage, VolumeStatus | ConvertTo-Html -Fragment } 
    else { "<p>No logical encryption properties mapped. BitLocker might be unconfigured or unsupported on Windows 11 Home.</p>" }
} catch { "<pre>Error pulling volume protection encryption schemas: $_</pre>" }
$HTMLContent += Add-ReportSection "14. BitLocker Drive Encryption Status" $BitLockerHTML


# --- CONTROL 15: DATE, TIME & TIMEZONE MATCHING ---
Write-Host "15/15 Auditing Time Synchronization Context..." -ForegroundColor White
$TimezoneHTML = try {
    $tz = Get-TimeZone
    $date = Get-Date -Format "F"
    @"
    <table>
        <tr><th style='width:30%'>Parameter</th><th>Configured Setting</th></tr>
        <tr><td>Current Node System Time</td><td>$date</td></tr>
        <tr><td>Standard Timezone Registry Identifier</td><td>$($tz.Id)</td></tr>
        <tr><td>Localization Display Text</td><td>$($tz.DisplayName)</td></tr>
        <tr><td>Daylight Savings Tracking Mode</td><td>$($tz.SupportsDaylightSavingTime)</td></tr>
    </table>
"@
} catch { "<pre>Error querying host regional configurations: $_</pre>" }
$HTMLContent += Add-ReportSection "15. Date, Time, and Regional Location Configuration" $TimezoneHTML


# --- CONTROL 16: EXTERNAL STORAGE USB CONTROL REGISTRY KEY ---
Write-Host "Auditing Registry Hardware USB Block Rules..." -ForegroundColor White
$USBHTML = try {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR"
    if (Test-Path $regPath) {
        $startVal = (Get-ItemProperty -Path $regPath).Start
        # Value 3 = Enabled (Risky/Default), Value 4 = Disabled (Secure Infrastructure)
        $statusText = if ($startVal -eq 4) { "<span class='badge badge-disabled'>Restricted (Mass Storage Blocked - Value 4)</span>" } else { "<span class='badge badge-enabled'>Unrestricted (Value $startVal)</span>" }
        @"
        <table>
            <tr><th>Registry Control Path</th><th>Registry Directive</th><th>Value Key</th><th>Operational Audit Assessment</th></tr>
            <tr><td>HKLM:\SYSTEM\CurrentControlSet\Services\USBSTOR</td><td>Start</td><td>$startVal</td><td>$statusText</td></tr>
        </table>
"@
    } else { "<p>USBSTOR kernel entry path missing from standard structural configuration tree.</p>" }
} catch { "<pre>Error testing storage interface restriction records: $_</pre>" }
$HTMLContent += Add-ReportSection "16. External USB Storage Device Restrictions" $USBHTML


# --- CONTROL 17: INSTALLED APPLICATION ENVIRONMENT PREVIEWS ---
Write-Host "Compiling installed application data index..." -ForegroundColor White
$SoftwareHTML = try {
    $apps = Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*, HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* -ErrorAction SilentlyContinue |
        Where-Object {$_.DisplayName} | Select-Object DisplayName, DisplayVersion, Publisher | Sort-Object DisplayName | Select-Object -First 30
    if ($apps) { $apps | ConvertTo-Html -Fragment } 
    else { "<p>No primary baseline entries registered in structural uninstallation records.</p>" }
} catch { "<pre>Error parsing core package lists: $_</pre>" }
$HTMLContent += Add-ReportSection "17. Installed Software Inventory (First 30 App Entries Sample)" $SoftwareHTML


# --- CONTROL 18: APPLIED USER GROUP POLICY OBJECT SLOTS ---
Write-Host "Evaluating policy objects sync..." -ForegroundColor White
$GPHTML = try {
    $gpData = gpresult /r /scope user 2>&1 | Select-Object -First 22 | Out-String
    "<p>Short preview of immediate Local/Domain Group Policy Objects hierarchy evaluated on this endpoint:</p><pre>$gpData</pre>"
} catch { "<pre>Error compiling active group policy object definitions: $_</pre>" }
$HTMLContent += Add-ReportSection "18. Applied Group Policy Objects Summary" $GPHTML


# Append Document Footers
$HTMLContent += @"
    <div class="footer">
        <p>Report compiled automatically via Windows 11 Security Endpoint Audit Routine Engine &copy; $(Get-Date -Format "yyyy")</p>
    </div>
</div>
</body>
</html>
"@

# Save final payload structure to target file path
try {
    Set-Content -Path $ReportPath -Value $HTMLContent -Force
    Write-Host "`n[SUCCESS] Security audit complete! Report generated successfully at: $ReportPath" -ForegroundColor Green
} catch {
    Write-Error "Failed to export report matrix contents out to file path: $ReportPath. Details: $_"
}