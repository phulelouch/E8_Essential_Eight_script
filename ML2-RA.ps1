# ML2-RA Privileged Access Control Verification Script
# Run this script with appropriate permissions

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "ML2-RA Privileged Access Controls Check" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ML2-RA-01 Check privileged accounts without expiration or expiration > 12 months
Write-Host "ML2-RA-01 - Privileged Access 12 Month Revalidation" -ForegroundColor Yellow
Write-Host "Checking for privileged accounts without expiration dates..."

$noExpiry = Get-ADUser -Filter {(admincount -eq 1) -and (enabled -eq $true)} -Properties AccountExpirationDate | Where-Object {$_.AccountExpirationDate -like ""} | Select @{n='Username'; e={$_.SamAccountName}}, @{n='Account Expiration Date'; e={$_.AccountExpirationDate}}, @{n='Enabled'; e={$_.Enabled}}

if ($noExpiry) {
    Write-Host "Found $($noExpiry.Count) privileged accounts with NO expiration date" -ForegroundColor Red
    $noExpiry | ForEach-Object {
        Write-Host "  $($_.Username) - No expiration set - Enabled $($_.Enabled)" -ForegroundColor Red
    }
} else {
    Write-Host "All privileged accounts have expiration dates set" -ForegroundColor Green
}

Write-Host ""
Write-Host "Checking for privileged accounts with expiration greater than 12 months..."

$longExpiry = Get-ADUser -Filter {(admincount -eq 1) -and (enabled -eq $true)} -Properties AccountExpirationDate | Where-Object {$_.AccountExpirationDate -gt (Get-Date).AddMonths(12)} | Select @{n='Username'; e={$_.SamAccountName}}, @{n='Account Expiration Date'; e={$_.AccountExpirationDate}}, @{n='Enabled'; e={$_.Enabled}}

if ($longExpiry) {
    Write-Host "Found $($longExpiry.Count) privileged accounts expiring after 12 months" -ForegroundColor Red
    $longExpiry | ForEach-Object {
        Write-Host "  $($_.Username) - Expires $($_.AccountExpirationDate) - Enabled $($_.Enabled)" -ForegroundColor Red
    }
} else {
    Write-Host "No privileged accounts found with expiration beyond 12 months" -ForegroundColor Green
}
Write-Host ""

# ML2-RA-02 Check privileged accounts inactive for 45+ days
Write-Host "ML2-RA-02 - Privileged Access 45 Day Inactivity Check" -ForegroundColor Yellow
Write-Host "Checking for privileged accounts inactive for more than 45 days..."

$inactiveAccounts = Get-ADUser -Filter {(admincount -eq 1) -and (enabled -eq $true)} -Properties LastLogonDate | Where-Object {$_.LastLogonDate -lt (Get-Date).AddDays(-45) -and $_.LastLogonDate -ne $null} | Select @{n='Username'; e={$_.samaccountname}}, @{n='Last Logon Date'; e={$_.LastLogonDate}}, @{n='Enabled'; e={$_.enabled}}

if ($inactiveAccounts) {
    Write-Host "Found $($inactiveAccounts.Count) privileged accounts inactive for 45+ days" -ForegroundColor Red
    $inactiveAccounts | ForEach-Object {
        $daysSinceLogon = ((Get-Date) - $_.LastLogonDate).Days
        Write-Host "  $($_.Username) - Last logon $($_.LastLogonDate.ToString('yyyy-MM-dd')) ($daysSinceLogon days ago) - Enabled $($_.Enabled)" -ForegroundColor Red
    }
} else {
    Write-Host "All privileged accounts have been active within 45 days" -ForegroundColor Green
}
Write-Host ""

# ML2-RA-03 Check for virtualization
Write-Host "ML2-RA-03 - Privileged Environment Virtualization Check" -ForegroundColor Yellow
Write-Host "Checking if current system is virtualized..."

$computerSystem = Get-WmiObject Win32_ComputerSystem
$bios = Get-WmiObject Win32_BIOS

if ($computerSystem.Model -match "Virtual" -or $computerSystem.Manufacturer -match "VMware|Microsoft Corporation|Xen|VirtualBox") {
    Write-Host "WARNING - System appears to be virtualized" -ForegroundColor Red
    Write-Host "  Manufacturer $($computerSystem.Manufacturer)" -ForegroundColor Red
    Write-Host "  Model $($computerSystem.Model)" -ForegroundColor Red
} else {
    Write-Host "System does not appear to be virtualized" -ForegroundColor Green
    Write-Host "  Manufacturer $($computerSystem.Manufacturer)" -ForegroundColor Gray
    Write-Host "  Model $($computerSystem.Model)" -ForegroundColor Gray
}
Write-Host ""

# ML2-RA-04 Check for jump server configuration
Write-Host "ML2-RA-04 - Jump Server Configuration" -ForegroundColor Yellow
Write-Host "Checking for Remote Desktop Gateway configuration..."

try {
    $rdGateway = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" -ErrorAction SilentlyContinue
    if ($rdGateway.fForceRDGateway -eq 1) {
        Write-Host "RD Gateway is enforced" -ForegroundColor Green
        Write-Host "  Gateway server $($rdGateway.GatewayHostname)" -ForegroundColor Green
    } else {
        Write-Host "RD Gateway is not enforced by policy" -ForegroundColor Yellow
    }
} catch {
    Write-Host "Unable to determine RD Gateway configuration" -ForegroundColor Gray
}
Write-Host ""

# ML2-RA-05 Check LAPS deployment
Write-Host "ML2-RA-05 - Local Administrator Password Management" -ForegroundColor Yellow
Write-Host "Checking LAPS deployment status..."

try {
    $lapsComputers = Get-ADComputer -Filter {ms-Mcs-AdmPwdExpirationTime -like "*"} -Properties ms-Mcs-AdmPwdExpirationTime | Measure-Object
    $totalComputers = Get-ADComputer -Filter {Enabled -eq $true} | Measure-Object
    
    Write-Host "Total enabled computers in AD $($totalComputers.Count)"
    Write-Host "Computers with LAPS configured $($lapsComputers.Count)"
    
    if ($totalComputers.Count -gt 0) {
        $lapsPercentage = [math]::Round(($lapsComputers.Count / $totalComputers.Count) * 100, 2)
        Write-Host "LAPS coverage $lapsPercentage%" -ForegroundColor $(if ($lapsPercentage -lt 90) { "Yellow" } else { "Green" })
    }
} catch {
    Write-Host "Unable to query LAPS status - ensure LAPS schema extension is installed" -ForegroundColor Gray
}

Write-Host ""
Write-Host "Checking service account password age..."

$PassLastSetTimeFrame = (Get-Date).AddMonths(-12)
$oldServiceAccounts = Get-ADUser -Filter "enabled -eq 'true' -and SamAccountName -like 'svc_*'" -Properties pwdlastset | Where-Object{$_.pwdlastset -like '0' -or ([datetime]::FromFileTime($_.pwdLastSet) -lt $PassLastSetTimeFrame)} | Select-Object SAMAccountName, @{name ="pwdLastSet"; expression={([datetime]::FromFileTime($_.pwdLastSet))}}

if ($oldServiceAccounts) {
    Write-Host "Found $($oldServiceAccounts.Count) service accounts with passwords older than 12 months" -ForegroundColor Red
    $oldServiceAccounts | ForEach-Object {
        if ($_.pwdLastSet -eq [datetime]::FromFileTime(0)) {
            Write-Host "  $($_.SAMAccountName) - Password NEVER set" -ForegroundColor Red
        } else {
            $passwordAge = ((Get-Date) - $_.pwdLastSet).Days
            Write-Host "  $($_.SAMAccountName) - Password set $($_.pwdLastSet.ToString('yyyy-MM-dd')) ($passwordAge days ago)" -ForegroundColor Red
        }
    }
} else {
    Write-Host "All service account passwords are less than 12 months old" -ForegroundColor Green
}
Write-Host ""

# ML2-RA-06 Check audit logging for privileged access
Write-Host "ML2-RA-06 - Privileged Access Event Logging" -ForegroundColor Yellow
Write-Host "Checking audit policy for privileged access events..."

$auditPolicy = auditpol /get /subcategory:"Special Logon" /r | ConvertFrom-Csv | Where-Object {$_."Subcategory" -eq "Special Logon"}
if ($auditPolicy."Inclusion Setting" -match "Success") {
    Write-Host "Event ID 4672 (Special privileges assigned) logging is ENABLED" -ForegroundColor Green
} else {
    Write-Host "Event ID 4672 (Special privileges assigned) logging is DISABLED" -ForegroundColor Red
}

$auditPolicy = auditpol /get /subcategory:"Logon" /r | ConvertFrom-Csv | Where-Object {$_."Subcategory" -eq "Logon"}
if ($auditPolicy."Inclusion Setting" -match "Failure") {
    Write-Host "Event ID 4625 (Failed logon) logging is ENABLED" -ForegroundColor Green
} else {
    Write-Host "Event ID 4625 (Failed logon) logging is DISABLED" -ForegroundColor Red
}
Write-Host ""

# ML2-RA-07 Check audit logging for account management
Write-Host "ML2-RA-07 - Account Management Event Logging" -ForegroundColor Yellow
Write-Host "Checking audit policy for account management events..."

$auditPolicy = auditpol /get /subcategory:"User Account Management" /r | ConvertFrom-Csv | Where-Object {$_."Subcategory" -eq "User Account Management"}
if ($auditPolicy."Inclusion Setting" -match "Success") {
    Write-Host "Event ID 4738 (User account modified) logging is ENABLED" -ForegroundColor Green
} else {
    Write-Host "Event ID 4738 (User account modified) logging is DISABLED" -ForegroundColor Red
}

$auditPolicy = auditpol /get /subcategory:"Security Group Management" /r | ConvertFrom-Csv | Where-Object {$_."Subcategory" -eq "Security Group Management"}
if ($auditPolicy."Inclusion Setting" -match "Success") {
    Write-Host "Event IDs 4728/4729/4737 (Group management) logging is ENABLED" -ForegroundColor Green
} else {
    Write-Host "Event IDs 4728/4729/4737 (Group management) logging is DISABLED" -ForegroundColor Red
}
Write-Host ""

# ML2-RA-08 Check event log protection
Write-Host "ML2-RA-08 - Event Log Protection" -ForegroundColor Yellow
Write-Host "Checking event log permissions..."

$logs = @("Application", "Security", "System")
foreach ($logName in $logs) {
    try {
        $log = Get-WmiObject -Class Win32_NTEventlogFile | Where-Object {$_.LogFileName -eq $logName}
        $maxSize = [math]::Round($log.MaxFileSize / 1MB, 2)
        Write-Host "$logName log - Max size ${maxSize}MB" -ForegroundColor Gray
    } catch {
        Write-Host "Unable to query $logName log settings" -ForegroundColor Gray
    }
}

# Check if clearing event logs is audited
$auditPolicy = auditpol /get /subcategory:"Audit Policy Change" /r | ConvertFrom-Csv | Where-Object {$_."Subcategory" -eq "Audit Policy Change"}
if ($auditPolicy."Inclusion Setting" -match "Success") {
    Write-Host "Audit policy changes are being logged" -ForegroundColor Green
} else {
    Write-Host "Audit policy changes are NOT being logged" -ForegroundColor Yellow
}
Write-Host ""

# ML2-RA-09 to ML2-RA-13 are process checks
Write-Host "ML2-RA-09 to ML2-RA-13 - Incident Response Process Checks" -ForegroundColor Yellow
Write-Host "These controls require manual verification of"
Write-Host "  - Internet-facing server log analysis procedures"
Write-Host "  - Cyber security event analysis processes"
Write-Host "  - Incident reporting to CISO/delegates"
Write-Host "  - Incident reporting to ASD via ReportCyber"
Write-Host "  - Cyber security incident response plan activation"
Write-Host ""

# Summary
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Scan Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Note This script provides automated checks for ML2-RA controls." -ForegroundColor White
Write-Host "Manual verification and additional testing may be required." -ForegroundColor White
Write-Host "Some checks require domain administrator privileges to run successfully." -ForegroundColor White
Write-Host ""
Write-Host "Critical findings should be investigated immediately." -ForegroundColor Red
Write-Host "Review yellow warnings for potential improvements." -ForegroundColor Yellow
