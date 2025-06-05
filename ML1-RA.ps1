# ML1-RA Privileged Access Control Verification Script
# Run this script with appropriate permissions

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "ML1-RA Privileged Access Controls Check" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ML1-RA-01 Check for privileged access documentation
Write-Host "ML1-RA-01 - Privileged Access Request Validation" -ForegroundColor Yellow
Write-Host "Checking for privileged access documentation..."

# Check for common privileged groups
$privGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators", "Account Operators", "Server Operators", "Print Operators", "Backup Operators")
Write-Host "Listing privileged groups in domain"
foreach ($group in $privGroups) {
    try {
        $members = Get-ADGroupMember -Identity $group -ErrorAction SilentlyContinue
        if ($members) {
            Write-Host "  $group has $($members.Count) members" -ForegroundColor Green
        }
    } catch {
        Write-Host "  $group not found or access denied" -ForegroundColor Gray
    }
}
Write-Host ""

# ML1-RA-02 Check for separate privileged accounts
Write-Host "ML1-RA-02 - Dedicated Privileged Accounts" -ForegroundColor Yellow
Write-Host "Checking for users with adminCount=1 (privileged flag)..."

$privUsers = Get-ADUser -Filter {admincount -eq 1} -Properties admincount, enabled | Where-Object {$_.enabled -eq $true}
Write-Host "Found $($privUsers.Count) enabled privileged accounts"

# Check for naming convention (common patterns for admin accounts)
$adminPatterns = @("adm_*", "admin_*", "svc_*", "_admin", "-admin", "administrator*")
$suspiciousAccounts = @()

foreach ($user in $privUsers) {
    $isAdminNamed = $false
    foreach ($pattern in $adminPatterns) {
        if ($user.SamAccountName -like $pattern) {
            $isAdminNamed = $true
            break
        }
    }
    if (-not $isAdminNamed) {
        $suspiciousAccounts += $user.SamAccountName
    }
}

if ($suspiciousAccounts.Count -gt 0) {
    Write-Host "Warning - Privileged accounts without admin naming convention" -ForegroundColor Red
    $suspiciousAccounts | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
}
Write-Host ""

# ML1-RA-03 Check privileged accounts with email access
Write-Host "ML1-RA-03 - Internet/Email Restrictions for Privileged Accounts" -ForegroundColor Yellow
Write-Host "Checking privileged accounts with email addresses..."

$privWithEmail = Get-ADUser -Filter {(admincount -eq 1) -and (emailaddress -like "*") -and (enabled -eq $true)} -Properties EmailAddress, SamAccountName
if ($privWithEmail) {
    Write-Host "Found $($privWithEmail.Count) privileged accounts with email addresses" -ForegroundColor Red
    $privWithEmail | ForEach-Object {
        Write-Host "  $($_.SamAccountName) - $($_.EmailAddress)" -ForegroundColor Red
    }
} else {
    Write-Host "No privileged accounts found with email addresses" -ForegroundColor Green
}

# Check for proxy settings
Write-Host "Checking system proxy configuration..."
$proxySettings = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings" -ErrorAction SilentlyContinue
if ($proxySettings.ProxyEnable -eq 1) {
    Write-Host "  Proxy is enabled - Server $($proxySettings.ProxyServer)" -ForegroundColor Yellow
} else {
    Write-Host "  Proxy is disabled" -ForegroundColor Green
}
Write-Host ""

# ML1-RA-04 Check for service accounts
Write-Host "ML1-RA-04 - Limited Online Service Access" -ForegroundColor Yellow
Write-Host "Checking for service accounts..."

$serviceAccounts = Get-ADUser -Filter {(admincount -eq 1) -and (SamAccountName -like "svc_*")} -Properties Description, enabled
Write-Host "Found $($serviceAccounts.Count) service accounts with privileged access"
$serviceAccounts | ForEach-Object {
    Write-Host "  $($_.SamAccountName) - Enabled $($_.Enabled)" -ForegroundColor Gray
}
Write-Host ""

# ML1-RA-05 Check for separate environments
Write-Host "ML1-RA-05 - Separate Operating Environments" -ForegroundColor Yellow
Write-Host "Checking current user context..."

$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
$isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

Write-Host "Current user $($currentUser.Name)"
Write-Host "Administrator privileges $isAdmin"

# Check for RDP restrictions
Write-Host "Checking Remote Desktop user rights..."
try {
    $rdpUsers = Get-LocalGroupMember -Group "Remote Desktop Users" -ErrorAction SilentlyContinue
    Write-Host "Remote Desktop Users group has $($rdpUsers.Count) members"
} catch {
    Write-Host "Unable to query Remote Desktop Users group" -ForegroundColor Gray
}
Write-Host ""

# ML1-RA-06 Check logon restrictions
Write-Host "ML1-RA-06 - Unprivileged Account Restrictions" -ForegroundColor Yellow
Write-Host "Checking for user rights assignments..."

# Export current user rights to check manually
try {
    secedit /export /cfg "$env:TEMP\secpol.cfg" /quiet
    $secpolContent = Get-Content "$env:TEMP\secpol.cfg" | Select-String -Pattern "SeDenyInteractiveLogonRight|SeDenyRemoteInteractiveLogonRight|SeInteractiveLogonRight"
    
    foreach ($line in $secpolContent) {
        Write-Host "  $line" -ForegroundColor Gray
    }
    Remove-Item "$env:TEMP\secpol.cfg" -Force -ErrorAction SilentlyContinue
} catch {
    Write-Host "Unable to export security policy" -ForegroundColor Gray
}
Write-Host ""

# ML1-RA-07 Check privileged account logon restrictions
Write-Host "ML1-RA-07 - Privileged Account Logon Restrictions" -ForegroundColor Yellow
Write-Host "Checking for cached credentials..."

# Check if credential caching is disabled
$credCaching = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon" -Name "CachedLogonsCount" -ErrorAction SilentlyContinue
if ($credCaching) {
    Write-Host "Cached logons count $($credCaching.CachedLogonsCount)"
    if ($credCaching.CachedLogonsCount -eq 0) {
        Write-Host "  Credential caching is disabled" -ForegroundColor Green
    } else {
        Write-Host "  Warning - Credential caching is enabled" -ForegroundColor Yellow
    }
} else {
    Write-Host "Unable to determine credential caching status" -ForegroundColor Gray
}

# Summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Scan Complete" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Note This script provides automated checks for ML1-RA controls." -ForegroundColor White
Write-Host "Manual verification and additional testing may be required." -ForegroundColor White
Write-Host "Some checks require domain administrator privileges to run successfully." -ForegroundColor White
