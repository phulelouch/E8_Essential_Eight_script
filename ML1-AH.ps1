# ML1-AH Application Hardening Verification Script
# Run this script with appropriate permissions

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "ML1-AH Application Hardening Controls Check" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ML1-AH-01 Internet Explorer 11 disabled/removed
Write-Host "ML1-AH-01 - Internet Explorer 11 Status" -ForegroundColor Yellow
Write-Host "Checking Internet Explorer 11 presence and status..."

# Check for IE executables
$iePaths = @(
    "${env:ProgramFiles}\Internet Explorer\iexplore.exe",
    "${env:ProgramFiles(x86)}\Internet Explorer\iexplore.exe"
)

$ieFound = $false
foreach ($path in $iePaths) {
    if (Test-Path $path) {
        $ieFound = $true
        Write-Host "Internet Explorer found at $path" -ForegroundColor Red
        
        # Check if it's blocked by checking if it redirects to Edge
        try {
            $ieProcess = Start-Process -FilePath $path -PassThru -WindowStyle Hidden
            Start-Sleep -Seconds 2
            
            # Check if Edge was launched instead
            $edgeProcesses = Get-Process -Name "msedge" -ErrorAction SilentlyContinue
            if ($edgeProcesses) {
                Write-Host "  IE execution redirects to Microsoft Edge (Good)" -ForegroundColor Green
            } else {
                Write-Host "  IE can execute independently (Bad)" -ForegroundColor Red
            }
            
            # Clean up
            Stop-Process -Id $ieProcess.Id -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Host "  Unable to test IE execution" -ForegroundColor Gray
        }
    }
}

if (-not $ieFound) {
    Write-Host "Internet Explorer executables NOT FOUND (Removed)" -ForegroundColor Green
}

# Check IE disable policy
$iePolicy = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Internet Explorer\Main" -Name NotifyDisableIEOptions -ErrorAction SilentlyContinue
if ($iePolicy) {
    Write-Host "Internet Explorer disable policy is configured" -ForegroundColor Green
} else {
    Write-Host "Internet Explorer disable policy NOT found" -ForegroundColor Yellow
}

# Check if IE feature is disabled in Windows Features
try {
    $ieFeature = Get-WindowsOptionalFeature -Online -FeatureName Internet-Explorer-Optional-amd64 -ErrorAction SilentlyContinue
    if ($ieFeature) {
        if ($ieFeature.State -eq "Disabled") {
            Write-Host "Internet Explorer Windows Feature is DISABLED" -ForegroundColor Green
        } else {
            Write-Host "Internet Explorer Windows Feature is ENABLED" -ForegroundColor Red
        }
    }
} catch {
    Write-Host "Unable to check Windows Features status" -ForegroundColor Gray
}
Write-Host ""

# ML1-AH-02 Java processing in browsers
Write-Host "ML1-AH-02 - Web Browser Java Processing" -ForegroundColor Yellow
Write-Host "Checking Java plugin configuration..."

# Check Java deployment registry keys
$javaKeys = @(
    "HKLM:\SOFTWARE\Oracle\JavaDeploy\WebDeployJava",
    "HKLM:\SOFTWARE\JavaSoft\Java Plug-in",
    "HKLM:\SOFTWARE\WOW6432Node\JavaSoft\Java Plug-in"
)

$javaFound = $false
foreach ($key in $javaKeys) {
    if (Test-Path $key) {
        $javaFound = $true
        Write-Host "Java plugin registry key found at $key" -ForegroundColor Red
        try {
            $javaConfig = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            if ($javaConfig.PSObject.Properties.Name -contains "Enabled") {
                Write-Host "  Java plugin Enabled = $($javaConfig.Enabled)" -ForegroundColor Red
            }
        } catch {
            Write-Host "  Unable to read Java configuration" -ForegroundColor Gray
        }
    }
}

if (-not $javaFound) {
    Write-Host "No Java plugin registry keys found (Good)" -ForegroundColor Green
}

# Check for Java installation
$javaInstalled = Get-Command java -ErrorAction SilentlyContinue
if ($javaInstalled) {
    Write-Host "Java is installed on the system" -ForegroundColor Yellow
    java -version 2>&1 | ForEach-Object { Write-Host "  $_" -ForegroundColor Gray }
} else {
    Write-Host "Java is NOT installed on the system" -ForegroundColor Green
}

# Check browser-specific Java settings
Write-Host "Checking browser-specific Java blocking..."

# Edge - Check for Java blocking
$edgeJavaBlock = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -Name PluginsAllowedForUrls -ErrorAction SilentlyContinue
if ($edgeJavaBlock) {
    Write-Host "Edge has plugin policies configured" -ForegroundColor Green
} else {
    Write-Host "Edge plugin policies not configured" -ForegroundColor Yellow
}
Write-Host ""

# ML1-AH-03 Web advertisement blocking
Write-Host "ML1-AH-03 - Web Advertisement Blocking" -ForegroundColor Yellow
Write-Host "Checking for ad blocking extensions and policies..."

# Check Edge extensions
Write-Host "Microsoft Edge ad blocking check..."
$edgeExtPath = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\Extensions"
if (Test-Path $edgeExtPath) {
    $edgeExtensions = Get-ChildItem -Path $edgeExtPath -Directory -ErrorAction SilentlyContinue
    if ($edgeExtensions) {
        Write-Host "  Edge has $($edgeExtensions.Count) extensions installed" -ForegroundColor Gray
        # Known ad blocker extension IDs
        $adBlockerIds = @("cjpalhdlnbpafiamejdnhcphjbkeiagm", "pkehgijcmpdhfbdbbnkijodmdjhbjlgp", "ldcecbkkoecffmfljeihcmifjjdoepkn")
        $adBlockerFound = $false
        foreach ($id in $adBlockerIds) {
            if ($edgeExtensions.Name -contains $id) {
                $adBlockerFound = $true
                Write-Host "  Ad blocker extension found (ID $id)" -ForegroundColor Green
            }
        }
        if (-not $adBlockerFound) {
            Write-Host "  No known ad blocker extensions detected" -ForegroundColor Yellow
        }
    }
}

# Check Chrome extensions
Write-Host "Google Chrome ad blocking check..."
$chromeExtPath = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Extensions"
if (Test-Path $chromeExtPath) {
    $chromeExtensions = Get-ChildItem -Path $chromeExtPath -Directory -ErrorAction SilentlyContinue
    if ($chromeExtensions) {
        Write-Host "  Chrome has $($chromeExtensions.Count) extensions installed" -ForegroundColor Gray
    }
}

# Check for DNS-based ad blocking
Write-Host "Checking for DNS-based ad blocking..."
$dnsServers = Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses -Unique
$knownAdBlockDNS = @("9.9.9.9", "149.112.112.112", "176.103.130.130", "176.103.130.131")
$dnsAdBlockFound = $false
foreach ($dns in $dnsServers) {
    if ($dns -in $knownAdBlockDNS) {
        $dnsAdBlockFound = $true
        Write-Host "  Ad-blocking DNS server detected $dns" -ForegroundColor Green
    }
}
if (-not $dnsAdBlockFound) {
    Write-Host "  Standard DNS servers in use (no DNS-based ad blocking detected)" -ForegroundColor Yellow
}
Write-Host ""

# ML1-AH-04 Browser security settings protection
Write-Host "ML1-AH-04 - Browser Security Settings Protection" -ForegroundColor Yellow
Write-Host "Checking if browser settings are managed by organization..."

# Check Edge management
Write-Host "Microsoft Edge management status..."
$edgePolicies = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -ErrorAction SilentlyContinue
if ($edgePolicies) {
    Write-Host "  Edge IS managed by organization policies" -ForegroundColor Green
    $policyCount = ($edgePolicies.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" }).Count
    Write-Host "  Number of Edge policies configured $policyCount" -ForegroundColor Green
    
    # Check specific security policies
    if ($edgePolicies.PSObject.Properties.Name -contains "DeveloperToolsAvailability") {
        Write-Host "  Developer tools policy configured" -ForegroundColor Green
    }
    if ($edgePolicies.PSObject.Properties.Name -contains "SSLErrorOverrideAllowed") {
        Write-Host "  SSL error override policy configured" -ForegroundColor Green
    }
} else {
    Write-Host "  Edge is NOT managed by organization policies" -ForegroundColor Red
}

# Check Chrome management
Write-Host "Google Chrome management status..."
$chromePolicies = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -ErrorAction SilentlyContinue
if ($chromePolicies) {
    Write-Host "  Chrome IS managed by organization policies" -ForegroundColor Green
    $policyCount = ($chromePolicies.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" }).Count
    Write-Host "  Number of Chrome policies configured $policyCount" -ForegroundColor Green
} else {
    Write-Host "  Chrome is NOT managed by organization policies" -ForegroundColor Yellow
}

# Check Firefox management
Write-Host "Mozilla Firefox management status..."
$firefoxPolicies = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Mozilla\Firefox" -ErrorAction SilentlyContinue
if ($firefoxPolicies) {
    Write-Host "  Firefox IS managed by organization policies" -ForegroundColor Green
    $policyCount = ($firefoxPolicies.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" }).Count
    Write-Host "  Number of Firefox policies configured $policyCount" -ForegroundColor Green
} else {
    Write-Host "  Firefox is NOT managed by organization policies" -ForegroundColor Yellow
}

# Check if users can modify policies
Write-Host ""
Write-Host "Checking user ability to modify policies..."
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
$isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdmin) {
    Write-Host "Current user has administrator privileges - can potentially modify policies" -ForegroundColor Yellow
} else {
    Write-Host "Current user does NOT have administrator privileges - cannot modify policies" -ForegroundColor Green
}
Write-Host ""

# Summary
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "ML1-AH Control Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Quick summary
$summaryItems = @()
if ($ieFound) { $summaryItems += "Internet Explorer present" }
if ($javaFound) { $summaryItems += "Java plugin keys found" }
if (-not $edgePolicies -and -not $chromePolicies) { $summaryItems += "No browser management policies" }

if ($summaryItems.Count -eq 0) {
    Write-Host "All ML1-AH controls appear to be properly configured" -ForegroundColor Green
} else {
    Write-Host "Issues found that require attention" -ForegroundColor Red
    foreach ($item in $summaryItems) {
        Write-Host "  - $item" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Note This script provides automated checks for ML1-AH controls." -ForegroundColor White
Write-Host "Manual verification and additional testing may be required." -ForegroundColor White
Write-Host "For complete verification, test actual websites with Java content and ads." -ForegroundColor White
