<#
.SYNOPSIS
    Office Macro Security Compliance Check Script
.DESCRIPTION
    This script checks for compliance with Office macro security requirements:
    - ML1-RM-01: Microsoft Office macros are disabled for users without business requirement
    - ML1-RM-02: Microsoft Office macros from the internet are blocked
    - ML1-RM-03: Microsoft Office macro antivirus scanning is enabled
    - ML1-RM-04: Microsoft Office macro security settings cannot be changed by users
.NOTES
    Created: June 5, 2025
    Author: phulelouch
#>

# Function to create formatted output
function Write-CheckResult {
    param (
        [Parameter(Mandatory=$true)]
        [string]$CheckID,
        
        [Parameter(Mandatory=$true)]
        [string]$Description,
        
        [Parameter(Mandatory=$true)]
        [string]$Result,
        
        [Parameter(Mandatory=$true)]
        [string]$Status
    )
    
    $statusColor = switch ($Status) {
        "PASS" { "Green" }
        "FAIL" { "Red" }
        "MANUAL" { "Yellow" }
        "INFO" { "Cyan" }
        default { "White" }
    }
    
    Write-Host "`n[$CheckID] $Description" -ForegroundColor Blue
    Write-Host "Result $Result"
    Write-Host "Status $Status" -ForegroundColor $statusColor
}

# Function to display registry values verbosely
function Show-RegistryValues {
    param (
        [Parameter(Mandatory=$true)]
        [string]$Path,
        
        [Parameter(Mandatory=$false)]
        [string]$Description = "Registry Values"
    )
    
    if (Test-Path -Path $Path) {
        Write-Host "`n$Description" -ForegroundColor Cyan
        Write-Host "Path $Path" -ForegroundColor Cyan
        Write-Host "-----------------------------------------" -ForegroundColor Cyan
        try {
            $values = Get-ItemProperty -Path $Path -ErrorAction SilentlyContinue
            if ($values) {
                $values | Format-List
            } else {
                Write-Host "No values found in registry path" -ForegroundColor Yellow
            }
        } catch {
            Write-Host "Error accessing registry $Path $_" -ForegroundColor Red
        }
    } else {
        Write-Host "`n$Description" -ForegroundColor Cyan
        Write-Host "Path $Path" -ForegroundColor Cyan
        Write-Host "-----------------------------------------" -ForegroundColor Cyan
        Write-Host "Registry path does not exist" -ForegroundColor Yellow
    }
}

# Create a results directory if it doesn't exist
$resultsDir = Join-Path -Path $env:USERPROFILE -ChildPath "OfficeMacroSecurityChecks"
if (-not (Test-Path -Path $resultsDir)) {
    New-Item -Path $resultsDir -ItemType Directory | Out-Null
}

$logFile = Join-Path -Path $resultsDir -ChildPath "OfficeMacroSecurityCheck_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $logFile

Write-Host "=========================================================" -ForegroundColor Green
Write-Host "     OFFICE MACRO SECURITY COMPLIANCE CHECK SCRIPT      " -ForegroundColor Green
Write-Host "=========================================================" -ForegroundColor Green
Write-Host "Starting Office macro security compliance checks..."
Write-Host "Date/Time $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "Computer $env:COMPUTERNAME"
Write-Host "User $env:USERNAME"
Write-Host "=========================================================" -ForegroundColor Green

# Detect installed Office versions
$officeVersions = @()
$officeApps = @("Word", "Excel", "PowerPoint", "Outlook", "Access")
$registryPaths = @(
    "HKLM:\SOFTWARE\Microsoft\Office",
    "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Office"
)

foreach ($regPath in $registryPaths) {
    if (Test-Path $regPath) {
        $versionFolders = Get-ChildItem -Path $regPath -ErrorAction SilentlyContinue | 
                          Where-Object { $_.PSChildName -match '^\d+\.\d+$' }
        
        foreach ($versionFolder in $versionFolders) {
            $version = $versionFolder.PSChildName
            if ($version -notin $officeVersions) {
                $officeVersions += $version
            }
        }
    }
}

if ($officeVersions.Count -eq 0) {
    # Try to detect Office 365 (Click-to-Run)
    if (Test-Path "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration") {
        $officeVersions += "16.0" # Office 365 / 2016 / 2019 / 2021 use version 16.0
    }
}

if ($officeVersions.Count -eq 0) {
    Write-Host "No Microsoft Office installation detected. Exiting script." -ForegroundColor Red
    Stop-Transcript
    exit
}

Write-Host "Detected Office version(s) $($officeVersions -join ', ')" -ForegroundColor Cyan

# Map version numbers to product names for reporting
$versionNameMap = @{
    "16.0" = "Office 365/2016/2019/2021"
    "15.0" = "Office 2013"
    "14.0" = "Office 2010"
    "12.0" = "Office 2007"
}

foreach ($version in $officeVersions) {
    $productName = $versionNameMap[$version]
    if ($productName) {
        Write-Host "Version $version corresponds to $productName" -ForegroundColor Cyan
    } else {
        Write-Host "Version $version detected (unknown product name)" -ForegroundColor Cyan
    }
}

#region ML1-RM-01: Microsoft Office macros are disabled for users that do not have a demonstrated business requirement
Write-Host "`n[ML1-RM-01] Checking if Microsoft Office macros are disabled for users without business requirement..." -ForegroundColor Blue

# Define registry paths to check for macro settings in policy
$macroDisabledPolicies = @{}
$macroDisabledCorrectly = $true

foreach ($version in $officeVersions) {
    foreach ($app in $officeApps) {
        # Check VBA macro settings in the policy
        $regPath = "HKCU:\SOFTWARE\Policies\Microsoft\Office\$version\$app\Security"
        $vbaPolicy = "VBAWarnings"
        
        if (Test-Path $regPath) {
            try {
                $value = Get-ItemProperty -Path $regPath -Name $vbaPolicy -ErrorAction SilentlyContinue
                if ($value) {
                    $setting = $value.$vbaPolicy
                    $status = switch ($setting) {
                        1 { "Enable all macros (not recommended)" }
                        2 { "Disable with notification (default, NOT COMPLIANT)" }
                        3 { "Disable except digitally signed macros" }
                        4 { "Disable without notification (COMPLIANT)" }
                        default { "Unknown setting $setting" }
                    }
                    
                    $macroDisabledPolicies["$app ($version)"] = @{
                        "Setting" = $setting
                        "Status" = $status
                        "Compliant" = ($setting -eq 4)
                    }
                    
                    if ($setting -ne 4) {
                        $macroDisabledCorrectly = $false
                    }
                    
                    Write-Host "$app ($version) $status" -ForegroundColor $(if ($setting -eq 4) { "Green" } else { "Red" })
                    
                    # Display verbose registry information
                    Show-RegistryValues -Path $regPath -Description "$app ($version) Security Settings"
                } else {
                    $macroDisabledPolicies["$app ($version)"] = @{
                        "Setting" = "Not set"
                        "Status" = "No policy (likely using default, NOT COMPLIANT)"
                        "Compliant" = $false
                    }
                    $macroDisabledCorrectly = $false
                    Write-Host "$app ($version) No policy found (likely using default, NOT COMPLIANT)" -ForegroundColor Red
                    
                    # Display verbose registry information (even if specific value not found)
                    Show-RegistryValues -Path $regPath -Description "$app ($version) Security Settings"
                }
            } catch {
                Write-Host "Error checking $app ($version) macro policy $_" -ForegroundColor Red
            }
        } else {
            $macroDisabledPolicies["$app ($version)"] = @{
                "Setting" = "No registry path"
                "Status" = "Registry path not found (likely no policy, NOT COMPLIANT)"
                "Compliant" = $false
            }
            $macroDisabledCorrectly = $false
            Write-Host "$app ($version) Registry path not found (likely no policy, NOT COMPLIANT)" -ForegroundColor Red
        }
    }
}

# Check for Active Directory security groups that enforce Office macro blocking
$adGroupsFound = $false
try {
    $adGroups = Get-ADGroup -Filter "Name -like '*macro*' -or Name -like '*office*security*'" -ErrorAction SilentlyContinue
    if ($adGroups) {
        $adGroupsFound = $true
        Write-Host "`nPotential AD security groups found for Office macro permissions" -ForegroundColor Cyan
        foreach ($group in $adGroups) {
            Write-Host "- $($group.Name)" -ForegroundColor Cyan
        }
    }
} catch {
    Write-Host "Note Unable to check Active Directory groups. AD module may not be installed or you don't have permissions." -ForegroundColor Yellow
}

# Overall result for ML1-RM-01
$resultDetails = "Office macro policy status`n"
foreach ($app in $macroDisabledPolicies.Keys) {
    $resultDetails += "- $app $($macroDisabledPolicies[$app].Status)`n"
}

if ($adGroupsFound) {
    $resultDetails += "`nPotential AD security groups found for macro management."
} else {
    $resultDetails += "`nNo specific AD security groups identified for macro management."
}

if ($macroDisabledCorrectly) {
    Write-CheckResult -CheckID "ML1-RM-01" -Description "Microsoft Office macros are disabled for users without business requirement" `
        -Result $resultDetails -Status "PASS"
} else {
    Write-CheckResult -CheckID "ML1-RM-01" -Description "Microsoft Office macros are disabled for users without business requirement" `
        -Result $resultDetails -Status "FAIL"
}

Write-Host "`nManual verification required for ML1-RM-01" -ForegroundColor Yellow
Write-Host "1. Run the 'gpresult /h C:\temp\rsop.html' command to generate an RSOP report and check Office macro settings"
Write-Host "2. Test running an Office macro document as a standard user to verify it's blocked"
Write-Host "3. Confirm a list of approved users who can execute Office macros is maintained and matches the AD security groups"
#endregion

#region ML1-RM-02: Microsoft Office macros in files originating from the internet are blocked
Write-Host "`n[ML1-RM-02] Checking if Microsoft Office macros from the internet are blocked..." -ForegroundColor Blue

# Check for internet macro blocking settings
$internetMacroBlocked = @{}
$allInternetMacrosBlocked = $true

foreach ($version in $officeVersions) {
    foreach ($app in $officeApps) {
        # Check BlockContentExecutionFromInternet setting
        $regPath = "HKCU:\SOFTWARE\Policies\Microsoft\Office\$version\$app\Security"
        $policyName = "BlockContentExecutionFromInternet"
        
        if (Test-Path $regPath) {
            try {
                $value = Get-ItemProperty -Path $regPath -Name $policyName -ErrorAction SilentlyContinue
                if ($value) {
                    $setting = $value.$policyName
                    $status = if ($setting -eq 1) { "Enabled (COMPLIANT)" } else { "Disabled (NOT COMPLIANT)" }
                    
                    $internetMacroBlocked["$app ($version)"] = @{
                        "Setting" = $setting
                        "Status" = $status
                        "Compliant" = ($setting -eq 1)
                    }
                    
                    if ($setting -ne 1) {
                        $allInternetMacrosBlocked = $false
                    }
                    
                    Write-Host "$app ($version) $status" -ForegroundColor $(if ($setting -eq 1) { "Green" } else { "Red" })
                    
                    # Display verbose registry information
                    Show-RegistryValues -Path $regPath -Description "$app ($version) Internet Macro Blocking Settings"
                } else {
                    $internetMacroBlocked["$app ($version)"] = @{
                        "Setting" = "Not set"
                        "Status" = "No policy (NOT COMPLIANT)"
                        "Compliant" = $false
                    }
                    $allInternetMacrosBlocked = $false
                    Write-Host "$app ($version) No policy found (NOT COMPLIANT)" -ForegroundColor Red
                    
                    # Display verbose registry information (even if specific value not found)
                    if (Test-Path $regPath) {
                        Show-RegistryValues -Path $regPath -Description "$app ($version) Security Settings (No Internet Macro Blocking Found)"
                    }
                }
            } catch {
                Write-Host "Error checking $app ($version) internet macro policy $_" -ForegroundColor Red
            }
        } else {
            $internetMacroBlocked["$app ($version)"] = @{
                "Setting" = "No registry path"
                "Status" = "Registry path not found (likely no policy, NOT COMPLIANT)"
                "Compliant" = $false
            }
            $allInternetMacrosBlocked = $false
            Write-Host "$app ($version) Registry path not found (likely no policy, NOT COMPLIANT)" -ForegroundColor Red
        }
    }
}

# Overall result for ML1-RM-02
$resultDetails = "Internet macro blocking status`n"
foreach ($app in $internetMacroBlocked.Keys) {
    $resultDetails += "- $app $($internetMacroBlocked[$app].Status)`n"
}

if ($allInternetMacrosBlocked) {
    Write-CheckResult -CheckID "ML1-RM-02" -Description "Microsoft Office macros from the internet are blocked" `
        -Result $resultDetails -Status "PASS"
} else {
    Write-CheckResult -CheckID "ML1-RM-02" -Description "Microsoft Office macros from the internet are blocked" `
        -Result $resultDetails -Status "FAIL"
}

Write-Host "`nManual verification required for ML1-RM-02" -ForegroundColor Yellow
Write-Host "1. Check Group Policy settings for 'Block macros from running in Office files from the internet'"
Write-Host "2. Verify this by downloading a macro-enabled file from the internet and attempting to run it"
#endregion

#region ML1-RM-03: Microsoft Office macro antivirus scanning is enabled
Write-Host "`n[ML1-RM-03] Checking if Microsoft Office macro antivirus scanning is enabled..." -ForegroundColor Blue

# Check for macro antivirus scanning settings
$macroAVScanEnabled = @{}
$allMacroAVScanEnabled = $true

foreach ($version in $officeVersions) {
    # Check MacroRuntimeScanScope setting at the Office level
    $regPath = "HKCU:\SOFTWARE\Policies\Microsoft\Office\$version\Common\Security"
    $policyName = "MacroRuntimeScanScope"
    
    if (Test-Path $regPath) {
        try {
            $value = Get-ItemProperty -Path $regPath -Name $policyName -ErrorAction SilentlyContinue
            if ($value) {
                $setting = $value.$policyName
                $status = switch ($setting) {
                    1 { "Scan macros in all open documents (COMPLIANT)" }
                    2 { "Scan only macros in documents from trusted locations (NOT COMPLIANT)" }
                    3 { "Don't scan macros (disable antivirus scanning) (NOT COMPLIANT)" }
                    default { "Unknown setting $setting (NOT COMPLIANT)" }
                }
                
                $macroAVScanEnabled["Office $version"] = @{
                    "Setting" = $setting
                    "Status" = $status
                    "Compliant" = ($setting -eq 1)
                }
                
                if ($setting -ne 1) {
                    $allMacroAVScanEnabled = $false
                }
                
                Write-Host "Office $version $status" -ForegroundColor $(if ($setting -eq 1) { "Green" } else { "Red" })
                
                # Display verbose registry information
                Show-RegistryValues -Path $regPath -Description "Office $version Macro AV Scan Settings"
            } else {
                $macroAVScanEnabled["Office $version"] = @{
                    "Setting" = "Not set"
                    "Status" = "No policy (default is don't scan, NOT COMPLIANT)"
                    "Compliant" = $false
                }
                $allMacroAVScanEnabled = $false
                Write-Host "Office $version No policy found (default is don't scan, NOT COMPLIANT)" -ForegroundColor Red
                
                # Display verbose registry information (even if specific value not found)
                if (Test-Path $regPath) {
                    Show-RegistryValues -Path $regPath -Description "Office $version Common Security Settings (No Macro AV Scan Setting Found)"
                }
            }
        } catch {
            Write-Host "Error checking Office $version macro AV scan policy $_" -ForegroundColor Red
        }
    } else {
        $macroAVScanEnabled["Office $version"] = @{
            "Setting" = "No registry path"
            "Status" = "Registry path not found (likely no policy, NOT COMPLIANT)"
            "Compliant" = $false
        }
        $allMacroAVScanEnabled = $false
        Write-Host "Office $version Registry path not found (likely no policy, NOT COMPLIANT)" -ForegroundColor Red
    }
}

# Check if antivirus is installed and running
$avStatus = "Unknown"
try {
    $avProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction SilentlyContinue
    if ($avProducts) {
        $avStatus = "Antivirus detected "
        foreach ($av in $avProducts) {
            $avStatus += "$($av.displayName), "
        }
        $avStatus = $avStatus.TrimEnd(", ")
        
        # Display detailed AV info
        Write-Host "`nDetailed Antivirus Information" -ForegroundColor Cyan
        Write-Host "-----------------------------------------" -ForegroundColor Cyan
        $avProducts | Format-List
    } else {
        $avStatus = "No antivirus product detected via WMI"
    }
} catch {
    $avStatus = "Unable to detect antivirus status $_"
}

Write-Host "`nAntivirus status $avStatus" -ForegroundColor Cyan

# Overall result for ML1-RM-03
$resultDetails = "Macro antivirus scanning status`n"
foreach ($office in $macroAVScanEnabled.Keys) {
    $resultDetails += "- $office $($macroAVScanEnabled[$office].Status)`n"
}
$resultDetails += "`n$avStatus"

if ($allMacroAVScanEnabled) {
    Write-CheckResult -CheckID "ML1-RM-03" -Description "Microsoft Office macro antivirus scanning is enabled" `
        -Result $resultDetails -Status "PASS"
} else {
    Write-CheckResult -CheckID "ML1-RM-03" -Description "Microsoft Office macro antivirus scanning is enabled" `
        -Result $resultDetails -Status "FAIL"
}

Write-Host "`nManual verification required for ML1-RM-03" -ForegroundColor Yellow
Write-Host "1. Check Group Policy settings for 'Macro Runtime Scan Scope'"
Write-Host "2. Test with a macro file containing an EICAR test string"
Write-Host "3. EICAR test string X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
#endregion

#region ML1-RM-04: Microsoft Office macro security settings cannot be changed by users
Write-Host "`n[ML1-RM-04] Checking if Microsoft Office macro security settings cannot be changed by users..." -ForegroundColor Blue

# Check for settings that prevent users from changing macro security
$macroSettingsLocked = @{}
$allMacroSettingsLocked = $true

foreach ($version in $officeVersions) {
    foreach ($app in $officeApps) {
        # Check DisableAllActivexSettings setting
        $regPath = "HKCU:\SOFTWARE\Policies\Microsoft\Office\$version\$app\Security"
        $disableTrustCenterUIPath = "HKCU:\SOFTWARE\Policies\Microsoft\Office\$version\$app\Security\Trusted Locations"
        $policyName = "DisableTrustCenterUI"
        
        $settingFound = $false
        
        # Check primary setting path
        if (Test-Path $regPath) {
            try {
                $value = Get-ItemProperty -Path $regPath -Name $policyName -ErrorAction SilentlyContinue
                if ($value) {
                    $setting = $value.$policyName
                    $status = if ($setting -eq 1) { "Trust Center UI disabled (COMPLIANT)" } else { "Trust Center UI enabled (NOT COMPLIANT)" }
                    
                    $macroSettingsLocked["$app ($version)"] = @{
                        "Setting" = $setting
                        "Status" = $status
                        "Compliant" = ($setting -eq 1)
                    }
                    
                    if ($setting -ne 1) {
                        $allMacroSettingsLocked = $false
                    }
                    
                    Write-Host "$app ($version) $status" -ForegroundColor $(if ($setting -eq 1) { "Green" } else { "Red" })
                    $settingFound = $true
                    
                    # Display verbose registry information
                    Show-RegistryValues -Path $regPath -Description "$app ($version) Trust Center UI Settings"
                }
            } catch {
                Write-Host "Error checking $app ($version) Trust Center UI policy $_" -ForegroundColor Red
            }
        }
        
        # Check secondary setting path if not found in primary
        if (-not $settingFound -and (Test-Path $disableTrustCenterUIPath)) {
            try {
                $value = Get-ItemProperty -Path $disableTrustCenterUIPath -Name $policyName -ErrorAction SilentlyContinue
                if ($value) {
                    $setting = $value.$policyName
                    $status = if ($setting -eq 1) { "Trust Center UI disabled (COMPLIANT)" } else { "Trust Center UI enabled (NOT COMPLIANT)" }
                    
                    $macroSettingsLocked["$app ($version)"] = @{
                        "Setting" = $setting
                        "Status" = $status
                        "Compliant" = ($setting -eq 1)
                    }
                    
                    if ($setting -ne 1) {
                        $allMacroSettingsLocked = $false
                    }
                    
                    Write-Host "$app ($version) $status" -ForegroundColor $(if ($setting -eq 1) { "Green" } else { "Red" })
                    $settingFound = $true
                    
                    # Display verbose registry information
                    Show-RegistryValues -Path $disableTrustCenterUIPath -Description "$app ($version) Trusted Locations Settings"
                }
            } catch {
                Write-Host "Error checking $app ($version) Trust Center UI policy (alternative path) $_" -ForegroundColor Red
            }
        }
        
        # If setting not found in either path, but at least one path exists
        if (-not $settingFound) {
            $macroSettingsLocked["$app ($version)"] = @{
                "Setting" = "Not set"
                "Status" = "No policy (users can change settings, NOT COMPLIANT)"
                "Compliant" = $false
            }
            $allMacroSettingsLocked = $false
            Write-Host "$app ($version) No policy found (users can change settings, NOT COMPLIANT)" -ForegroundColor Red
            
            # Display verbose registry information for the primary path if it exists
            if (Test-Path $regPath) {
                Show-RegistryValues -Path $regPath -Description "$app ($version) Security Settings (No Trust Center UI Setting Found)"
            }
            
            # Display verbose registry information for the secondary path if it exists
            if (Test-Path $disableTrustCenterUIPath) {
                Show-RegistryValues -Path $disableTrustCenterUIPath -Description "$app ($version) Trusted Locations Settings (No Trust Center UI Setting Found)"
            }
        }
    }
}

# Overall result for ML1-RM-04
$resultDetails = "Macro security settings lockdown status`n"
foreach ($app in $macroSettingsLocked.Keys) {
    $resultDetails += "- $app $($macroSettingsLocked[$app].Status)`n"
}

if ($allMacroSettingsLocked) {
    Write-CheckResult -CheckID "ML1-RM-04" -Description "Microsoft Office macro security settings cannot be changed by users" `
        -Result $resultDetails -Status "PASS"
} else {
    Write-CheckResult -CheckID "ML1-RM-04" -Description "Microsoft Office macro security settings cannot be changed by users" `
        -Result $resultDetails -Status "FAIL"
}

Write-Host "`nManual verification required for ML1-RM-04" -ForegroundColor Yellow
Write-Host "1. Open each Microsoft Office application (Word, Excel, PowerPoint, etc.)"
Write-Host "2. Go to File > Options > Trust Center > Trust Center Settings"
Write-Host "3. Verify that macro security settings are greyed out or inaccessible"
Write-Host "4. If settings can be changed, this check fails"
#endregion

# Additional checks for verbose registry output
Write-Host "`n=========================================================" -ForegroundColor Green
Write-Host "          ADDITIONAL REGISTRY INFORMATION               " -ForegroundColor Green
Write-Host "=========================================================" -ForegroundColor Green

# Check additional registry paths that might be relevant to macro security
foreach ($version in $officeVersions) {
    # Check Office-wide security settings
    $officeSecurityPath = "HKCU:\SOFTWARE\Policies\Microsoft\Office\$version\Common\Security"
    Show-RegistryValues -Path $officeSecurityPath -Description "Office $version Common Security Settings"
    
    # Check Trust Center settings
    $trustCenterPath = "HKCU:\SOFTWARE\Policies\Microsoft\Office\$version\Common\Security\Trusted Locations"
    Show-RegistryValues -Path $trustCenterPath -Description "Office $version Trusted Locations"
    
    foreach ($app in $officeApps) {
        # Check app-specific trusted locations
        $appTrustedLocationsPath = "HKCU:\SOFTWARE\Policies\Microsoft\Office\$version\$app\Security\Trusted Locations"
        Show-RegistryValues -Path $appTrustedLocationsPath -Description "$app ($version) Trusted Locations"
        
        # Check app-specific trusted publishers
        $appTrustedPublishersPath = "HKCU:\SOFTWARE\Policies\Microsoft\Office\$version\$app\Security\Trusted Publishers"
        Show-RegistryValues -Path $appTrustedPublishersPath -Description "$app ($version) Trusted Publishers"
    }
}

# Check global machine policy settings
$machinePolicyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Office"
Show-RegistryValues -Path $machinePolicyPath -Description "Machine-wide Office Policy Settings"

# Create EICAR test macro file for manual testing
$eicarTestDir = Join-Path -Path $resultsDir -ChildPath "TestFiles"
if (-not (Test-Path -Path $eicarTestDir)) {
    New-Item -Path $eicarTestDir -ItemType Directory | Out-Null
}

# Create EICAR test macro file for manual testing
Write-Host "`n=========================================================" -ForegroundColor Green
Write-Host "                  EICAR TEST MACRO                      " -ForegroundColor Green
Write-Host "=========================================================" -ForegroundColor Green

$eicarTestDir = Join-Path -Path $env:USERPROFILE -ChildPath "OfficeMacroSecurityChecks\TestFiles"
if (-not (Test-Path -Path $eicarTestDir)) {
    New-Item -Path $eicarTestDir -ItemType Directory -Force | Out-Null
}

$eicarMacroFile = Join-Path -Path $eicarTestDir -ChildPath "EicarTestMacro.txt"
$eicarString = "X5O!P%@AP[4\PZX54(P^)7CC)7}`$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!`$H+H*"
$eicarMacroContent = @"
'
' EICAR Test Macro
' This is a sample macro that would write the EICAR test string to a file
' DO NOT EXECUTE this in a production environment
'
Sub EicarTest()
    Dim fso As Object
    Dim outFile As Object
    
    ' Create FileSystemObject
    Set fso = CreateObject("Scripting.FileSystemObject")
    
    ' Create test file
    Set outFile = fso.CreateTextFile("C:\Temp\eicar_test.txt", True)
    
    ' Write EICAR test string
    outFile.WriteLine "$eicarString"
    
    ' Close file
    outFile.Close
    
    MsgBox "EICAR test file created. Your antivirus should detect this.", vbInformation
End Sub
"@

Write-Host $eicarMacroContent -ForegroundColor Yellow
Write-Host "`nEICAR test macro can be used to verify antivirus scanning of Office macros" -ForegroundColor Cyan
Write-Host "To use Copy this macro code into a macro-enabled Office document (.docm, .xlsm, etc.)" -ForegroundColor Cyan
Write-Host "File also saved to $eicarMacroFile" -ForegroundColor Cyan
try {
    Set-Content -Path $eicarMacroFile -Value $eicarMacroContent -Force
    Write-Host "`nCreated EICAR test macro file at $eicarMacroFile" -ForegroundColor Cyan
    Write-Host "NOTE This is a text file with VBA code. For testing, you would need to create a macro-enabled Office document (.docm, .xlsm, etc.) and import this code." -ForegroundColor Yellow
} catch {
    Write-Host "Error creating EICAR test macro file $_" -ForegroundColor Red
}

# Summary of all checks
Write-Host "`n=========================================================" -ForegroundColor Green
Write-Host "                 SUMMARY OF FINDINGS                    " -ForegroundColor Green
Write-Host "=========================================================" -ForegroundColor Green

Write-Host "`nA full log of this check has been saved to $logFile"
Write-Host "`nNOTE Some checks require manual verification. Please review the detailed instructions above."

Stop-Transcript
