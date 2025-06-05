<#
.SYNOPSIS
    Application Control Compliance Check Script
.DESCRIPTION
    This script checks for compliance with application control requirements:
    - ML1-AC-01: Application control is implemented on workstations
    - ML1-AC-02: Application control is applied to user profiles and temporary folders
    - ML1-AC-03: Application control restricts execution to an organisation-approved set
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
$resultsDir = Join-Path -Path $env:USERPROFILE -ChildPath "AppControlChecks"
if (-not (Test-Path -Path $resultsDir)) {
    New-Item -Path $resultsDir -ItemType Directory | Out-Null
}

$logFile = Join-Path -Path $resultsDir -ChildPath "AppControlCheck_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
Start-Transcript -Path $logFile

Write-Host "=========================================================" -ForegroundColor Green
Write-Host "     APPLICATION CONTROL COMPLIANCE CHECK SCRIPT        " -ForegroundColor Green
Write-Host "=========================================================" -ForegroundColor Green
Write-Host "Starting application control compliance checks..."
Write-Host "Date/Time $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Write-Host "Computer $env:COMPUTERNAME"
Write-Host "User $env:USERNAME"
Write-Host "=========================================================" -ForegroundColor Green

#region ML1-AC-01: Application control is implemented on workstations
Write-Host "`n[ML1-AC-01] Checking if application control is implemented on workstations..." -ForegroundColor Blue

# Check for common application control solutions
$appControlSolutions = @{
    "Windows Defender Application Control (WDAC)" = @{
        Implemented = $false
        Details = ""
        RegPaths = @(
            "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy",
            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\CodeIntegrity"
        )
        Services = @(
            "AppIDSvc"
        )
        Processes = @(
            "appidsvc.dll"
        )
    }
    "AppLocker" = @{
        Implemented = $false
        Details = ""
        RegPaths = @(
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2",
            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"
        )
        Services = @(
            "AppIDSvc"
        )
        Processes = @(
            "appidsvc.dll"
        )
    }
    "Microsoft Defender Application Control" = @{
        Implemented = $false
        Details = ""
        RegPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR",
            "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender\Windows Defender Exploit Guard\ASR"
        )
        Services = @(
            "WinDefend"
        )
        Processes = @(
            "MsMpEng.exe"
        )
    }
    "Third-Party Solution" = @{
        Implemented = $false
        Details = ""
        RegPaths = @(
            # Common third-party application control solutions
            "HKLM:\SOFTWARE\McAfee\Solidcore",
            "HKLM:\SOFTWARE\CarbonBlack",
            "HKLM:\SOFTWARE\Symantec\Symantec Endpoint Protection",
            "HKLM:\SOFTWARE\Bit9",
            "HKLM:\SOFTWARE\Cisco\AMP"
        )
        Services = @(
            # Common third-party service names
            "McAfeeFramework",
            "CbDefense",
            "SepMasterService",
            "Bit9Core",
            "CSFalconService"
        )
        Processes = @()
    }
}

# Check for application control registry keys
foreach ($solution in $appControlSolutions.Keys) {
    foreach ($regPath in $appControlSolutions[$solution].RegPaths) {
        if (Test-Path -Path $regPath) {
            $appControlSolutions[$solution].Implemented = $true
            $appControlSolutions[$solution].Details += "Registry path found: $regPath`n"
            
            # Display registry values for the found path
            Show-RegistryValues -Path $regPath -Description "$solution Registry Values"
        }
    }
}

# Check for application control services
foreach ($solution in $appControlSolutions.Keys) {
    foreach ($service in $appControlSolutions[$solution].Services) {
        $svc = Get-Service -Name $service -ErrorAction SilentlyContinue
        if ($svc) {
            $appControlSolutions[$solution].Implemented = $true
            $appControlSolutions[$solution].Details += "Service found: $service (Status: $($svc.Status))`n"
        }
    }
}

# Check for application control processes
foreach ($solution in $appControlSolutions.Keys) {
    foreach ($process in $appControlSolutions[$solution].Processes) {
        $proc = Get-Process -Name ($process -replace '\.exe$', '') -ErrorAction SilentlyContinue
        if ($proc) {
            $appControlSolutions[$solution].Implemented = $true
            $appControlSolutions[$solution].Details += "Process found: $process`n"
        }
    }
}

# Check for specific AppLocker settings
if (Test-Path -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2") {
    # Check each AppLocker rule collection
    $ruleCollections = @("Appx", "Dll", "Exe", "Msi", "Script")
    foreach ($collection in $ruleCollections) {
        $collectionPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collection"
        if (Test-Path -Path $collectionPath) {
            try {
                $enforcementMode = Get-ItemProperty -Path $collectionPath -Name "EnforcementMode" -ErrorAction SilentlyContinue
                if ($enforcementMode) {
                    $mode = switch ($enforcementMode.EnforcementMode) {
                        0 { "Audit Only" }
                        1 { "Enforced" }
                        default { "Unknown ($($enforcementMode.EnforcementMode))" }
                    }
                    $appControlSolutions["AppLocker"].Details += "$collection rules: $mode`n"
                }
                
                # Count rules in this collection
                $rulesPath = "$collectionPath\Rules"
                if (Test-Path -Path $rulesPath) {
                    $ruleCount = (Get-ChildItem -Path $rulesPath).Count
                    $appControlSolutions["AppLocker"].Details += "$collection rule count: $ruleCount`n"
                }
            } catch {
                Write-Host "Error checking AppLocker $collection rules $_" -ForegroundColor Red
            }
        }
    }
}

# Check for WDAC CodeIntegrity policy
$wdacPolicyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CI\Policy"
if (Test-Path -Path $wdacPolicyPath) {
    try {
        $ciPolicy = Get-ItemProperty -Path $wdacPolicyPath -ErrorAction SilentlyContinue
        if ($ciPolicy.PSObject.Properties.Name -contains "SupplementalPolicyInfo") {
            $appControlSolutions["Windows Defender Application Control (WDAC)"].Details += "Supplemental policies configured`n"
        }
        if ($ciPolicy.PSObject.Properties.Name -contains "Options") {
            $options = $ciPolicy.Options
            $appControlSolutions["Windows Defender Application Control (WDAC)"].Details += "Policy options: 0x$($options.ToString("X8"))`n"
        }
    } catch {
        Write-Host "Error checking WDAC policy $_" -ForegroundColor Red
    }
}

# Check for SRP policies (older Windows versions)
$srpPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Safer"
if (Test-Path -Path $srpPath) {
    try {
        $srpPolicies = Get-ChildItem -Path "$srpPath\CodeIdentifiers" -ErrorAction SilentlyContinue
        if ($srpPolicies) {
            $appControlSolutions["AppLocker"].Details += "Software Restriction Policies (SRP) found`n"
            $appControlSolutions["AppLocker"].Implemented = $true
            
            # Show SRP policy details
            Show-RegistryValues -Path "$srpPath\CodeIdentifiers" -Description "Software Restriction Policies"
        }
    } catch {
        Write-Host "Error checking SRP policies $_" -ForegroundColor Red
    }
}

# Determine if any application control solution is implemented
$appControlImplemented = $false
$implementedSolutions = @()
foreach ($solution in $appControlSolutions.Keys) {
    if ($appControlSolutions[$solution].Implemented) {
        $appControlImplemented = $true
        $implementedSolutions += $solution
    }
}

# Overall result for ML1-AC-01
$resultDetails = "Application control status`n"
if ($implementedSolutions.Count -gt 0) {
    $resultDetails += "Detected application control solutions:`n"
    foreach ($solution in $implementedSolutions) {
        $resultDetails += "- $solution`n"
        $resultDetails += $appControlSolutions[$solution].Details
    }
    
    Write-CheckResult -CheckID "ML1-AC-01" -Description "Application control is implemented on workstations" `
        -Result $resultDetails -Status "PASS"
} else {
    $resultDetails += "No application control solution detected"
    
    Write-CheckResult -CheckID "ML1-AC-01" -Description "Application control is implemented on workstations" `
        -Result $resultDetails -Status "FAIL"
}

Write-Host "`nManual verification required for ML1-AC-01" -ForegroundColor Yellow
Write-Host "1. Check for application control policies in Group Policy (gpresult /h C:\temp\gpresult.html)"
Write-Host "2. Verify with system administrators which application control solution is deployed"
Write-Host "3. Check documentation for third-party solutions that might not be detected by this script"
#endregion

#region ML1-AC-02: Application control is applied to user profiles and temporary folders
Write-Host "`n[ML1-AC-02] Checking if application control is applied to user profiles and temporary folders..." -ForegroundColor Blue

# Define critical paths that should be protected by application control
$criticalPaths = @{
    "User Profile" = @{
        Paths = @(
            $env:USERPROFILE,
            [Environment]::GetFolderPath("UserProfile"),
            "C:\Users"
        )
        Protected = $false
        Details = ""
    }
    "Temporary Folders" = @{
        Paths = @(
            $env:TEMP,
            $env:TMP,
            "C:\Windows\Temp",
            [System.IO.Path]::GetTempPath()
        )
        Protected = $false
        Details = ""
    }
    "Browser Temp Folders" = {
        Paths = @(
            "$env:LOCALAPPDATA\Microsoft\Windows\INetCache",
            "$env:LOCALAPPDATA\Microsoft\Windows\Temporary Internet Files",
            "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\Cache",
            "$env:LOCALAPPDATA\Mozilla\Firefox\Profiles"
        )
        Protected = $false
        Details = ""
    }
    "Email Client Temp Folders" = {
        Paths = @(
            "$env:LOCALAPPDATA\Microsoft\Outlook",
            "$env:LOCALAPPDATA\Microsoft\Windows Live Mail",
            "$env:APPDATA\Thunderbird"
        )
        Protected = $false
        Details = ""
    }
}

# Check AppLocker path rules if implemented
$pathRulesExist = $false
if ($appControlSolutions["AppLocker"].Implemented) {
    # Check each AppLocker rule collection for path rules
    $ruleCollections = @("Exe", "Dll", "Script", "Msi")
    foreach ($collection in $ruleCollections) {
        $rulesPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\SrpV2\$collection\Rules"
        if (Test-Path -Path $rulesPath) {
            try {
                $rules = Get-ChildItem -Path $rulesPath -ErrorAction SilentlyContinue
                foreach ($rule in $rules) {
                    $rulePath = $rule.PSPath
                    $ruleData = Get-ItemProperty -Path $rulePath -ErrorAction SilentlyContinue
                    
                    # Check if this is a path rule
                    if ($ruleData.PSObject.Properties.Name -contains "RuleType" -and $ruleData.RuleType -eq 0) {
                        $pathRulesExist = $true
                        
                        # Get rule conditions (XML format)
                        if ($ruleData.PSObject.Properties.Name -contains "Conditions") {
                            $conditions = $ruleData.Conditions
                            
                            # Check if rule applies to critical paths
                            foreach ($category in $criticalPaths.Keys) {
                                foreach ($path in $criticalPaths[$category].Paths) {
                                    # Simple string matching (not perfect but indicative)
                                    if ($conditions -match [regex]::Escape($path) -or 
                                        $conditions -match [regex]::Escape($path.Replace("\", "\\")) -or
                                        $conditions -match [regex]::Escape($path.Replace("\", "/"))) {
                                        $criticalPaths[$category].Protected = $true
                                        $criticalPaths[$category].Details += "Path '$path' appears to be covered by AppLocker rule`n"
                                        $criticalPaths[$category].Details += "Rule: $($ruleData.Name)`n"
                                    }
                                }
                            }
                        }
                    }
                }
            } catch {
                Write-Host "Error checking AppLocker path rules for $collection $_" -ForegroundColor Red
            }
        }
    }
}

# Check if WDAC or third-party solutions are implemented (these typically protect all paths by default)
$publisherOrHashBasedProtection = $false
$publisherOrHashSolution = ""

if ($appControlSolutions["Windows Defender Application Control (WDAC)"].Implemented) {
    $publisherOrHashBasedProtection = $true
    $publisherOrHashSolution = "Windows Defender Application Control (WDAC)"
} elseif ($appControlSolutions["Microsoft Defender Application Control"].Implemented) {
    $publisherOrHashBasedProtection = $true
    $publisherOrHashSolution = "Microsoft Defender Application Control"
} elseif ($appControlSolutions["Third-Party Solution"].Implemented) {
    # Many third-party solutions use publisher or hash-based approaches
    # This is a heuristic and would need verification
    $publisherOrHashBasedProtection = $true
    $publisherOrHashSolution = "Third-Party Solution"
}

# If a publisher or hash-based solution is implemented, mark all paths as protected
if ($publisherOrHashBasedProtection) {
    foreach ($category in $criticalPaths.Keys) {
        $criticalPaths[$category].Protected = $true
        $criticalPaths[$category].Details = "Protected by $publisherOrHashSolution (publisher or hash-based protection)`n"
    }
}

# Determine if all critical paths are protected
$allPathsProtected = $true
$unprotectedCategories = @()
foreach ($category in $criticalPaths.Keys) {
    if (-not $criticalPaths[$category].Protected) {
        $allPathsProtected = $false
        $unprotectedCategories += $category
    }
}

# Overall result for ML1-AC-02
$resultDetails = "Application control on critical paths`n"
if ($publisherOrHashBasedProtection) {
    $resultDetails += "Publisher or hash-based protection detected: $publisherOrHashSolution`n"
    $resultDetails += "This type of protection automatically covers all paths system-wide`n"
    
    Write-CheckResult -CheckID "ML1-AC-02" -Description "Application control is applied to user profiles and temporary folders" `
        -Result $resultDetails -Status "PASS"
} elseif ($pathRulesExist) {
    if ($allPathsProtected) {
        $resultDetails += "Path-based protection detected`n"
        foreach ($category in $criticalPaths.Keys) {
            $resultDetails += "$category Protected`n"
            $resultDetails += $criticalPaths[$category].Details
        }
        
        Write-CheckResult -CheckID "ML1-AC-02" -Description "Application control is applied to user profiles and temporary folders" `
            -Result $resultDetails -Status "PASS"
    } else {
        $resultDetails += "Path-based protection detected, but not all critical paths are covered`n"
        $resultDetails += "Unprotected categories:`n"
        foreach ($category in $unprotectedCategories) {
            $resultDetails += "- $category`n"
        }
        
        Write-CheckResult -CheckID "ML1-AC-02" -Description "Application control is applied to user profiles and temporary folders" `
            -Result $resultDetails -Status "FAIL"
    }
} else {
    $resultDetails += "No path-based or publisher/hash-based application control detected`n"
    
    Write-CheckResult -CheckID "ML1-AC-02" -Description "Application control is applied to user profiles and temporary folders" `
        -Result $resultDetails -Status "FAIL"
}

Write-Host "`nManual verification required for ML1-AC-02" -ForegroundColor Yellow
Write-Host "1. If a path-based approach is used, verify rules cover user profiles and temporary folders"
Write-Host "2. If publisher or hash-based approach is used, confirm it's applied system-wide"
Write-Host "3. Test execution of unauthorized files in these locations (see test files in next section)"
#endregion

#region ML1-AC-03: Application control restricts execution to an organisation-approved set
Write-Host "`n[ML1-AC-03] Checking if application control restricts execution to an organisation-approved set..." -ForegroundColor Blue

# Create test files for manual verification
$testFilesDir = Join-Path -Path $resultsDir -ChildPath "TestFiles"
if (-not (Test-Path -Path $testFilesDir)) {
    New-Item -Path $testFilesDir -ItemType Directory | Out-Null
}

# Function to create test files
function Create-TestFile {
    param (
        [Parameter(Mandatory=$true)]
        [string]$FilePath,
        
        [Parameter(Mandatory=$true)]
        [string]$Content,
        
        [Parameter(Mandatory=$false)]
        [string]$Description = ""
    )
    
    try {
        Set-Content -Path $FilePath -Value $Content -Force
        Write-Host "Created test file $FilePath" -ForegroundColor Green
        if (-not [string]::IsNullOrEmpty($Description)) {
            Write-Host $Description -ForegroundColor Cyan
        }
    } catch {
        Write-Host "Error creating test file $FilePath $_" -ForegroundColor Red
    }
}

Write-Host "`nCreating test files for manual verification..." -ForegroundColor Yellow

# 1. Executable (EXE)
$exeTestFile = Join-Path -Path $testFilesDir -ChildPath "TestExecutable.exe"
$exeContent = @'
4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00
B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 E8 00 00 00
0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68
69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F
74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20
6D 6F 64 65 2E 0D 0D 0A 24 00 00 00 00 00 00 00
'@
Create-TestFile -FilePath $exeTestFile -Content $exeContent -Description "This is a benign executable test file. It's a minimal valid EXE file that does nothing."

# 2. DLL file
$dllTestFile = Join-Path -Path $testFilesDir -ChildPath "TestLibrary.dll"
$dllContent = @'
4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00
B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 E8 00 00 00
0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68
69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F
74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20
6D 6F 64 65 2E 0D 0D 0A 24 00 00 00 00 00 00 00
'@
Create-TestFile -FilePath $dllTestFile -Content $dllContent -Description "This is a benign DLL test file. It's a minimal valid DLL file structure that does nothing."

# 3. PowerShell script
$psTestFile = Join-Path -Path $testFilesDir -ChildPath "TestScript.ps1"
$psContent = @'
# This is a benign PowerShell test script
Write-Host "Application Control Test Script"
Write-Host "This script should be blocked by application control"
pause
'@
Create-TestFile -FilePath $psTestFile -Content $psContent -Description "This is a benign PowerShell script for testing."

# 4. VBScript file
$vbsTestFile = Join-Path -Path $testFilesDir -ChildPath "TestScript.vbs"
$vbsContent = @'
' This is a benign VBScript test file
MsgBox "Application Control Test Script" & vbCrLf & "This script should be blocked by application control", vbInformation, "AppControl Test"
'@
Create-TestFile -FilePath $vbsTestFile -Content $vbsContent -Description "This is a benign VBScript for testing."

# 5. Batch file
$batTestFile = Join-Path -Path $testFilesDir -ChildPath "TestScript.bat"
$batContent = @'
@echo off
echo Application Control Test Script
echo This script should be blocked by application control
pause
'@
Create-TestFile -FilePath $batTestFile -Content $batContent -Description "This is a benign Batch file for testing."

# 6. JavaScript file
$jsTestFile = Join-Path -Path $testFilesDir -ChildPath "TestScript.js"
$jsContent = @'
// This is a benign JavaScript test file
alert("Application Control Test Script\nThis script should be blocked by application control");
'@
Create-TestFile -FilePath $jsTestFile -Content $jsContent -Description "This is a benign JavaScript file for testing."

# 7. MSI installer
$msiTestFile = Join-Path -Path $testFilesDir -ChildPath "TestInstaller.msi"
$msiContent = @'
D0 CF 11 E0 A1 B1 1A E1 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 3E 00 03 00 FE FF 09 00
06 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00
01 00 00 00 00 00 00 00 00 10 00 00 02 00 00 00
01 00 00 00 FE FF FF FF 00 00 00 00 00 00 00 00
FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF FF
'@
Create-TestFile -FilePath $msiTestFile -Content $msiContent -Description "This is a minimal MSI file structure for testing. It's not a valid installer but has the MSI signature."

# 8. Compiled HTML Help file
$chmTestFile = Join-Path -Path $testFilesDir -ChildPath "TestHelp.chm"
$chmContent = @'
49 54 53 46 03 00 00 00 60 00 00 00 01 00 00 00
4B 00 00 00 00 10 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 01 00 00 00
42 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
'@
Create-TestFile -FilePath $chmTestFile -Content $chmContent -Description "This is a minimal CHM file structure for testing. It's not a valid help file but has the CHM signature."

# 9. HTML Application file
$htaTestFile = Join-Path -Path $testFilesDir -ChildPath "TestApp.hta"
$htaContent = @'
<!DOCTYPE html>
<html>
<head>
<title>Application Control Test HTA</title>
<HTA:APPLICATION 
    ID="AppControlTest"
    APPLICATIONNAME="AppControl Test"
    BORDER="thin"
    BORDERSTYLE="normal"
    CAPTION="yes"
    MAXIMIZEBUTTON="yes"
    MINIMIZEBUTTON="yes"
    SHOWINTASKBAR="yes"
    SINGLEINSTANCE="yes"
    SYSMENU="yes"
    VERSION="1.0"
    WINDOWSTATE="normal">
</head>
<body>
    <h1>Application Control Test</h1>
    <p>This HTA should be blocked by application control</p>
    <script language="VBScript">
        Sub Window_OnLoad
            MsgBox "Application Control Test HTA loaded", vbInformation, "AppControl Test"
        End Sub
    </script>
</body>
</html>
'@
Create-TestFile -FilePath $htaTestFile -Content $htaContent -Description "This is a benign HTA file for testing."

# 10. Control Panel applet
$cplTestFile = Join-Path -Path $testFilesDir -ChildPath "TestPanel.cpl"
$cplContent = @'
4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00
B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
00 00 00 00 00 00 00 00 00 00 00 00 E8 00 00 00
0E 1F BA 0E 00 B4 09 CD 21 B8 01 4C CD 21 54 68
69 73 20 70 72 6F 67 72 61 6D 20 63 61 6E 6E 6F
74 20 62 65 20 72 75 6E 20 69 6E 20 44 4F 53 20
6D 6F 64 65 2E 0D 0D 0A 24 00 00 00 00 00 00 00
'@
Create-TestFile -FilePath $cplTestFile -Content $cplContent -Description "This is a minimal CPL file structure for testing. It's not a valid control panel applet but has the CPL signature."

# Create test script for copying and executing files
$testScriptFile = Join-Path -Path $testFilesDir -ChildPath "RunTests.ps1"
$testScriptContent = @"
<#
.SYNOPSIS
    Application Control Test Script
.DESCRIPTION
    This script helps test application control by copying test files to user profile 
    and temporary folders and attempting to execute them.
.NOTES
    IMPORTANT: This script should be run with standard user privileges, not as administrator.
#>

# Define test locations
`$testLocations = @(
    [System.Environment]::GetFolderPath('UserProfile'),
    [System.Environment]::GetFolderPath('Desktop'),
    [System.Environment]::GetFolderPath('MyDocuments'),
    [System.Environment]::GetFolderPath('LocalApplicationData'),
    [System.IO.Path]::GetTempPath()
)

# Source test files
`$sourceDir = '$testFilesDir'
`$testFiles = @(
    @{Name = "TestExecutable.exe"; Type = "Executable"; ExpectedBlocked = `$true},
    @{Name = "TestLibrary.dll"; Type = "Library"; ExpectedBlocked = `$true},
    @{Name = "TestScript.ps1"; Type = "PowerShell Script"; ExpectedBlocked = `$true},
    @{Name = "TestScript.vbs"; Type = "VBScript"; ExpectedBlocked = `$true},
    @{Name = "TestScript.bat"; Type = "Batch File"; ExpectedBlocked = `$true},
    @{Name = "TestScript.js"; Type = "JavaScript"; ExpectedBlocked = `$true},
    @{Name = "TestInstaller.msi"; Type = "MSI Installer"; ExpectedBlocked = `$true},
    @{Name = "TestHelp.chm"; Type = "Compiled HTML"; ExpectedBlocked = `$true},
    @{Name = "TestApp.hta"; Type = "HTML Application"; ExpectedBlocked = `$true},
    @{Name = "TestPanel.cpl"; Type = "Control Panel Applet"; ExpectedBlocked = `$true}
)

# Function to test file execution
function Test-FileExecution {
    param (
        [string]`$FilePath,
        [string]`$FileType
    )
    
    `$blocked = `$false
    `$result = "UNKNOWN"
    
    try {
        switch -Regex (`$FilePath) {
            '\.exe$' {
                Start-Process -FilePath `$FilePath -ErrorAction Stop
                `$result = "NOT BLOCKED"
            }
            '\.dll$' {
                # Try to load DLL using rundll32
                Start-Process -FilePath "rundll32.exe" -ArgumentList "`$FilePath,DllMain" -ErrorAction Stop
                `$result = "NOT BLOCKED"
            }
            '\.ps1$' {
                # Try to execute PowerShell script
                PowerShell -File `$FilePath -ErrorAction Stop
                `$result = "NOT BLOCKED"
            }
            '\.vbs$' {
                # Try to execute VBScript
                Start-Process -FilePath "cscript.exe" -ArgumentList "`$FilePath" -ErrorAction Stop
                `$result = "NOT BLOCKED"
            }
            '\.bat$' {
                # Try to execute batch file
                Start-Process -FilePath `$FilePath -ErrorAction Stop
                `$result = "NOT BLOCKED"
            }
            '\.js$' {
                # Try to execute JavaScript
                Start-Process -FilePath "wscript.exe" -ArgumentList "`$FilePath" -ErrorAction Stop
                `$result = "NOT BLOCKED"
            }
            '\.msi$' {
                # Try to execute MSI installer
                Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `$FilePath" -ErrorAction Stop
                `$result = "NOT BLOCKED"
            }
            '\.chm$' {
                # Try to open CHM file
                Start-Process -FilePath `$FilePath -ErrorAction Stop
                `$result = "NOT BLOCKED"
            }
            '\.hta$' {
                # Try to execute HTA file
                Start-Process -FilePath "mshta.exe" -ArgumentList "`$FilePath" -ErrorAction Stop
                `$result = "NOT BLOCKED"
            }
            '\.cpl$' {
                # Try to execute Control Panel applet
                Start-Process -FilePath "control.exe" -ArgumentList "`$FilePath" -ErrorAction Stop
                `$result = "NOT BLOCKED"
            }
        }
    } catch {
        `$blocked = `$true
        `$result = "BLOCKED: `$(`$_.Exception.Message)"
    }
    
    return @{
        Blocked = `$blocked
        Result = `$result
    }
}

# Create results directory
`$resultsDir = Join-Path -Path `$env:USERPROFILE -ChildPath "AppControlTestResults"
if (-not (Test-Path -Path `$resultsDir)) {
    New-Item -Path `$resultsDir -ItemType Directory | Out-Null
}

# Create results file
`$resultsFile = Join-Path -Path `$resultsDir -ChildPath "TestResults_`$(Get-Date -Format 'yyyyMMdd_HHmmss').txt"
"APPLICATION CONTROL TEST RESULTS" | Out-File -FilePath `$resultsFile
"Date: `$(Get-Date)" | Out-File -FilePath `$resultsFile -Append
"Computer: `$env:COMPUTERNAME" | Out-File -FilePath `$resultsFile -Append
"User: `$env:USERNAME" | Out-File -FilePath `$resultsFile -Append
"" | Out-File -FilePath `$resultsFile -Append

foreach (`$location in `$testLocations) {
    Write-Host "`nTesting location: `$location" -ForegroundColor Cyan
    "LOCATION: `$location" | Out-File -FilePath `$resultsFile -Append
    
    foreach (`$file in `$testFiles) {
        Write-Host "Testing `$(`$file.Type): `$(`$file.Name)" -ForegroundColor Yellow
        
        # Copy test file to location
        `$destinationPath = Join-Path -Path `$location -ChildPath `$file.Name
        try {
            Copy-Item -Path (Join-Path -Path `$sourceDir -ChildPath `$file.Name) -Destination `$destinationPath -Force
            Write-Host "  Copied to `$destinationPath" -ForegroundColor Green
            
            # Test execution
            `$testResult = Test-FileExecution -FilePath `$destinationPath -FileType `$file.Type
            
            if (`$testResult.Blocked) {
                Write-Host "  BLOCKED - Application control prevented execution" -ForegroundColor Green
                "`$(`$file.Type) (`$(`$file.Name)): BLOCKED" | Out-File -FilePath `$resultsFile -Append
            } else {
                Write-Host "  NOT BLOCKED - File executed successfully" -ForegroundColor Red
                "`$(`$file.Type) (`$(`$file.Name)): NOT BLOCKED" | Out-File -FilePath `$resultsFile -Append
            }
            
            # Clean up
            Remove-Item -Path `$destinationPath -Force -ErrorAction SilentlyContinue
        } catch {
            Write-Host "  Error: `$_" -ForegroundColor Red
            "`$(`$file.Type) (`$(`$file.Name)): ERROR - `$_" | Out-File -FilePath `$resultsFile -Append
        }
    }
    
    "" | Out-File -FilePath `$resultsFile -Append
}

Write-Host "`nTesting complete. Results saved to: `$resultsFile" -ForegroundColor Green
Write-Host "Press any key to exit..."
`$null = `$Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
"@
Create-TestFile -FilePath $testScriptFile -Content $testScriptContent -Description "This script helps test application control by copying test files to user profile and temporary folders and attempting to execute them."

# Overall result for ML1-AC-03
# This is primarily a manual check, so we can only provide instructions
Write-CheckResult -CheckID "ML1-AC-03" -Description "Application control restricts execution to an organisation-approved set" `
    -Result "Manual verification required" -Status "MANUAL"

Write-Host "`nManual verification required for ML1-AC-03" -ForegroundColor Yellow
Write-Host "1. Verify the organization has an approved set of applications"
Write-Host "2. Compare application control policies to the approved set"
Write-Host "3. Use the provided test files to verify application control is functioning"
Write-Host "4. Execute the RunTests.ps1 script to automatically test execution in different folders"
Write-Host "   - Run this script with standard user privileges, not as administrator"
Write-Host "   - Check the generated results file for any 'NOT BLOCKED' entries"
Write-Host "5. Tests should show that application control blocks execution of the test files"
#endregion

# Create instruction document
$instructionsFile = Join-Path -Path $resultsDir -ChildPath "AppControlTestInstructions.txt"
$instructionsContent = @"
APPLICATION CONTROL TESTING INSTRUCTIONS
========================================

BACKGROUND
----------
These tests verify compliance with the following requirements:
ML1-AC-01: Application control is implemented on workstations
ML1-AC-02: Application control is applied to user profiles and temporary folders
ML1-AC-03: Application control restricts execution to an organisation-approved set

TEST FILES
----------
The following test files have been created in $testFilesDir
- TestExecutable.exe: A benign executable file
- TestLibrary.dll: A benign software library
- TestScript.ps1: A PowerShell script
- TestScript.vbs: A VBScript file
- TestScript.bat: A batch file
- TestScript.js: A JavaScript file
- TestInstaller.msi: An MSI installer
- TestHelp.chm: A compiled HTML help file
- TestApp.hta: An HTML application
- TestPanel.cpl: A control panel applet

AUTOMATED TESTING
----------------
1. Open PowerShell as a standard user (not administrator)
2. Navigate to the test files directory: cd "$testFilesDir"
3. Run the test script: .\RunTests.ps1
4. The script will:
   - Copy each test file to various user profile and temporary folders
   - Attempt to execute each file
   - Record the results to a log file
5. Review the results to verify that application control blocks execution

MANUAL TESTING
-------------
If you prefer to test manually:
1. Copy TestExecutable.exe to your desktop
2. Try to run it - application control should block it
3. Repeat with the other test files

INTERPRETING RESULTS
-------------------
- ML1-AC-01: Application control is implemented if any solutions were detected by the script
- ML1-AC-02: Application control covers user profiles and temp folders if:
  - A publisher or hash-based solution is implemented, OR
  - Path-based rules include these locations
- ML1-AC-03: Application control restricts execution to approved set if:
  - The organization has a documented approved application set
  - The application control policy enforces this set
  - Test files are blocked from executing in user profiles and temp folders

ADDITIONAL VERIFICATION
----------------------
- Check Group Policy to review application control settings
- Verify that users cannot disable or bypass application control
- Confirm that application control is enabled system-wide
- Test execution of the test files in various locations

NOTE: Keep the test files secure and delete them after testing is complete.
"@
Set-Content -Path $instructionsFile -Value $instructionsContent -Force
Write-Host "`nCreated test instructions at $instructionsFile" -ForegroundColor Cyan

# Summary of all checks
Write-Host "`n=========================================================" -ForegroundColor Green
Write-Host "                 SUMMARY OF FINDINGS                    " -ForegroundColor Green
Write-Host "=========================================================" -ForegroundColor Green

Write-Host "`nA full log of this check has been saved to $logFile"
Write-Host "`nTest files and instructions have been created in $resultsDir"
Write-Host "Please follow the instructions in AppControlTestInstructions.txt to complete the verification."

Stop-Transcript
