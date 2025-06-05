# ML2-AH Application Hardening Verification Script
# Run this script with appropriate permissions

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "ML2-AH Application Hardening Controls Check" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# ML2-AH-01 Web browser hardening
Write-Host "ML2-AH-01 - Web Browser Hardening" -ForegroundColor Yellow
Write-Host "Checking for installed browsers and their policies..."

# Check for Edge
$edgeInstalled = Test-Path "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\msedge.exe"
if ($edgeInstalled) {
    Write-Host "Microsoft Edge is installed" -ForegroundColor Green
    $edgePolicies = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Edge" -ErrorAction SilentlyContinue
    if ($edgePolicies) {
        Write-Host "  Edge policies are configured via GPO" -ForegroundColor Green
        Write-Host "  Number of policy settings $($edgePolicies.PSObject.Properties.Name.Count)" -ForegroundColor Gray
    } else {
        Write-Host "  No Edge group policies detected" -ForegroundColor Yellow
    }
}

# Check for Chrome
$chromeInstalled = Test-Path "${env:ProgramFiles(x86)}\Google\Chrome\Application\chrome.exe"
if ($chromeInstalled) {
    Write-Host "Google Chrome is installed" -ForegroundColor Green
    $chromePolicies = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Google\Chrome" -ErrorAction SilentlyContinue
    if ($chromePolicies) {
        Write-Host "  Chrome policies are configured via GPO" -ForegroundColor Green
        Write-Host "  Number of policy settings $($chromePolicies.PSObject.Properties.Name.Count)" -ForegroundColor Gray
    } else {
        Write-Host "  No Chrome group policies detected" -ForegroundColor Yellow
    }
}
Write-Host ""

# ML2-AH-02 Microsoft Office child process blocking
Write-Host "ML2-AH-02 - Microsoft Office Child Process Blocking" -ForegroundColor Yellow
Write-Host "Checking ASR rule for blocking Office child processes..."

try {
    $ASRRules = (Get-MpPreference).AttackSurfaceReductionRules_Ids
    $ASRActions = (Get-MpPreference).AttackSurfaceReductionRules_Actions
    
    $childProcessRule = "d4f940ab-401b-4efc-aadc-ad5f3c50688a"
    $ruleIndex = [array]::IndexOf($ASRRules, $childProcessRule)
    
    if ($ruleIndex -ge 0) {
        $action = $ASRActions[$ruleIndex]
        if ($action -eq 1) {
            Write-Host "Office child process blocking is ENABLED (Block mode)" -ForegroundColor Green
        } elseif ($action -eq 2) {
            Write-Host "Office child process blocking is in AUDIT mode" -ForegroundColor Yellow
        } else {
            Write-Host "Office child process blocking is DISABLED" -ForegroundColor Red
        }
    } else {
        Write-Host "Office child process blocking rule is NOT configured" -ForegroundColor Red
    }
} catch {
    Write-Host "Unable to query ASR rules - Windows Defender may not be active" -ForegroundColor Gray
}
Write-Host ""

# ML2-AH-03 Microsoft Office executable content blocking
Write-Host "ML2-AH-03 - Microsoft Office Executable Content Blocking" -ForegroundColor Yellow
Write-Host "Checking ASR rule for blocking Office executable content..."

try {
    $execContentRule = "3b576869-a4ec-4529-8536-b80a7769e899"
    $ruleIndex = [array]::IndexOf($ASRRules, $execContentRule)
    
    if ($ruleIndex -ge 0) {
        $action = $ASRActions[$ruleIndex]
        if ($action -eq 1) {
            Write-Host "Office executable content blocking is ENABLED (Block mode)" -ForegroundColor Green
        } elseif ($action -eq 2) {
            Write-Host "Office executable content blocking is in AUDIT mode" -ForegroundColor Yellow
        } else {
            Write-Host "Office executable content blocking is DISABLED" -ForegroundColor Red
        }
    } else {
        Write-Host "Office executable content blocking rule is NOT configured" -ForegroundColor Red
    }
} catch {
    Write-Host "Unable to query ASR rules" -ForegroundColor Gray
}
Write-Host ""

# ML2-AH-04 Microsoft Office code injection blocking
Write-Host "ML2-AH-04 - Microsoft Office Code Injection Blocking" -ForegroundColor Yellow
Write-Host "Checking ASR rule for blocking Office code injection..."

try {
    $codeInjectionRule = "75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84"
    $ruleIndex = [array]::IndexOf($ASRRules, $codeInjectionRule)
    
    if ($ruleIndex -ge 0) {
        $action = $ASRActions[$ruleIndex]
        if ($action -eq 1) {
            Write-Host "Office code injection blocking is ENABLED (Block mode)" -ForegroundColor Green
        } elseif ($action -eq 2) {
            Write-Host "Office code injection blocking is in AUDIT mode" -ForegroundColor Yellow
        } else {
            Write-Host "Office code injection blocking is DISABLED" -ForegroundColor Red
        }
    } else {
        Write-Host "Office code injection blocking rule is NOT configured" -ForegroundColor Red
    }
} catch {
    Write-Host "Unable to query ASR rules" -ForegroundColor Gray
}
Write-Host ""

# ML2-AH-05 OLE package blocking
Write-Host "ML2-AH-05 - OLE Package Activation Prevention" -ForegroundColor Yellow
Write-Host "Checking Office OLE package settings..."

$officeApps = @("excel", "word", "powerpoint", "outlook")
foreach ($app in $officeApps) {
    try {
        $packagerPrompt = Get-ItemProperty -Path "HKCU:\SOFTWARE\Microsoft\office\16.0\$app\security\" -Name PackagerPrompt -ErrorAction SilentlyContinue
        if ($packagerPrompt.PackagerPrompt -eq 2) {
            Write-Host "$app OLE packages are BLOCKED (PackagerPrompt=2)" -ForegroundColor Green
        } elseif ($packagerPrompt.PackagerPrompt -eq 1) {
            Write-Host "$app OLE packages show WARNING prompt (PackagerPrompt=1)" -ForegroundColor Yellow
        } else {
            Write-Host "$app OLE packages are ALLOWED (PackagerPrompt=0)" -ForegroundColor Red
        }
    } catch {
        Write-Host "$app OLE package setting not found" -ForegroundColor Gray
    }
}
Write-Host ""

# ML2-AH-06 Office hardening check
Write-Host "ML2-AH-06 - Office Productivity Suite Hardening" -ForegroundColor Yellow
Write-Host "Checking for Office installation and policies..."

$officeInstalled = Test-Path "${env:ProgramFiles}\Microsoft Office\root\Office16"
if ($officeInstalled) {
    Write-Host "Microsoft Office 2016/2019/365 is installed" -ForegroundColor Green
    
    # Check if Office policies exist
    $officePolicies = Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Office"
    if ($officePolicies) {
        Write-Host "Office policies are configured via GPO" -ForegroundColor Green
    } else {
        Write-Host "No Office group policies detected" -ForegroundColor Yellow
    }
}
Write-Host ""

# ML2-AH-07 Office security settings protection
Write-Host "ML2-AH-07 - Office Security Settings Protection" -ForegroundColor Yellow
Write-Host "Checking if Office security settings are enforced by policy..."

foreach ($app in $officeApps) {
    try {
        $vbaWarnings = Get-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\office\16.0\$app\security\" -Name vbawarnings -ErrorAction SilentlyContinue
        if ($vbaWarnings) {
            Write-Host "$app VBA warnings are ENFORCED by policy (value=$($vbaWarnings.vbawarnings))" -ForegroundColor Green
        } else {
            Write-Host "$app VBA warnings are NOT enforced by policy" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "$app VBA policy setting not found" -ForegroundColor Gray
    }
}
Write-Host ""

# ML2-AH-08 PDF reader child process blocking
Write-Host "ML2-AH-08 - PDF Software Child Process Blocking" -ForegroundColor Yellow
Write-Host "Checking ASR rule for blocking Adobe Reader child processes..."

try {
    $pdfRule = "7674BA52-37EB-4A4F-A9A1-F0F9A1619A2C"
    $ruleIndex = [array]::IndexOf($ASRRules, $pdfRule)
    
    if ($ruleIndex -ge 0) {
        $action = $ASRActions[$ruleIndex]
        if ($action -eq 1) {
            Write-Host "Adobe Reader child process blocking is ENABLED (Block mode)" -ForegroundColor Green
        } elseif ($action -eq 2) {
            Write-Host "Adobe Reader child process blocking is in AUDIT mode" -ForegroundColor Yellow
        } else {
            Write-Host "Adobe Reader child process blocking is DISABLED" -ForegroundColor Red
        }
    } else {
        Write-Host "Adobe Reader child process blocking rule is NOT configured" -ForegroundColor Red
    }
} catch {
    Write-Host "Unable to query ASR rules" -ForegroundColor Gray
}
Write-Host ""

# ML2-AH-09 & ML2-AH-10 PDF hardening
Write-Host "ML2-AH-09/10 - PDF Software Hardening" -ForegroundColor Yellow
Write-Host "Checking for installed PDF readers..."

$adobeReader = Test-Path "${env:ProgramFiles(x86)}\Adobe\Acrobat Reader DC\Reader\AcroRd32.exe"
if ($adobeReader) {
    Write-Host "Adobe Reader DC is installed" -ForegroundColor Green
    
    # Check for Adobe policies
    $adobePolicies = Test-Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader"
    if ($adobePolicies) {
        Write-Host "Adobe Reader policies are configured" -ForegroundColor Green
    } else {
        Write-Host "No Adobe Reader policies detected" -ForegroundColor Yellow
    }
}
Write-Host ""

# ML2-AH-11 PowerShell logging
Write-Host "ML2-AH-11 - PowerShell Logging Configuration" -ForegroundColor Yellow
Write-Host "Checking PowerShell logging settings..."

# Module logging
$moduleLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" -ErrorAction SilentlyContinue
if ($moduleLogging.EnableModuleLogging -eq 1) {
    Write-Host "PowerShell Module Logging is ENABLED" -ForegroundColor Green
    $moduleNames = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" -ErrorAction SilentlyContinue
    if ($moduleNames.'*' -eq '*') {
        Write-Host "  Logging ALL modules (*)" -ForegroundColor Green
    } else {
        Write-Host "  Logging specific modules only" -ForegroundColor Yellow
    }
} else {
    Write-Host "PowerShell Module Logging is DISABLED" -ForegroundColor Red
}

# Script block logging
$scriptBlockLogging = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -ErrorAction SilentlyContinue
if ($scriptBlockLogging.EnableScriptBlockLogging -eq 1) {
    Write-Host "PowerShell Script Block Logging is ENABLED" -ForegroundColor Green
} else {
    Write-Host "PowerShell Script Block Logging is DISABLED" -ForegroundColor Red
}

# Transcription
$transcription = Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -ErrorAction SilentlyContinue
if ($transcription.EnableTranscripting -eq 1) {
    Write-Host "PowerShell Transcription is ENABLED" -ForegroundColor Green
    if ($transcription.OutputDirectory) {
        Write-Host "  Output directory $($transcription.OutputDirectory)" -ForegroundColor Gray
    }
} else {
    Write-Host "PowerShell Transcription is DISABLED" -ForegroundColor Red
}
Write-Host ""

# ML2-AH-12 Command line auditing
Write-Host "ML2-AH-12 - Command Line Process Creation Logging" -ForegroundColor Yellow
Write-Host "Checking command line auditing settings..."

# Check process creation auditing
$auditPolicy = auditpol /get /subcategory:"Process Creation" /r | ConvertFrom-Csv | Where-Object {$_."Subcategory" -eq "Process Creation"}
if ($auditPolicy."Inclusion Setting" -match "Success") {
    Write-Host "Process Creation auditing is ENABLED" -ForegroundColor Green
} else {
    Write-Host "Process Creation auditing is DISABLED" -ForegroundColor Red
}

# Check command line inclusion
$cmdLineAudit = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue
if ($cmdLineAudit.ProcessCreationIncludeCmdLine_Enabled -eq 1) {
    Write-Host "Command line inclusion in process creation events is ENABLED" -ForegroundColor Green
} else {
    Write-Host "Command line inclusion in process creation events is DISABLED" -ForegroundColor Red
}
Write-Host ""

# ML2-AH-13 Event log protection (same as ML2-RA-08)
Write-Host "ML2-AH-13 - Event Log Protection" -ForegroundColor Yellow
Write-Host "Checking event log permissions and settings..."

$logs = @("Application", "Security", "System", "Microsoft-Windows-PowerShell/Operational")
foreach ($logName in $logs) {
    try {
        $log = Get-WinEvent -ListLog $logName -ErrorAction SilentlyContinue
        if ($log) {
            $maxSize = [math]::Round($log.MaximumSizeInBytes / 1MB, 2)
            Write-Host "$logName log - Max size ${maxSize}MB, Enabled $($log.IsEnabled)" -ForegroundColor Gray
        }
    } catch {
        Write-Host "Unable to query $logName log" -ForegroundColor Gray
    }
}
Write-Host ""

# ML2-AH-14 to ML2-AH-18 are process checks
Write-Host "ML2-AH-14 to ML2-AH-18 - Incident Response Process Checks" -ForegroundColor Yellow
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
Write-Host "Note This script provides automated checks for ML2-AH controls." -ForegroundColor White
Write-Host "Manual verification and additional testing may be required." -ForegroundColor White
Write-Host "Some checks require administrative privileges to run successfully." -ForegroundColor White
Write-Host ""
Write-Host "Critical findings in RED require immediate attention." -ForegroundColor Red
Write-Host "Findings in YELLOW should be reviewed for potential improvements." -ForegroundColor Yellow
Write-Host "Findings in GREEN indicate properly configured controls." -ForegroundColor Green
