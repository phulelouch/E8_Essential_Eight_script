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

# ML2-AH-13 Event Log Protection Verification Script
# Run this script with appropriate permissions

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "ML2-AH-13 - Event Log Protection Check" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Function to check permissions on event log files
function Get-EventLogPermissions {
    param([string]$LogName)
    
    try {
        # Get the log file path
        $log = Get-WinEvent -ListLog $LogName -ErrorAction Stop
        $logPath = $log.LogFilePath
        
        if (Test-Path $logPath) {
            $acl = Get-Acl -Path $logPath
            return $acl
        }
    } catch {
        return $null
    }
}

# Function to check registry permissions for event log configuration
function Get-EventLogRegistryPermissions {
    param([string]$LogName)
    
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\$LogName"
    try {
        if (Test-Path $regPath) {
            $acl = Get-Acl -Path $regPath
            return $acl
        }
    } catch {
        return $null
    }
}

Write-Host "Current User Context" -ForegroundColor Yellow
$currentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
Write-Host "Running as $($currentUser.Name)"
$principal = New-Object System.Security.Principal.WindowsPrincipal($currentUser)
$isAdmin = $principal.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "Administrator privileges $isAdmin"
Write-Host ""

# Check critical event logs
$criticalLogs = @("Security", "System", "Application", "Microsoft-Windows-PowerShell/Operational")

Write-Host "Checking Event Log File Permissions" -ForegroundColor Yellow
Write-Host "=====================================" -ForegroundColor Gray

foreach ($logName in $criticalLogs) {
    Write-Host ""
    Write-Host "Log $logName" -ForegroundColor Cyan
    
    # Get log configuration
    try {
        $log = Get-WinEvent -ListLog $logName -ErrorAction Stop
        Write-Host "  Log enabled $($log.IsEnabled)"
        Write-Host "  Max size $([math]::Round($log.MaximumSizeInBytes / 1MB, 2)) MB"
        Write-Host "  Retention policy $($log.LogMode)"
        
        # Check file permissions
        $acl = Get-EventLogPermissions -LogName $logName
        if ($acl) {
            Write-Host "  File path $($log.LogFilePath)" -ForegroundColor Gray
            
            # Check for dangerous permissions
            $dangerousPermissions = @()
            foreach ($access in $acl.Access) {
                $identity = $access.IdentityReference.Value
                $rights = $access.FileSystemRights
                
                # Check if non-admin users have write/delete permissions
                if ($identity -match "Users|Everyone|Authenticated Users") {
                    if ($rights -match "Write|Delete|ChangePermissions|TakeOwnership") {
                        $dangerousPermissions += "    WARNING - $identity has $rights" 
                    }
                }
            }
            
            if ($dangerousPermissions.Count -gt 0) {
                Write-Host "  File permissions VULNERABLE" -ForegroundColor Red
                $dangerousPermissions | ForEach-Object { Write-Host $_ -ForegroundColor Red }
            } else {
                Write-Host "  File permissions SECURE (no write/delete for standard users)" -ForegroundColor Green
            }
        }
    } catch {
        Write-Host "  Unable to query log configuration" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "Checking Event Log Registry Permissions" -ForegroundColor Yellow
Write-Host "=======================================" -ForegroundColor Gray

foreach ($logName in $criticalLogs) {
    Write-Host ""
    Write-Host "Registry for $logName" -ForegroundColor Cyan
    
    $acl = Get-EventLogRegistryPermissions -LogName $logName
    if ($acl) {
        $dangerousPermissions = @()
        foreach ($access in $acl.Access) {
            $identity = $access.IdentityReference.Value
            $rights = $access.RegistryRights
            
            # Check if non-admin users have write permissions
            if ($identity -match "Users|Everyone|Authenticated Users") {
                if ($rights -match "WriteKey|ChangePermissions|TakeOwnership|Delete") {
                    $dangerousPermissions += "    WARNING - $identity has $rights"
                }
            }
        }
        
        if ($dangerousPermissions.Count -gt 0) {
            Write-Host "  Registry permissions VULNERABLE" -ForegroundColor Red
            $dangerousPermissions | ForEach-Object { Write-Host $_ -ForegroundColor Red }
        } else {
            Write-Host "  Registry permissions SECURE" -ForegroundColor Green
        }
    } else {
        Write-Host "  Unable to check registry permissions" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "Checking Event Log Service Configuration" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Gray

# Check Windows Event Log service
$eventLogService = Get-Service -Name EventLog -ErrorAction SilentlyContinue
if ($eventLogService) {
    Write-Host "Windows Event Log service status $($eventLogService.Status)"
    if ($eventLogService.Status -eq "Running") {
        Write-Host "  Service is running properly" -ForegroundColor Green
    } else {
        Write-Host "  Service is not running!" -ForegroundColor Red
    }
    
    # Check service permissions
    $serviceSddl = sc.exe sdshow EventLog
    if ($serviceSddl -match "D:") {
        Write-Host "  Service permissions configured" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "Checking Audit Policies for Event Log Protection" -ForegroundColor Yellow
Write-Host "================================================" -ForegroundColor Gray

# Check if event log clearing is audited
$auditCategories = @(
    @{Name="Audit Policy Change"; Expected="Success and Failure"},
    @{Name="System Integrity"; Expected="Success and Failure"}
)

foreach ($category in $auditCategories) {
    $result = auditpol /get /subcategory:"$($category.Name)" /r | ConvertFrom-Csv | Where-Object {$_."Subcategory" -eq $category.Name}
    if ($result) {
        if ($result."Inclusion Setting" -match "Success and Failure") {
            Write-Host "$($category.Name) auditing is FULLY ENABLED" -ForegroundColor Green
        } elseif ($result."Inclusion Setting" -match "Success|Failure") {
            Write-Host "$($category.Name) auditing is PARTIALLY enabled ($($result.'Inclusion Setting'))" -ForegroundColor Yellow
        } else {
            Write-Host "$($category.Name) auditing is DISABLED" -ForegroundColor Red
        }
    }
}

Write-Host ""
Write-Host "Checking Group Policy Settings for Event Log Protection" -ForegroundColor Yellow
Write-Host "======================================================" -ForegroundColor Gray

# Check for specific GPO settings
$gpoSettings = @(
    @{Path="HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\Security"; Name="RestrictGuestAccess"; Expected=1},
    @{Path="HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security"; Name="Retention"; Expected=0}
)

foreach ($setting in $gpoSettings) {
    try {
        $value = Get-ItemProperty -Path $setting.Path -Name $setting.Name -ErrorAction Stop
        if ($value.($setting.Name) -eq $setting.Expected) {
            Write-Host "$($setting.Name) is properly configured" -ForegroundColor Green
        } else {
            Write-Host "$($setting.Name) is not set to recommended value" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "$($setting.Name) policy not configured" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "Testing Current User's Ability to Modify Logs" -ForegroundColor Yellow
Write-Host "=============================================" -ForegroundColor Gray

if (-not $isAdmin) {
    Write-Host "Running as standard user - attempting to test log access..."
    
    # Test ability to clear event log (should fail)
    try {
        # This should fail for non-admins
        Clear-EventLog -LogName "Application" -ErrorAction Stop
        Write-Host "WARNING - User CAN clear Application log!" -ForegroundColor Red
    } catch {
        Write-Host "User CANNOT clear Application log (Good)" -ForegroundColor Green
    }
    
    # Test ability to modify log settings
    try {
        $testLog = Get-WinEvent -ListLog "Application" -ErrorAction Stop
        $testLog.MaximumSizeInBytes = 1MB
        $testLog.SaveChanges()
        Write-Host "WARNING - User CAN modify log settings!" -ForegroundColor Red
    } catch {
        Write-Host "User CANNOT modify log settings (Good)" -ForegroundColor Green
    }
} else {
    Write-Host "Running as administrator - skipping modification tests"
    Write-Host "Run this script as a standard user to test protection against unauthorized access"
}

Write-Host ""
Write-Host "Additional Security Recommendations" -ForegroundColor Yellow
Write-Host "===================================" -ForegroundColor Gray

# Check for event log forwarding
$wecutil = Get-Command wecutil -ErrorAction SilentlyContinue
if ($wecutil) {
    try {
        $subscriptions = & wecutil es 2>$null
        if ($subscriptions) {
            Write-Host "Event log forwarding is CONFIGURED" -ForegroundColor Green
            Write-Host "  Active subscriptions $($subscriptions.Count)" -ForegroundColor Green
        } else {
            Write-Host "Event log forwarding is NOT configured" -ForegroundColor Yellow
        }
    } catch {
        Write-Host "Unable to check event log forwarding" -ForegroundColor Gray
    }
} else {
    Write-Host "Windows Event Collector service not available" -ForegroundColor Gray
}

# Check for SIEM agent
$siemAgents = @(
    @{Name="Splunk Universal Forwarder"; Service="SplunkForwarder"},
    @{Name="Windows Defender ATP"; Service="Sense"},
    @{Name="Sysmon"; Service="Sysmon*"}
)

Write-Host ""
Write-Host "Checking for SIEM/Monitoring Agents" -ForegroundColor Gray
foreach ($agent in $siemAgents) {
    $service = Get-Service -Name $agent.Service -ErrorAction SilentlyContinue
    if ($service) {
        Write-Host "$($agent.Name) is INSTALLED and $($service.Status)" -ForegroundColor Green
    }
}

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Event Log Protection Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Summary
$issues = @()
if ($dangerousPermissions.Count -gt 0) { $issues += "Vulnerable file/registry permissions found" }
if (-not $eventLogService -or $eventLogService.Status -ne "Running") { $issues += "Event Log service issues" }

if ($issues.Count -eq 0) {
    Write-Host "Event logs appear to be properly protected" -ForegroundColor Green
} else {
    Write-Host "Security issues found" -ForegroundColor Red
    foreach ($issue in $issues) {
        Write-Host "  - $issue" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Note To fully test protection, run this script as both" -ForegroundColor White
Write-Host "an administrator and a standard user account." -ForegroundColor White
Write-Host "Standard users should not be able to modify or delete logs." -ForegroundColor White
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
