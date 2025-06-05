# ML2-RM-01 Microsoft Office Macro Win32 API Call Test Script
# Run this script with appropriate permissions

Write-Host "========================================" -ForegroundColor Cyan
Write-Host "ML2-RM-01 - Office Macro Win32 API Block Test" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

# Function to create test macro files
function Create-MacroTestFile {
    param(
        [string]$AppName,
        [string]$FilePath
    )
    
    $testContent = @"
' This macro attempts to make Win32 API calls
' It should be blocked if ML2-RM-01 is properly configured

Private Declare PtrSafe Function GetUserName Lib "advapi32.dll" Alias "GetUserNameA" (ByVal lpBuffer As String, nSize As Long) As Long
Private Declare PtrSafe Function MessageBox Lib "user32" Alias "MessageBoxA" (ByVal hwnd As Long, ByVal lpText As String, ByVal lpCaption As String, ByVal wType As Long) As Long

Sub TestWin32API()
    On Error GoTo ErrorHandler
    
    ' Attempt to call Win32 API
    Dim userName As String * 255
    Dim result As Long
    
    ' This should be blocked
    result = GetUserName(userName, 255)
    
    If result <> 0 Then
        MsgBox "FAIL: Win32 API call succeeded! User: " & Trim(userName), vbCritical, "Security Test Failed"
    Else
        MsgBox "PASS: Win32 API call was blocked", vbInformation, "Security Test Passed"
    End If
    
    Exit Sub
    
ErrorHandler:
    MsgBox "PASS: Win32 API call was blocked (Error: " & Err.Description & ")", vbInformation, "Security Test Passed"
End Sub
"@
    
    return $testContent
}

# Check for installed Office applications
Write-Host "Checking for installed Microsoft Office applications..." -ForegroundColor Yellow
$officeApps = @(
    @{Name="Excel"; Extension=".xlsm"; Process="EXCEL"; RegPath="Excel.Application"},
    @{Name="Word"; Extension=".docm"; Process="WINWORD"; RegPath="Word.Application"},
    @{Name="PowerPoint"; Extension=".pptm"; Process="POWERPNT"; RegPath="PowerPoint.Application"},
    @{Name="Access"; Extension=".accdb"; Process="MSACCESS"; RegPath="Access.Application"}
)

$installedApps = @()
foreach ($app in $officeApps) {
    try {
        $test = New-Object -ComObject $app.RegPath -ErrorAction Stop
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($test) | Out-Null
        $installedApps += $app
        Write-Host "  $($app.Name) - INSTALLED" -ForegroundColor Green
    } catch {
        Write-Host "  $($app.Name) - Not installed" -ForegroundColor Gray
    }
}

if ($installedApps.Count -eq 0) {
    Write-Host "No Microsoft Office applications found!" -ForegroundColor Red
    exit
}

Write-Host ""
Write-Host "Checking Office Macro Security Settings..." -ForegroundColor Yellow

# Check VBA settings in registry
foreach ($app in $installedApps) {
    $appLower = $app.Name.ToLower()
    $vbaPath = "HKCU:\Software\Microsoft\Office\16.0\$appLower\Security"
    
    try {
        $vbaSetting = Get-ItemProperty -Path $vbaPath -Name VBAWarnings -ErrorAction Stop
        Write-Host "$($app.Name) VBA Warning Level = $($vbaSetting.VBAWarnings)" -ForegroundColor Gray
        
        switch ($vbaSetting.VBAWarnings) {
            1 { Write-Host "  Macros disabled without notification" -ForegroundColor Green }
            2 { Write-Host "  Macros disabled with notification" -ForegroundColor Green }
            3 { Write-Host "  Macros disabled except digitally signed" -ForegroundColor Yellow }
            4 { Write-Host "  All macros enabled (DANGEROUS)" -ForegroundColor Red }
        }
    } catch {
        Write-Host "$($app.Name) VBA settings not found" -ForegroundColor Gray
    }
}

Write-Host ""
Write-Host "Checking AMSI (Antimalware Scan Interface) for Office..." -ForegroundColor Yellow

# Check if AMSI is enabled for Office
$amsiPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
try {
    $amsiSetting = Get-ItemProperty -Path $amsiPath -Name DisableAntiSpyware -ErrorAction Stop
    if ($amsiSetting.DisableAntiSpyware -eq 0) {
        Write-Host "Windows Defender/AMSI is ENABLED" -ForegroundColor Green
    } else {
        Write-Host "Windows Defender/AMSI is DISABLED" -ForegroundColor Red
    }
} catch {
    Write-Host "Windows Defender/AMSI status unknown" -ForegroundColor Gray
}

# Check Office-specific AMSI settings
$officeAmsiPath = "HKCU:\Software\Microsoft\Office\16.0\Common\Security"
try {
    $amsiEnable = Get-ItemProperty -Path $officeAmsiPath -Name MacroRuntimeScanScope -ErrorAction Stop
    Write-Host "Office AMSI Macro Runtime Scan Scope = $($amsiEnable.MacroRuntimeScanScope)" -ForegroundColor Green
} catch {
    Write-Host "Office AMSI settings not configured" -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Creating Test Files..." -ForegroundColor Yellow

# Create test directory
$testDir = "$env:TEMP\ML2-RM-01-Test"
if (-not (Test-Path $testDir)) {
    New-Item -ItemType Directory -Path $testDir | Out-Null
}

Write-Host "Test files will be created in $testDir" -ForegroundColor Gray

# Create PowerShell script to generate macro-enabled files
$createScript = @'
param($AppName, $FilePath)

switch ($AppName) {
    "Excel" {
        $excel = New-Object -ComObject Excel.Application
        $excel.Visible = $false
        $workbook = $excel.Workbooks.Add()
        $xlmodule = $workbook.VBProject.VBComponents.Add(1)
        $code = @"
Private Declare PtrSafe Function GetUserName Lib "advapi32.dll" Alias "GetUserNameA" (ByVal lpBuffer As String, nSize As Long) As Long
Private Declare PtrSafe Function MessageBox Lib "user32" Alias "MessageBoxA" (ByVal hwnd As Long, ByVal lpText As String, ByVal lpCaption As String, ByVal wType As Long) As Long

Sub TestWin32API()
    On Error GoTo ErrorHandler
    Dim userName As String * 255
    Dim result As Long
    result = GetUserName(userName, 255)
    If result <> 0 Then
        MsgBox "FAIL: Win32 API call succeeded! User: " & Trim(userName), vbCritical, "ML2-RM-01 Test Failed"
    End If
    Exit Sub
ErrorHandler:
    MsgBox "PASS: Win32 API call was blocked (Error: " & Err.Description & ")", vbInformation, "ML2-RM-01 Test Passed"
End Sub

Sub Auto_Open()
    TestWin32API
End Sub
"@
        $xlmodule.CodeModule.AddFromString($code)
        $workbook.SaveAs($FilePath, 52) # xlOpenXMLWorkbookMacroEnabled
        $workbook.Close()
        $excel.Quit()
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($excel) | Out-Null
    }
    
    "Word" {
        $word = New-Object -ComObject Word.Application
        $word.Visible = $false
        $document = $word.Documents.Add()
        $vbModule = $document.VBProject.VBComponents.Add(1)
        $code = @"
Private Declare PtrSafe Function GetUserName Lib "advapi32.dll" Alias "GetUserNameA" (ByVal lpBuffer As String, nSize As Long) As Long

Sub TestWin32API()
    On Error GoTo ErrorHandler
    Dim userName As String * 255
    Dim result As Long
    result = GetUserName(userName, 255)
    If result <> 0 Then
        MsgBox "FAIL: Win32 API call succeeded! User: " & Trim(userName), vbCritical, "ML2-RM-01 Test Failed"
    End If
    Exit Sub
ErrorHandler:
    MsgBox "PASS: Win32 API call was blocked", vbInformation, "ML2-RM-01 Test Passed"
End Sub

Sub AutoOpen()
    TestWin32API
End Sub
"@
        $vbModule.CodeModule.AddFromString($code)
        $document.SaveAs2([ref]$FilePath, [ref]13) # wdFormatXMLDocumentMacroEnabled
        $document.Close()
        $word.Quit()
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($word) | Out-Null
    }
    
    "PowerPoint" {
        $ppt = New-Object -ComObject PowerPoint.Application
        $presentation = $ppt.Presentations.Add()
        $vbModule = $presentation.VBProject.VBComponents.Add(1)
        $code = @"
Private Declare PtrSafe Function GetUserName Lib "advapi32.dll" Alias "GetUserNameA" (ByVal lpBuffer As String, nSize As Long) As Long

Sub TestWin32API()
    On Error GoTo ErrorHandler
    Dim userName As String * 255
    Dim result As Long
    result = GetUserName(userName, 255)
    If result <> 0 Then
        MsgBox "FAIL: Win32 API call succeeded! User: " & Trim(userName), vbCritical, "ML2-RM-01 Test Failed"
    End If
    Exit Sub
ErrorHandler:
    MsgBox "PASS: Win32 API call was blocked", vbInformation, "ML2-RM-01 Test Passed"
End Sub

Sub OnSlideShowPageChange()
    TestWin32API
End Sub
"@
        $vbModule.CodeModule.AddFromString($code)
        $presentation.SaveAs($FilePath, 25) # ppSaveAsOpenXMLPresentationMacroEnabled
        $presentation.Close()
        $ppt.Quit()
        [System.Runtime.Interopservices.Marshal]::ReleaseComObject($ppt) | Out-Null
    }
}
'@

# Save the creation script
$createScriptPath = "$testDir\CreateMacroFile.ps1"
$createScript | Out-File -FilePath $createScriptPath -Encoding UTF8

# Create test files for each installed Office application
$testFiles = @()
foreach ($app in $installedApps) {
    $testFile = Join-Path $testDir "ML2-RM-01-Test-$($app.Name)$($app.Extension)"
    
    Write-Host "Creating test file for $($app.Name)..." -ForegroundColor Gray
    
    try {
        # Check if programmatic access to VBA is allowed
        $trustPath = "HKCU:\Software\Microsoft\Office\16.0\$($app.Name.ToLower())\Security"
        $trustAccess = Get-ItemProperty -Path $trustPath -Name AccessVBOM -ErrorAction SilentlyContinue
        
        if (-not $trustAccess -or $trustAccess.AccessVBOM -ne 1) {
            Write-Host "  Note Programmatic access to VBA not enabled for $($app.Name)" -ForegroundColor Yellow
            Write-Host "  Manual file creation may be required" -ForegroundColor Yellow
        } else {
            # Try to create the file
            & $createScriptPath -AppName $app.Name -FilePath $testFile
            if (Test-Path $testFile) {
                $testFiles += @{App=$app.Name; Path=$testFile}
                Write-Host "  Test file created successfully" -ForegroundColor Green
            }
        }
    } catch {
        Write-Host "  Failed to create test file $_" -ForegroundColor Red
    }
}

Write-Host ""
Write-Host "Manual Test Instructions" -ForegroundColor Yellow
Write-Host "========================" -ForegroundColor Gray
Write-Host "1. Open each test file in $testDir"
Write-Host "2. Enable macros when prompted"
Write-Host "3. The macro will automatically run and test Win32 API calls"
Write-Host "4. Expected result PASS message showing API calls are blocked"
Write-Host "5. If you see FAIL message, Win32 API calls are NOT blocked"
Write-Host ""

# Provide alternative test using E8MVT if available
Write-Host "Alternative Testing with E8MVT" -ForegroundColor Yellow
Write-Host "==============================" -ForegroundColor Gray
Write-Host "If Enterprise 8 Maturity Validation Tool (E8MVT) is available"
Write-Host "1. Run E8MVT.exe"
Write-Host "2. Select the ML2-RM-01 test"
Write-Host "3. E8MVT will automatically test Win32 API blocking"
Write-Host ""

# Check for potential Win32 API blocking mechanisms
Write-Host "Checking Win32 API Blocking Mechanisms..." -ForegroundColor Yellow

# Check for ASR rules that might block Win32 API calls
try {
    $asrRules = (Get-MpPreference).AttackSurfaceReductionRules_Ids
    if ($asrRules) {
        Write-Host "Attack Surface Reduction rules are configured" -ForegroundColor Green
        # Check for specific rules related to Office
        $officeRules = @(
            "3b576869-a4ec-4529-8536-b80a7769e899", # Block Office from creating executable content
            "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84", # Block Office from injecting into processes
            "d4f940ab-401b-4efc-aadc-ad5f3c50688a"  # Block Office from creating child processes
        )
        
        foreach ($rule in $officeRules) {
            if ($rule -in $asrRules) {
                Write-Host "  Office protection rule $rule is enabled" -ForegroundColor Green
            }
        }
    }
} catch {
    Write-Host "Unable to check ASR rules" -ForegroundColor Gray
}

# Summary
Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "Test Summary" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""
Write-Host "Test files created $($testFiles.Count)"
Write-Host "Test directory $testDir"
Write-Host ""
Write-Host "Next steps"
Write-Host "1. Open the test files and enable macros"
Write-Host "2. Look for PASS/FAIL messages"
Write-Host "3. Document the results for each Office application"
Write-Host ""
Write-Host "Expected result All Win32 API calls should be blocked (PASS)" -ForegroundColor Green
Write-Host "Security risk If any show FAIL, Win32 APIs are not blocked" -ForegroundColor Red
