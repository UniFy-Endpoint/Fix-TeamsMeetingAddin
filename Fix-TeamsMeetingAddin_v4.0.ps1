<#
.SYNOPSIS
    Fix Microsoft Teams Meeting Add-in for Outlook (Smart Unified Version)

.DESCRIPTION
    Unified script combining smart pre-flight logic with robust remediation:
    0. Execution Context Detection (SYSTEM, Admin, Standard User)
    1. Environmental Pre-checks (WebView2, .NET 4.8+, HKLM blockers, Outlook bitness via registry)
    2. Teams Client Version detection and minimum version validation
    3. Teams Process Check (is Teams actually running?)
    4. Smart Health Check (LoadBehavior, DLL, COM match, InstallState)
    5. IF HEALTHY: Logs status, outputs summary, exits cleanly
    6. IF BROKEN: Full remediation suite:
       a. Registry backup (safety net)
       b. Graceful Outlook close, then force-stop if needed
       c. Run teamsbootstrapper.exe with download validation and retry (-x, -p, --installTMA)
       d. Clean stale HKCU COM overrides and old add-in version folders
       e. Fix COM registration (HKCU override with regsvr32 /i:user)
       f. Set LoadBehavior=3 with FriendlyName and Description
       g. Policy override (AddinList + DoNotDisableAddinList)
       h. Fix Outlook Security Policy (promptoom blocking keys)
       i. Clean Resiliency cache (DisabledItems, CrashingAddinList)
       j. Pre-launch registry verification
       k. Conditional Outlook restart (only if it was running before)
       l. Post-launch verification with actionable guidance

.VERSION
    4.0 - Unified smart logic with all hardening recommendations

.NOTES
    Deploy via Intune as Platform Script (user or device context) or run manually.
    Teams Add-in location: %LocalAppData%\Microsoft\TeamsMeetingAdd-in
    This script ONLY modifies HKCU registry keys, never HKLM.
    If COM registration points to wrong location, creates HKCU override.

    EXIT CODES:
      0 = Healthy, no action needed
      1 = Remediated successfully
      2 = Remediated with warnings
      3 = Failed, manual intervention needed
#>

# ============================================================================
# CONFIGURATION
# ============================================================================
$ErrorActionPreference = "Continue"
$script:LogFile = Join-Path $env:TEMP "Fix-TMA_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
$script:BootstrapperUrl = "https://go.microsoft.com/fwlink/?linkid=2243204&clcid=0x409"
$script:TmaClsid = "{A7AB73A3-CB10-4AA5-9D38-6AEFFBDE4C91}"
$script:MinTeamsVersion = [version]"24.1.0"  # Minimum Teams version for reliable TMA
$script:OutlookPath = $null
$script:OutlookArch = "Unknown"
$script:OutlookWasRunning = $false
$script:ExitCode = 0

# ============================================================================
# LOGGING (Color-coded output)
# ============================================================================
function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logMessage = "[$timestamp] [$Level] $Message"
    Add-Content -Path $script:LogFile -Value $logMessage -ErrorAction SilentlyContinue

    $color = switch ($Level) {
        "WARNING" { "Yellow" }
        "ERROR"   { "Red" }
        "SUCCESS" { "Green" }
        default   { "Cyan" }
    }
    Write-Host $logMessage -ForegroundColor $color
}

# ============================================================================
# EXECUTION CONTEXT DETECTION
# ============================================================================
function Get-ExecutionContext {
    Write-Log "CONTEXT: Detecting execution context..."

    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    $isAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $isSystem = $identity.IsSystem

    if ($isSystem) {
        Write-Log "Running as: SYSTEM"
        Write-Log "  --installTMA: Available"
    } elseif ($isAdmin) {
        Write-Log "Running as: Administrator ($($identity.Name))"
        Write-Log "  --installTMA: Available"
    } else {
        Write-Log "Running as: Standard User ($($identity.Name))"
        Write-Log "  --installTMA: Will be skipped (requires elevation)"
    }

    return @{
        IsSystem = $isSystem
        IsAdmin  = $isAdmin
        UserName = $identity.Name
    }
}

# ============================================================================
# STEP 0: ENVIRONMENTAL PRE-CHECKS
# ============================================================================
function Invoke-EnvironmentalChecks {
    Write-Log "STEP 0: Running Environmental Pre-checks..."
    $issues = @()

    # 1. WebView2 Runtime
    $wv2Machine = "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
    $wv2User = "HKCU:\Software\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
    if (-not (Test-Path $wv2Machine) -and -not (Test-Path $wv2User)) {
        Write-Log "WebView2 Runtime: NOT DETECTED - Teams Add-in requires this" "WARNING"
        $issues += "WebView2 missing"
    } else {
        Write-Log "WebView2 Runtime: Installed"
    }

    # 2. .NET Framework 4.8+
    $dotNetRelease = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\NET Framework Setup\NDP\v4\Full" -Name Release -ErrorAction SilentlyContinue
    if ($dotNetRelease -lt 528040) {
        Write-Log ".NET Framework 4.8+: NOT DETECTED - Modern add-ins may fail" "WARNING"
        $issues += ".NET 4.8+ missing"
    } else {
        Write-Log ".NET Framework 4.8+: Present (Release $dotNetRelease)"
    }

    # 3. HKLM LoadBehavior Blockers (machine-wide overrides)
    $hklmAddinPath = "HKLM:\SOFTWARE\Microsoft\Office\Outlook\Addins\TeamsAddin.FastConnect"
    $hklmLoad = Get-ItemPropertyValue -Path $hklmAddinPath -Name "LoadBehavior" -ErrorAction SilentlyContinue
    if ($null -ne $hklmLoad -and $hklmLoad -ne 3) {
        Write-Log "HKLM LoadBehavior: $hklmLoad - This OVERRIDES user settings!" "WARNING"
        $issues += "HKLM LoadBehavior=$hklmLoad"
    } elseif ($null -ne $hklmLoad) {
        Write-Log "HKLM LoadBehavior: $hklmLoad (OK)"
    } else {
        Write-Log "HKLM LoadBehavior: Not set (OK - no machine override)"
    }

    # 4. Outlook Bitness Detection (registry-first, filesystem fallback)
    $outlookBitness = Get-ItemPropertyValue -Path "HKLM:\SOFTWARE\Microsoft\Office\16.0\Outlook" -Name "Bitness" -ErrorAction SilentlyContinue
    if ($outlookBitness) {
        $script:OutlookArch = $outlookBitness
        Write-Log "Outlook Bitness (registry): $outlookBitness"
    } else {
        Write-Log "Outlook Bitness registry key not found - falling back to filesystem detection" "WARNING"
    }

    # Outlook executable path (always resolve for restart capability)
    $outlookPaths = @(
        @{ Path = "${env:ProgramFiles}\Microsoft Office\root\Office16\OUTLOOK.EXE"; Arch = "x64" },
        @{ Path = "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\OUTLOOK.EXE"; Arch = "x86" }
    )
    foreach ($entry in $outlookPaths) {
        if (Test-Path $entry.Path) {
            $script:OutlookPath = $entry.Path
            # Only use filesystem arch if registry didn't provide it
            if (-not $outlookBitness) {
                $script:OutlookArch = $entry.Arch
            }
            break
        }
    }
    Write-Log "Outlook Path: $($script:OutlookPath)"
    Write-Log "Outlook Architecture: $($script:OutlookArch)"

    # 5. Check if Outlook is currently running (for conditional restart later)
    $outlookProc = Get-Process -Name "OUTLOOK" -ErrorAction SilentlyContinue
    if ($outlookProc) {
        $script:OutlookWasRunning = $true
        Write-Log "Outlook Status: Running (PID $($outlookProc.Id))"
    } else {
        $script:OutlookWasRunning = $false
        Write-Log "Outlook Status: Not running"
    }

    if ($issues.Count -gt 0) {
        Write-Log "Environmental issues found: $($issues -join ', ')" "WARNING"
        Write-Log "Continuing - some issues may require separate resolution"
    } else {
        Write-Log "All environmental checks passed"
    }

    return $issues
}

# ============================================================================
# STEP 1: CHECK TEAMS CLIENT VERSION
# ============================================================================
function Get-TeamsClientVersion {
    Write-Log "STEP 1: Checking Teams client version..."

    $teamsVersion = $null

    # Check for New Teams (MSIX) first
    $newTeamsPath = "$env:LOCALAPPDATA\Packages\MSTeams_8wekyb3d8bbwe"
    if (Test-Path $newTeamsPath) {
        Write-Log "New Teams (MSIX) detected"
        try {
            $pkg = Get-AppxPackage -Name "MSTeams" -ErrorAction SilentlyContinue
            if ($pkg) {
                $teamsVersion = $pkg.Version
                Write-Log "Teams client version: $teamsVersion"
            }
        } catch {
            Write-Log "Could not get Teams MSIX version" "WARNING"
        }
    }

    # Fallback: Classic Teams settings.json
    if (-not $teamsVersion) {
        $settingsPath = "$env:LOCALAPPDATA\Microsoft\Teams\settings.json"
        if (Test-Path $settingsPath) {
            try {
                $settings = Get-Content $settingsPath -Raw | ConvertFrom-Json
                if ($settings.version) {
                    $teamsVersion = $settings.version
                    Write-Log "Teams client version (classic): $teamsVersion"
                }
            } catch {
                Write-Log "Could not read Teams settings" "WARNING"
            }
        }
    }

    # Fallback: version.txt
    if (-not $teamsVersion) {
        $currentPath = "$env:LOCALAPPDATA\Microsoft\Teams\current\version.txt"
        if (Test-Path $currentPath) {
            $teamsVersion = (Get-Content $currentPath -ErrorAction SilentlyContinue).Trim()
            if ($teamsVersion) {
                Write-Log "Teams client version (version.txt): $teamsVersion"
            }
        }
    }

    if (-not $teamsVersion) {
        Write-Log "Could not determine Teams client version" "WARNING"
        return $null
    }

    # Validate minimum version
    try {
        $parsed = [version]$teamsVersion
        if ($parsed -lt $script:MinTeamsVersion) {
            Write-Log "Teams version $teamsVersion is BELOW minimum $($script:MinTeamsVersion) - update recommended" "WARNING"
        } else {
            Write-Log "Teams version meets minimum requirements"
        }
    } catch {
        Write-Log "Could not parse Teams version for comparison" "WARNING"
    }

    return $teamsVersion
}

# ============================================================================
# STEP 2: CHECK TEAMS PROCESS
# ============================================================================
function Test-TeamsRunning {
    Write-Log "STEP 2: Checking if Teams is running..."

    $teamsProc = Get-Process -Name "ms-teams" -ErrorAction SilentlyContinue
    if (-not $teamsProc) {
        $teamsProc = Get-Process -Name "Teams" -ErrorAction SilentlyContinue
    }

    if ($teamsProc) {
        Write-Log "Teams is running (PID $($teamsProc.Id))"
        return $true
    } else {
        Write-Log "Teams is NOT running - add-in may not load even after fix" "WARNING"
        return $false
    }
}

# ============================================================================
# STEP 3: SMART HEALTH CHECK (Unified status assessment)
# ============================================================================
function Get-AddinHealthStatus {
    param([switch]$Silent)

    if (-not $Silent) { Write-Log "STEP 3: Running Smart Health Check..." }

    $status = @{
        IsHealthy          = $false
        LoadBehavior       = $null
        DllPath            = $null
        Version            = $null
        InstallStateExists = $false
        ComRegistered      = $null
        ComMatch           = $false
        NeedsBootstrapper  = $false
        Issues             = @()
    }

    # 1. Check LoadBehavior
    $regPath = "HKCU:\Software\Microsoft\Office\Outlook\Addins\TeamsAddin.FastConnect"
    $status.LoadBehavior = (Get-ItemProperty -Path $regPath -Name "LoadBehavior" -ErrorAction SilentlyContinue).LoadBehavior

    if ($status.LoadBehavior -ne 3) {
        $status.Issues += "LoadBehavior=$($status.LoadBehavior) (expected 3)"
    }
    if (-not $Silent) { Write-Log "  LoadBehavior: $($status.LoadBehavior)" }

    # 2. Check Add-in Files (DLL + InstallState)
    $addinPath = "$env:LOCALAPPDATA\Microsoft\TeamsMeetingAdd-in"

    if (-not (Test-Path $addinPath)) {
        if (-not $Silent) { Write-Log "  TeamsMeetingAdd-in folder: NOT FOUND" "WARNING" }
        $status.NeedsBootstrapper = $true
        $status.Issues += "Add-in folder missing"
        return $status
    }

    $versions = Get-ChildItem -Path $addinPath -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^\d+\.\d+\.\d+$' } |
                Sort-Object { [version]$_.Name } -Descending

    if ($versions.Count -eq 0) {
        if (-not $Silent) { Write-Log "  Version folders: NONE FOUND" "WARNING" }
        $status.NeedsBootstrapper = $true
        $status.Issues += "No version folders"
        return $status
    }

    $latest = $versions[0]
    $status.Version = $latest.Name
    if (-not $Silent) { Write-Log "  Latest version: $($latest.Name)" }

    # InstallState
    $installStatePath = Join-Path $latest.FullName "AddinInstaller.InstallState"
    if (Test-Path $installStatePath) {
        $status.InstallStateExists = $true
        if (-not $Silent) { Write-Log "  InstallState: FOUND" }
    } else {
        if (-not $Silent) { Write-Log "  InstallState: MISSING - installation incomplete" "WARNING" }
        $status.NeedsBootstrapper = $true
        $status.Issues += "InstallState missing"
    }

    # DLL (prefer architecture matching Outlook, fallback)
    $preferredArch = if ($script:OutlookArch -eq "x86") { "x86" } else { "x64" }
    $fallbackArch = if ($preferredArch -eq "x64") { "x86" } else { "x64" }

    $dllPath = Join-Path $latest.FullName "$preferredArch\Microsoft.Teams.AddinLoader.dll"
    if (-not (Test-Path $dllPath)) {
        $dllPath = Join-Path $latest.FullName "$fallbackArch\Microsoft.Teams.AddinLoader.dll"
    }

    if (Test-Path $dllPath) {
        $status.DllPath = $dllPath
        if (-not $Silent) { Write-Log "  DLL: $dllPath" }
    } else {
        if (-not $Silent) { Write-Log "  DLL: NOT FOUND" "WARNING" }
        $status.NeedsBootstrapper = $true
        $status.Issues += "DLL missing"
    }

    # 3. Check COM Registration
    $comPath = (Get-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\CLSID\$($script:TmaClsid)\InprocServer32" -ErrorAction SilentlyContinue)."(default)"
    $status.ComRegistered = $comPath

    if ($comPath) {
        if (-not $Silent) { Write-Log "  COM registered: $comPath" }
        if ($status.DllPath -and $comPath -eq $status.DllPath) {
            $status.ComMatch = $true
            if (-not $Silent) { Write-Log "  COM match: YES" }
        } elseif ($status.DllPath) {
            if (-not $Silent) {
                Write-Log "  COM match: NO - points to different path" "WARNING"
                if (-not (Test-Path $comPath)) {
                    Write-Log "  COM target file: DOES NOT EXIST" "WARNING"
                }
            }
            $status.Issues += "COM mismatch"
        }
    } else {
        if (-not $Silent) { Write-Log "  COM registration: NOT FOUND" "WARNING" }
        $status.Issues += "COM not registered"
    }

    # 4. Final Health Decision
    if ($status.LoadBehavior -eq 3 -and $status.InstallStateExists -and $status.ComMatch -and $status.DllPath) {
        $status.IsHealthy = $true
    }

    return $status
}

# ============================================================================
# REMEDIATION: REGISTRY BACKUP
# ============================================================================
function Backup-RegistryKeys {
    Write-Log "REMEDIATION: Backing up registry keys..."

    $backupFile = Join-Path $env:TEMP "Fix-TMA_RegBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"

    $keysToBackup = @(
        "HKCU\Software\Microsoft\Office\Outlook\Addins\TeamsAddin.FastConnect",
        "HKCU\Software\Policies\Microsoft\Office\16.0\Outlook\Resiliency\AddinList",
        "HKCU\Software\Microsoft\Office\16.0\Outlook\Resiliency\DoNotDisableAddinList",
        "HKCU\Software\Microsoft\Office\16.0\Outlook\Resiliency\DisabledItems",
        "HKCU\Software\Microsoft\Office\16.0\Outlook\Resiliency\CrashingAddinList",
        "HKCU\SOFTWARE\Classes\CLSID\$($script:TmaClsid)"
    )

    $backupContent = "Windows Registry Editor Version 5.00`r`n`r`n; Fix-TMA Registry Backup - $(Get-Date)`r`n"

    foreach ($key in $keysToBackup) {
        try {
            $result = reg export $key $backupFile /y 2>&1
            if (Test-Path $backupFile) {
                $keyContent = Get-Content $backupFile -Raw -ErrorAction SilentlyContinue
                if ($keyContent) {
                    $backupContent += "`r`n; --- $key ---`r`n"
                    # Strip the header from subsequent exports
                    $keyContent = $keyContent -replace "Windows Registry Editor Version 5.00\r?\n", ""
                    $backupContent += $keyContent
                }
            }
        } catch {
            # Key may not exist - that's fine
        }
    }

    $finalBackupFile = Join-Path $env:TEMP "Fix-TMA_RegBackup_$(Get-Date -Format 'yyyyMMdd_HHmmss').reg"
    $backupContent | Out-File -FilePath $finalBackupFile -Encoding Unicode -Force
    Write-Log "Registry backup saved: $finalBackupFile"

    # Clean up temp export file
    if (Test-Path $backupFile) { Remove-Item $backupFile -Force -ErrorAction SilentlyContinue }

    return $finalBackupFile
}

# ============================================================================
# REMEDIATION: GRACEFUL OUTLOOK CLOSE
# ============================================================================
function Stop-OutlookProcess {
    Write-Log "REMEDIATION: Stopping Outlook..."
    $outlook = Get-Process -Name "OUTLOOK" -ErrorAction SilentlyContinue

    if (-not $outlook) {
        Write-Log "Outlook is not running."
        return
    }

    # Attempt graceful close first
    Write-Log "Attempting graceful close..."
    try {
        $outlook | ForEach-Object {
            $_.CloseMainWindow() | Out-Null
        }
        # Wait up to 15 seconds for graceful close
        $waited = 0
        while ($waited -lt 15) {
            Start-Sleep -Seconds 1
            $waited++
            $still = Get-Process -Name "OUTLOOK" -ErrorAction SilentlyContinue
            if (-not $still) {
                Write-Log "Outlook closed gracefully after $waited seconds."
                return
            }
        }
    } catch {
        Write-Log "Graceful close attempt failed: $_" "WARNING"
    }

    # Force stop if still running
    $outlook = Get-Process -Name "OUTLOOK" -ErrorAction SilentlyContinue
    if ($outlook) {
        Write-Log "Graceful close timed out - force stopping Outlook..." "WARNING"
        $outlook | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3

        # Verify it's gone
        $still = Get-Process -Name "OUTLOOK" -ErrorAction SilentlyContinue
        if ($still) {
            Write-Log "Outlook process still running after force stop!" "ERROR"
        } else {
            Write-Log "Outlook force-stopped."
        }
    }
}

# ============================================================================
# REMEDIATION: RUN TEAMSBOOTSTRAPPER (with download validation and retry)
# ============================================================================
function Invoke-TeamsBootstrapper {
    Write-Log "REMEDIATION: Running teamsbootstrapper..."

    $bootstrapperPath = "$env:LOCALAPPDATA\Microsoft\Teams\teamsbootstrapper.exe"

    if (-not (Test-Path $bootstrapperPath)) {
        Write-Log "Downloading teamsbootstrapper.exe..."
        $bootstrapperPath = Join-Path $env:TEMP "teamsbootstrapper.exe"

        $maxRetries = 2
        $downloaded = $false

        for ($attempt = 1; $attempt -le $maxRetries; $attempt++) {
            try {
                [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
                Invoke-WebRequest -Uri $script:BootstrapperUrl -OutFile $bootstrapperPath -UseBasicParsing
                Write-Log "Downloaded to: $bootstrapperPath (attempt $attempt)"
                $downloaded = $true
                break
            } catch {
                Write-Log "Download attempt $attempt failed: $_" "WARNING"
                if ($attempt -lt $maxRetries) {
                    Write-Log "Retrying in 5 seconds..."
                    Start-Sleep -Seconds 5
                }
            }
        }

        if (-not $downloaded) {
            Write-Log "Failed to download teamsbootstrapper after $maxRetries attempts" "ERROR"
            return $false
        }

        # Validate downloaded file
        if (Test-Path $bootstrapperPath) {
            $fileInfo = Get-Item $bootstrapperPath
            if ($fileInfo.Length -eq 0) {
                Write-Log "Downloaded file is empty (0 bytes) - download corrupted" "ERROR"
                Remove-Item $bootstrapperPath -Force -ErrorAction SilentlyContinue
                return $false
            }
            Write-Log "Download size: $([math]::Round($fileInfo.Length / 1KB, 1)) KB"

            # Validate digital signature
            try {
                $sig = Get-AuthenticodeSignature -FilePath $bootstrapperPath -ErrorAction SilentlyContinue
                if ($sig.Status -eq "Valid") {
                    Write-Log "Digital signature: Valid ($($sig.SignerCertificate.Subject))"
                } elseif ($sig.Status -eq "NotSigned") {
                    Write-Log "Digital signature: Not signed - proceeding with caution" "WARNING"
                } else {
                    Write-Log "Digital signature: $($sig.Status) - file may be tampered" "WARNING"
                }
            } catch {
                Write-Log "Could not verify digital signature" "WARNING"
            }
        }
    }

    if (-not (Test-Path $bootstrapperPath)) {
        Write-Log "teamsbootstrapper.exe not available" "ERROR"
        return $false
    }

    Write-Log "Bootstrapper path: $bootstrapperPath"

    try {
        # Unregister
        $result = Start-Process -FilePath $bootstrapperPath -ArgumentList "-x" -Wait -PassThru -WindowStyle Hidden
        Write-Log "Unregister (-x) exit code: $($result.ExitCode)"
        Start-Sleep -Seconds 2

        # Register
        $result = Start-Process -FilePath $bootstrapperPath -ArgumentList "-p" -Wait -PassThru -WindowStyle Hidden
        Write-Log "Register (-p) exit code: $($result.ExitCode)"
        Start-Sleep -Seconds 2

        # InstallTMA (requires admin/SYSTEM)
        $isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        if ($isAdmin) {
            $result = Start-Process -FilePath $bootstrapperPath -ArgumentList "--installTMA" -Wait -PassThru -WindowStyle Hidden
            Write-Log "InstallTMA exit code: $($result.ExitCode)"
        } else {
            Write-Log "Skipping --installTMA (requires admin rights)"
        }

        Write-Log "Bootstrapper actions complete."
        return $true
    } catch {
        Write-Log "Bootstrapper failed: $_" "ERROR"
        return $false
    }
}

# ============================================================================
# REMEDIATION: CLEAN STALE HKCU COM OVERRIDES
# ============================================================================
function Clear-StaleComOverride {
    Write-Log "REMEDIATION: Checking for stale HKCU COM overrides..."

    $hkcuClsidPath = "HKCU:\SOFTWARE\Classes\CLSID\$($script:TmaClsid)"
    $hkcuInprocPath = "$hkcuClsidPath\InprocServer32"

    if (Test-Path $hkcuInprocPath) {
        $existingDll = (Get-ItemProperty -Path $hkcuInprocPath -ErrorAction SilentlyContinue)."(default)"
        if ($existingDll) {
            if (-not (Test-Path $existingDll)) {
                Write-Log "Stale HKCU COM override found: $existingDll (file does not exist)" "WARNING"
                Remove-Item -Path $hkcuClsidPath -Recurse -Force -ErrorAction SilentlyContinue
                Write-Log "Removed stale HKCU COM override"
            } else {
                Write-Log "Existing HKCU COM override: $existingDll (file exists)"
            }
        }
    } else {
        Write-Log "No existing HKCU COM override"
    }
}

# ============================================================================
# REMEDIATION: CLEAN OLD ADD-IN VERSION FOLDERS
# ============================================================================
function Clear-OldAddinVersions {
    Write-Log "REMEDIATION: Checking for stale add-in version folders..."

    $addinPath = "$env:LOCALAPPDATA\Microsoft\TeamsMeetingAdd-in"
    if (-not (Test-Path $addinPath)) { return }

    $versions = Get-ChildItem -Path $addinPath -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match '^\d+\.\d+\.\d+$' } |
                Sort-Object { [version]$_.Name } -Descending

    if ($versions.Count -le 1) {
        Write-Log "No stale version folders to clean"
        return
    }

    $latest = $versions[0]
    $stale = $versions | Select-Object -Skip 1

    foreach ($old in $stale) {
        Write-Log "Removing stale version folder: $($old.Name)"
        try {
            Remove-Item -Path $old.FullName -Recurse -Force -ErrorAction Stop
            Write-Log "Removed: $($old.FullName)"
        } catch {
            Write-Log "Could not remove $($old.Name): $_" "WARNING"
        }
    }

    Write-Log "Kept latest version: $($latest.Name)"
}

# ============================================================================
# REMEDIATION: FIX COM REGISTRATION (HKCU override with diagnostics)
# ============================================================================
function Fix-ComRegistration {
    param([string]$DllPath)

    Write-Log "REMEDIATION: Fixing COM Registration..."

    if (-not $DllPath -or -not (Test-Path $DllPath)) {
        Write-Log "DLL path not valid: $DllPath" "ERROR"
        return $false
    }

    # Check current COM state for diagnostics
    $currentPath = (Get-ItemProperty -Path "Registry::HKEY_CLASSES_ROOT\CLSID\$($script:TmaClsid)\InprocServer32" -ErrorAction SilentlyContinue)."(default)"

    if ($currentPath) {
        Write-Log "Current COM registration: $currentPath"
        if (-not (Test-Path $currentPath)) {
            Write-Log "COM MISMATCH: Registered file does not exist" "WARNING"
            Write-Log "  Registered: $currentPath"
            Write-Log "  Actual DLL: $DllPath"
        } elseif ($currentPath -eq $DllPath) {
            Write-Log "COM registration already correct"
        } else {
            Write-Log "COM points to different version: $currentPath"
        }
    } else {
        Write-Log "No existing COM registration found"
    }

    # Create HKCU override (HKCU takes priority over HKLM)
    Write-Log "Creating HKCU COM override..."
    $hkcuClsidPath = "HKCU:\SOFTWARE\Classes\CLSID\$($script:TmaClsid)"
    $hkcuInprocPath = "$hkcuClsidPath\InprocServer32"

    try {
        if (-not (Test-Path $hkcuClsidPath)) {
            New-Item -Path $hkcuClsidPath -Force | Out-Null
        }
        if (-not (Test-Path $hkcuInprocPath)) {
            New-Item -Path $hkcuInprocPath -Force | Out-Null
        }
        Set-ItemProperty -Path $hkcuInprocPath -Name "(default)" -Value $DllPath -Force
        Set-ItemProperty -Path $hkcuInprocPath -Name "ThreadingModel" -Value "Both" -Force
        Write-Log "HKCU COM override created: $DllPath"
    } catch {
        Write-Log "Could not create HKCU override: $_" "ERROR"
        return $false
    }

    # Run regsvr32 with per-user registration
    Write-Log "Running regsvr32 /i:user..."
    try {
        $result = Start-Process -FilePath "regsvr32.exe" -ArgumentList "/s /n /i:user `"$DllPath`"" -Wait -PassThru -WindowStyle Hidden
        Write-Log "regsvr32 /i:user exit code: $($result.ExitCode)"
        return ($result.ExitCode -eq 0)
    } catch {
        Write-Log "regsvr32 failed: $_" "ERROR"
        return $false
    }
}

# ============================================================================
# REMEDIATION: SET LOADBEHAVIOR=3
# ============================================================================
function Set-LoadBehavior {
    Write-Log "REMEDIATION: Setting LoadBehavior=3..."

    $addinPath = "HKCU:\Software\Microsoft\Office\Outlook\Addins\TeamsAddin.FastConnect"

    try {
        if (-not (Test-Path $addinPath)) {
            New-Item -Path $addinPath -Force | Out-Null
        }

        Set-ItemProperty -Path $addinPath -Name "FriendlyName" -Value "Microsoft Teams Meeting Add-in for Microsoft Office" -Type String -Force
        Set-ItemProperty -Path $addinPath -Name "LoadBehavior" -Value 3 -Type DWord -Force
        Set-ItemProperty -Path $addinPath -Name "Description" -Value "Microsoft Teams Meeting Add-in for Microsoft Office" -Type String -Force

        Write-Log "LoadBehavior set to 3" "SUCCESS"
        return $true
    } catch {
        Write-Log "Failed to set LoadBehavior: $_" "ERROR"
        return $false
    }
}

# ============================================================================
# REMEDIATION: SET POLICY OVERRIDES
# ============================================================================
function Set-PolicyOverride {
    Write-Log "REMEDIATION: Setting Policy overrides..."

    # AddinList policy (force-enable)
    $policyPath = "HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\Resiliency\AddinList"
    try {
        if (-not (Test-Path $policyPath)) {
            New-Item -Path $policyPath -Force | Out-Null
        }
        Set-ItemProperty -Path $policyPath -Name "TeamsAddin.FastConnect" -Value "1" -Type String -Force
        Write-Log "Policy AddinList: TeamsAddin.FastConnect=1"
    } catch {
        Write-Log "Could not set AddinList policy: $_" "WARNING"
    }

    # DoNotDisableAddinList
    $doNotDisablePath = "HKCU:\Software\Microsoft\Office\16.0\Outlook\Resiliency\DoNotDisableAddinList"
    try {
        if (-not (Test-Path $doNotDisablePath)) {
            New-Item -Path $doNotDisablePath -Force | Out-Null
        }
        Set-ItemProperty -Path $doNotDisablePath -Name "TeamsAddin.FastConnect" -Value 1 -Type DWord -Force
        Write-Log "DoNotDisableAddinList: TeamsAddin.FastConnect=1"
    } catch {
        Write-Log "Could not set DoNotDisableAddinList: $_" "WARNING"
    }
}

# ============================================================================
# REMEDIATION: FIX OUTLOOK SECURITY POLICY
# ============================================================================
function Fix-OutlookSecurityPolicy {
    Write-Log "REMEDIATION: Checking Outlook security policies..."

    $securityPaths = @(
        "HKCU:\Software\Policies\Microsoft\Office\16.0\Outlook\Security",
        "HKCU:\Software\Policies\Microsoft\Cloud\Office\16.0\Outlook\Security"
    )

    $blockingKeys = @("promptoomaddressinformationaccess", "promptoomaddressbookaccess", "promptoomsend")

    foreach ($path in $securityPaths) {
        if (Test-Path $path) {
            foreach ($keyName in $blockingKeys) {
                $value = (Get-ItemProperty -Path $path -Name $keyName -ErrorAction SilentlyContinue).$keyName
                if ($value -eq 0) {
                    Write-Log "FOUND: $keyName=0 at $path - this blocks add-ins!" "WARNING"
                    try {
                        Remove-ItemProperty -Path $path -Name $keyName -ErrorAction Stop
                        Write-Log "Removed blocking key: $keyName" "SUCCESS"
                    } catch {
                        Write-Log "Could not remove $keyName : $_" "WARNING"
                    }
                } elseif ($null -ne $value) {
                    Write-Log "Security key $keyName at $path = $value (OK)"
                }
            }
        }
    }

    Write-Log "Security policy check complete"
}

# ============================================================================
# REMEDIATION: CLEAN RESILIENCY CACHE
# ============================================================================
function Clear-ResiliencyCache {
    Write-Log "REMEDIATION: Cleaning Resiliency cache..."

    $resiliencyPath = "HKCU:\Software\Microsoft\Office\16.0\Outlook\Resiliency"

    if (Test-Path "$resiliencyPath\DisabledItems") {
        Remove-Item -Path "$resiliencyPath\DisabledItems" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "Removed DisabledItems"
    } else {
        Write-Log "DisabledItems: Clean"
    }

    if (Test-Path "$resiliencyPath\CrashingAddinList") {
        Remove-Item -Path "$resiliencyPath\CrashingAddinList" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Log "Removed CrashingAddinList"
    } else {
        Write-Log "CrashingAddinList: Clean"
    }
}

# ============================================================================
# REMEDIATION: CONDITIONAL OUTLOOK RESTART
# ============================================================================
function Start-OutlookConditional {
    if (-not $script:OutlookWasRunning) {
        Write-Log "Outlook was not running before remediation - skipping auto-restart"
        Write-Log "You can start Outlook manually when ready."
        return $false
    }

    Write-Log "REMEDIATION: Restarting Outlook (was running before remediation)..."

    if ($script:OutlookPath -and (Test-Path $script:OutlookPath)) {
        Start-Process $script:OutlookPath -ErrorAction SilentlyContinue
        Write-Log "Outlook started: $($script:OutlookPath)"
        return $true
    }

    # Fallback search
    $outlookPaths = @(
        "${env:ProgramFiles}\Microsoft Office\root\Office16\OUTLOOK.EXE",
        "${env:ProgramFiles(x86)}\Microsoft Office\root\Office16\OUTLOOK.EXE"
    )

    foreach ($path in $outlookPaths) {
        if (Test-Path $path) {
            Start-Process $path -ErrorAction SilentlyContinue
            Write-Log "Outlook started: $path"
            return $true
        }
    }

    Write-Log "Outlook executable not found - please start manually" "WARNING"
    return $false
}

# ============================================================================
# POST-LAUNCH VERIFICATION
# ============================================================================
function Test-PostLaunchResult {
    param([bool]$OutlookRestarted)

    if ($OutlookRestarted) {
        Write-Log "VERIFICATION: Waiting for Outlook to initialize..."
        Start-Sleep -Seconds 10
    }

    $finalStatus = Get-AddinHealthStatus -Silent

    Write-Log ""
    Write-Log "=== FINAL STATUS ==="
    Write-Log "  LoadBehavior:  $($finalStatus.LoadBehavior)"
    Write-Log "  InstallState:  $($finalStatus.InstallStateExists)"
    Write-Log "  COM Match:     $($finalStatus.ComMatch)"
    Write-Log "  DLL:           $($finalStatus.DllPath)"
    Write-Log "  Version:       $($finalStatus.Version)"

    if ($finalStatus.IsHealthy) {
        Write-Log "RESULT: Add-in is healthy and active" "SUCCESS"
        return $true
    }

    if ($finalStatus.LoadBehavior -eq 2) {
        Write-Log "LoadBehavior reverted to 2 - Outlook is disabling the add-in" "WARNING"
        Write-Log ""
        Write-Log "=== ACTION REQUIRED ==="
        if ($finalStatus.ComRegistered -and -not (Test-Path $finalStatus.ComRegistered)) {
            Write-Log "COM registration points to non-existent file: $($finalStatus.ComRegistered)" "WARNING"
            Write-Log "Actual DLL location: $($finalStatus.DllPath)" "WARNING"
        }
        Write-Log "To resolve this:"
        Write-Log "  1. Update Microsoft Teams to the latest version"
        Write-Log "  2. Update Microsoft Outlook: File > Office Account > Update Options > Update Now"
        Write-Log "  3. Restart computer and run this script again"
        Write-Log "===================="
        return $false
    }

    if ($finalStatus.Issues.Count -gt 0) {
        Write-Log "Remaining issues: $($finalStatus.Issues -join ', ')" "WARNING"
    }

    return $false
}

# ============================================================================
# OUTPUT SUMMARY (JSON block for monitoring/parsing)
# ============================================================================
function Write-Summary {
    param(
        [int]$ExitCode,
        [hashtable]$FinalStatus,
        [string]$TeamsVersion,
        [array]$EnvIssues
    )

    $summary = @{
        Timestamp      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        Computer       = $env:COMPUTERNAME
        User           = $env:USERNAME
        ExitCode       = $ExitCode
        Result         = switch ($ExitCode) { 0 { "Healthy" } 1 { "Remediated" } 2 { "Warnings" } 3 { "Failed" } }
        TeamsVersion   = $TeamsVersion
        AddinVersion   = $FinalStatus.Version
        LoadBehavior   = $FinalStatus.LoadBehavior
        InstallState   = $FinalStatus.InstallStateExists
        ComMatch       = $FinalStatus.ComMatch
        IsHealthy      = $FinalStatus.IsHealthy
        EnvIssues      = $EnvIssues
        LogFile        = $script:LogFile
    } | ConvertTo-Json -Compress

    Write-Log ""
    Write-Log "=== MACHINE-READABLE SUMMARY ==="
    Write-Log $summary
    Write-Log "================================="
}

# ============================================================================
# ============================================================================
# MAIN EXECUTION
# ============================================================================
# ============================================================================
Write-Log "========================================================"
Write-Log "Teams Meeting Add-in Smart Fix v3.5"
Write-Log "========================================================"
Write-Log "Computer: $env:COMPUTERNAME"
Write-Log "Log: $script:LogFile"
Write-Log ""

# --- Execution Context ---
$execContext = Get-ExecutionContext
Write-Log ""

# --- STEP 0: Environmental Pre-checks ---
$envIssues = Invoke-EnvironmentalChecks
Write-Log ""

# --- STEP 1: Teams Client Version ---
$teamsVersion = Get-TeamsClientVersion
Write-Log ""

# --- STEP 2: Teams Process Check ---
$teamsRunning = Test-TeamsRunning
Write-Log ""

# --- STEP 3: Smart Health Check ---
$healthStatus = Get-AddinHealthStatus
Write-Log ""

Write-Log "=== HEALTH SUMMARY ==="
Write-Log "  Healthy:       $($healthStatus.IsHealthy)"
Write-Log "  LoadBehavior:  $($healthStatus.LoadBehavior)"
Write-Log "  InstallState:  $($healthStatus.InstallStateExists)"
Write-Log "  COM Match:     $($healthStatus.ComMatch)"
Write-Log "  Version:       $($healthStatus.Version)"

if ($healthStatus.IsHealthy) {
    Write-Log ""
    Write-Log "Add-in is correctly configured and healthy. No remediation needed." "SUCCESS"
    Write-Summary -ExitCode 0 -FinalStatus $healthStatus -TeamsVersion $teamsVersion -EnvIssues $envIssues
    Write-Log "========================================================"
    Write-Log "Log file: $script:LogFile"
    exit 0
}

# ============================================================================
# REMEDIATION REQUIRED
# ============================================================================
Write-Log ""
Write-Log "ISSUES DETECTED: $($healthStatus.Issues -join ', ')" "WARNING"
Write-Log "Starting full remediation..."
Write-Log "--------------------------------------------------------"

# Registry Backup
$backupFile = Backup-RegistryKeys

# Stop Outlook (graceful first, then force)
Stop-OutlookProcess

# Run Bootstrapper (with retry and validation)
$bootstrapResult = Invoke-TeamsBootstrapper
Start-Sleep -Seconds 3

# Clean stale COM overrides
Clear-StaleComOverride

# Clean old add-in version folders
Clear-OldAddinVersions

# Re-assess after bootstrapper and cleanup
$postBootStatus = Get-AddinHealthStatus -Silent

# Fix COM Registration
if ($postBootStatus.DllPath) {
    Fix-ComRegistration -DllPath $postBootStatus.DllPath
} else {
    Write-Log "DLL not found even after bootstrapper - Teams add-in may not work" "ERROR"
}

# Set LoadBehavior
Set-LoadBehavior

# Set Policy Overrides
Set-PolicyOverride

# Fix Outlook Security Policy
Fix-OutlookSecurityPolicy

# Clean Resiliency Cache
Clear-ResiliencyCache

# Pre-launch Verification
Write-Log ""
Write-Log "PRE-LAUNCH: Verifying registry before starting Outlook..."
$preLaunchLB = (Get-ItemProperty -Path "HKCU:\Software\Microsoft\Office\Outlook\Addins\TeamsAddin.FastConnect" -Name "LoadBehavior" -ErrorAction SilentlyContinue).LoadBehavior
Write-Log "LoadBehavior before Outlook launch: $preLaunchLB"

if ($preLaunchLB -ne 3) {
    Write-Log "LoadBehavior is not 3 - forcing again..." "WARNING"
    Set-LoadBehavior
}

# Conditional Outlook Restart
$outlookRestarted = Start-OutlookConditional

# Post-launch Verification
$success = Test-PostLaunchResult -OutlookRestarted $outlookRestarted

# Determine exit code
if ($success) {
    $script:ExitCode = 1  # Remediated successfully
} else {
    # Check if it's a warning or full failure
    $finalCheck = Get-AddinHealthStatus -Silent
    if ($finalCheck.LoadBehavior -eq 3) {
        $script:ExitCode = 2  # Remediated with warnings (LB is 3 but other issues)
    } else {
        $script:ExitCode = 3  # Failed
    }
}

Write-Log ""
Write-Log "========================================================"
if ($script:ExitCode -eq 1) {
    Write-Log "COMPLETED SUCCESSFULLY" "SUCCESS"
    Write-Log "Teams Meeting Add-in has been remediated and should now be active."
} elseif ($script:ExitCode -eq 2) {
    Write-Log "COMPLETED WITH WARNINGS" "WARNING"
    Write-Log ""
    Write-Log "If the add-in is still not working:"
    Write-Log "  1. Open Microsoft Teams and check for updates"
    Write-Log "  2. Open Outlook > File > Office Account > Update Options > Update Now"
    Write-Log "  3. Restart computer and run this script again"
    Write-Log "  4. Check environmental issues reported above"
    if ($envIssues.Count -gt 0) {
        Write-Log "  ** Environmental issues: $($envIssues -join ', ')" "WARNING"
    }
} else {
    Write-Log "REMEDIATION FAILED" "ERROR"
    Write-Log ""
    Write-Log "Manual intervention required:"
    Write-Log "  1. Ensure Microsoft Teams is installed and up to date"
    Write-Log "  2. Ensure Microsoft 365 Apps are up to date"
    Write-Log "  3. Check the log file for specific errors"
    Write-Log "  4. Registry backup available at: $backupFile"
    if (-not $teamsRunning) {
        Write-Log "  ** Teams was not running - start Teams first, then retry" "WARNING"
    }
    if ($envIssues.Count -gt 0) {
        Write-Log "  ** Environmental issues: $($envIssues -join ', ')" "WARNING"
    }
}

# Output machine-readable summary
$finalStatus = Get-AddinHealthStatus -Silent
Write-Summary -ExitCode $script:ExitCode -FinalStatus $finalStatus -TeamsVersion $teamsVersion -EnvIssues $envIssues

Write-Log "========================================================"
Write-Log "Log file: $script:LogFile"

exit $script:ExitCode