#Requires -Version 5.1
<#
.SYNOPSIS
  Vindex agent MSI post-install step: Sysmon, its log limits and the archive prune task.

.DESCRIPTION
  Run by the MSI as SYSTEM (deferred, no impersonation) on install, upgrade and uninstall.
  Logic follows soc-ai-triage deploy/windows/endpoint/Install-ViktrixEndpoint.ps1:

  - Sysmon absent: obtain Microsoft Sysmon (SysmonZip, else download from Sysinternals), check
    its Microsoft Authenticode signature and install it with sysmon-baseline.xml.
  - Sysmon present: leave the customer's config alone unless SysmonConfig is 'replace'.
  - Cap Microsoft-Windows-Sysmon/Operational at SysmonLogMaxMB and let it overwrite old events.
    The log is never cleared: clearing writes "audit log cleared" events, which the SOC treats
    as defence evasion (T1070.001).
  - Register the daily SYSTEM task 'Vindex Sysmon archive prune'. Sysmon has no quota for its
    FileDelete archive (C:\viktrix-sysmon); a full archive filled endpoint disks (#729, spec 843).
  - Uninstall removes the task, and removes Sysmon only if this installer installed it.

  Every step writes to <install dir>\vindex\setup.log.
#>
[CmdletBinding()]
param(
    [ValidateSet('install', 'uninstall')]
    [string]$Mode = 'install',
    [Parameter(Mandatory = $true)]
    [string]$InstallDir,
    # install (default): install Sysmon if absent, warn on failure.
    # required: fail the MSI when Sysmon cannot be installed. skip: do nothing with Sysmon.
    [string]$Sysmon = 'install',
    # keep (default) leaves an existing Sysmon config; replace applies sysmon-baseline.xml.
    [string]$SysmonConfig = 'keep',
    # Local path or UNC path to Sysmon.zip for offline installs.
    [string]$SysmonZip = '',
    [int]$SysmonArchiveRetentionDays = 14,
    [int]$SysmonArchiveMaxSizeMB = 2048,
    [int]$SysmonLogMaxMB = 256
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The MSI passes "[APPLICATIONFOLDER]." so the quoted argument never ends in a backslash.
$InstallDir = [IO.Path]::GetFullPath($InstallDir.Trim('"')).TrimEnd('\')
$VindexDir = Join-Path $InstallDir 'vindex'
$LogPath = Join-Path $VindexDir 'setup.log'
$Baseline = Join-Path $VindexDir 'sysmon-baseline.xml'
$StateKey = 'HKLM:\SOFTWARE\Viktrix\Vindex'
$SysmonUrl = 'https://download.sysinternals.com/files/Sysmon.zip'
$SysmonChannel = 'Microsoft-Windows-Sysmon/Operational'
# The baseline's <ArchiveDirectory>: a folder on the system drive.
$SysmonArchiveDirName = 'viktrix-sysmon'
$PruneTask = 'Vindex Sysmon archive prune'

if ([string]::IsNullOrWhiteSpace($Sysmon)) { $Sysmon = 'install' }
if ([string]::IsNullOrWhiteSpace($SysmonConfig)) { $SysmonConfig = 'keep' }
$Sysmon = $Sysmon.ToLowerInvariant()
$SysmonConfig = $SysmonConfig.ToLowerInvariant()
if ($Sysmon -notin @('install', 'required', 'skip')) { throw "SYSMON must be install, required or skip (got '$Sysmon')." }
if ($SysmonConfig -notin @('keep', 'replace')) { throw "SYSMON_CONFIG must be keep or replace (got '$SysmonConfig')." }

New-Item -ItemType Directory -Force -Path $VindexDir | Out-Null

function Write-Log([string]$Message) {
    $line = '{0:u} {1}' -f (Get-Date).ToUniversalTime(), $Message
    Add-Content -LiteralPath $LogPath -Value $line -Encoding UTF8
    Write-Host $line
}

function Get-SysmonService {
    # Sysmon installs as Sysmon or Sysmon64 (Sysmon64a on ARM64); the driver is SysmonDrv.
    return Get-Service -Name 'Sysmon', 'Sysmon64', 'Sysmon64a' -ErrorAction SilentlyContinue |
        Select-Object -First 1
}

function Get-SysmonBinaryName {
    if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { return 'Sysmon64a.exe' }
    if ([Environment]::Is64BitOperatingSystem) { return 'Sysmon64.exe' }
    return 'Sysmon.exe'
}

function Assert-MicrosoftSigned([string]$Path) {
    $sig = Get-AuthenticodeSignature -LiteralPath $Path
    if ($sig.Status -ne 'Valid' -or $sig.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        throw "Sysmon binary $Path is not validly signed by Microsoft ($($sig.Status))."
    }
}

function Get-SysmonBinary {
    $name = Get-SysmonBinaryName
    $dest = Join-Path $VindexDir $name
    $work = Join-Path $env:TEMP ('vindex-sysmon-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    try {
        $zip = Join-Path $work 'Sysmon.zip'
        if ($SysmonZip) {
            Write-Log "Using Sysmon package $SysmonZip"
            Copy-Item -LiteralPath $SysmonZip.Trim('"') -Destination $zip
        } else {
            Write-Log "Downloading $SysmonUrl"
            [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
            Invoke-WebRequest -Uri $SysmonUrl -OutFile $zip -UseBasicParsing
        }
        Expand-Archive -LiteralPath $zip -DestinationPath $work -Force
        $exe = Join-Path $work $name
        if (-not (Test-Path -LiteralPath $exe)) { throw "$name not found in the Sysmon package." }
        Assert-MicrosoftSigned $exe
        Copy-Item -LiteralPath $exe -Destination $dest -Force
        return $dest
    } finally {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Set-SysmonLogLimit {
    if (-not (Get-WinEvent -ListLog $SysmonChannel -ErrorAction SilentlyContinue)) { return }
    $bytes = [int64]$SysmonLogMaxMB * 1MB
    # /rt:false = overwrite the oldest events when full (circular); never clear the log.
    & wevtutil.exe sl $SysmonChannel /ms:$bytes /rt:false /ab:false
    if ($LASTEXITCODE -ne 0) { throw "wevtutil sl exit $LASTEXITCODE" }
    Write-Log "Sysmon event log capped at $SysmonLogMaxMB MB, overwriting oldest events."
}

function Register-SysmonArchivePrune {
    # Same prune as Install-ViktrixEndpoint.ps1 (spec 781 age prune, spec 843 size cap). The
    # archive folder is SYSTEM-ACL'd, so only SYSTEM can prune it; the command is encoded to
    # avoid quoting through the task scheduler; re-registering is idempotent.
    $prune = ('$d = Join-Path $env:SystemDrive ''{0}''; if (Test-Path -LiteralPath $d) {{ ' +
        'Get-ChildItem -LiteralPath $d -File -Recurse -Force -ErrorAction SilentlyContinue | ' +
        'Where-Object {{ $_.LastWriteTimeUtc -lt [DateTime]::UtcNow.AddDays(-{1}) }} | ' +
        'Remove-Item -Force -ErrorAction SilentlyContinue; ' +
        '$cap = [int64]{2} * 1MB; ' +
        '$files = @(Get-ChildItem -LiteralPath $d -File -Recurse -Force -ErrorAction SilentlyContinue | ' +
        'Sort-Object LastWriteTimeUtc); ' +
        '$total = [int64](($files | Measure-Object -Property Length -Sum).Sum); ' +
        'foreach ($f in $files) {{ if ($total -le $cap) {{ break }}; ' +
        'Remove-Item -LiteralPath $f.FullName -Force -ErrorAction SilentlyContinue; ' +
        'if (-not (Test-Path -LiteralPath $f.FullName)) {{ $total -= $f.Length }} }} }}')
    $prune = $prune -f $SysmonArchiveDirName, $SysmonArchiveRetentionDays, $SysmonArchiveMaxSizeMB
    $encoded = [Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($prune))
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
        -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand $encoded"
    # Daily, plus at startup: an endpoint that is off at 03:30 every day still gets pruned.
    $triggers = @(
        (New-ScheduledTaskTrigger -Daily -At '03:30'),
        (New-ScheduledTaskTrigger -AtStartup)
    )
    $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1)
    Register-ScheduledTask -TaskName $PruneTask -Description 'Keeps the Sysmon FileDelete archive within its age and size limits (Vindex agent).' `
        -Action $action -Trigger $triggers -Principal $principal -Settings $settings -Force | Out-Null
    Write-Log "Registered '$PruneTask' (keep $SysmonArchiveRetentionDays days, cap $SysmonArchiveMaxSizeMB MB)."
}

function Install-Sysmon {
    if ($Sysmon -eq 'skip') { Write-Log 'SYSMON=skip: Sysmon not touched.'; return }
    if (-not (Test-Path -LiteralPath $Baseline)) { throw "Sysmon baseline missing: $Baseline" }
    $svc = Get-SysmonService
    if ($svc) {
        if ($SysmonConfig -eq 'replace') {
            $bin = Join-Path $env:windir ($svc.Name + '.exe')
            if (-not (Test-Path -LiteralPath $bin)) { $bin = Get-SysmonBinary }
            & $bin -c $Baseline | Out-Null
            if ($LASTEXITCODE -ne 0) { throw "Sysmon config replace exit $LASTEXITCODE" }
            Write-Log "Existing Sysmon ($($svc.Name)) now uses sysmon-baseline.xml."
        } else {
            Write-Log "Sysmon already installed ($($svc.Name)); its config is left as is (SYSMON_CONFIG=keep)."
        }
    } else {
        $bin = Get-SysmonBinary
        & $bin -accepteula -i $Baseline | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "Sysmon install exit $LASTEXITCODE" }
        New-Item -Path $StateKey -Force | Out-Null
        Set-ItemProperty -Path $StateKey -Name 'SysmonInstalledByVindex' -Value 1 -Type DWord
        Set-ItemProperty -Path $StateKey -Name 'SysmonBinary' -Value $bin
        Write-Log "Installed Sysmon ($([IO.Path]::GetFileName($bin))) with sysmon-baseline.xml."
    }
    Set-SysmonLogLimit
    Register-SysmonArchivePrune
}

function Uninstall-Vindex {
    Unregister-ScheduledTask -TaskName $PruneTask -Confirm:$false -ErrorAction SilentlyContinue
    Write-Log "Removed '$PruneTask'."
    $state = Get-ItemProperty -Path $StateKey -ErrorAction SilentlyContinue
    if ($state -and $state.PSObject.Properties['SysmonInstalledByVindex'] -and $state.SysmonInstalledByVindex -eq 1) {
        $svc = Get-SysmonService
        if ($svc) {
            $bin = Join-Path $env:windir ($svc.Name + '.exe')
            if (-not (Test-Path -LiteralPath $bin)) { $bin = [string]$state.SysmonBinary }
            if ($bin -and (Test-Path -LiteralPath $bin)) {
                & $bin -u force | Out-Null
                Write-Log "Uninstalled Sysmon (exit $LASTEXITCODE)."
            }
        }
    } else {
        Write-Log 'Sysmon was not installed by Vindex; left in place.'
    }
    Remove-Item -Path $StateKey -Recurse -Force -ErrorAction SilentlyContinue
}

try {
    Write-Log "vindex-endpoint-setup $Mode (SYSMON=$Sysmon, SYSMON_CONFIG=$SysmonConfig)"
    if ($Mode -eq 'install') { Install-Sysmon } else { Uninstall-Vindex }
    exit 0
} catch {
    Write-Log "ERROR: $($_.Exception.Message)"
    if ($Mode -eq 'install' -and $Sysmon -eq 'required') { exit 1 }
    # Agent telemetry still flows without Sysmon; the console shows the endpoint as missing it.
    Write-Log 'Continuing without Sysmon (set SYSMON=required to fail the install instead).'
    exit 0
}
