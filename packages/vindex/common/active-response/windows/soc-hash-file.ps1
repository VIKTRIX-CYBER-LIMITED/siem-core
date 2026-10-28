# Wazuh ≥4.2 read-only hash AR (Windows). One JSON line on STDIN.
# Hashes an existing file under user/profile or Temp/Downloads/AppData, on a local drive-letter
# path only (UNC, \\?\ and \\.\ paths are refused: no SMB egress).
# Registered roots (System32/SysWOW64, Defender platform/tool trees — spec 275; Program
# Files — spec 861) are allowed only when the alert already names the canonical path.
# Since spec 275 an ok result also carries the endpoint-measured Authenticode object
# {status, signer_subject, issuer, catalog} (Get-AuthenticodeSignature; IsOSBinary is
# the catalog indicator). Never copies, deletes, isolates, or kills.
# Spec 888 (deploy-34 D2): before hashing, the file is opened query-only and its final path
# (GetFinalPathNameByHandle, which resolves reparse points) must equal the canonical queued
# target — a junction/symlink planted on the queued path refuses (reparse_target_mismatch;
# final_path_unavailable when the final path cannot be determined). Fail-closed either way.
# Timeout ≤15s for Get-FileHash. Signature verification is the endpoint's own
# (WinVerifyTrust through the cmdlet) — the manager never parses binaries.
# https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html
$ArLog = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'
$HashTimeoutSec = 15

# Mirrors the pipeline's registered image roots exactly (core/provenance_claims.py
# MODULE_ROOTS + TOOL_SERVICES trees + core/wazuh_hash_file.py HASH_IDENTITY_ROOTS; the
# spec 861 contract compares the two sets). The pipeline admits them the same way.
$RegisteredImageRoots = @(
    'c:\program files (x86)\',
    'c:\program files (x86)\ossec-agent\',
    'c:\program files\',
    'c:\program files\osquery\',
    'c:\program files\windows defender\',
    'c:\programdata\microsoft\windows defender\',
    'c:\programdata\microsoft\windows defender\definition updates\',
    'c:\programdata\microsoft\windows defender\platform\',
    'c:\windows\',
    'c:\windows\system32\',
    'c:\windows\syswow64\',
    'c:\windows\winsxs\'
)

$stdin = New-Object System.IO.StreamReader([Console]::OpenStandardInput())

function Write-ArJson([hashtable]$Payload) {
    # Use the JSON serializer: paths/error fields must not create extra records.
    # The nested authenticode hashtable rides the same one-line record.
    $record = [ordered]@{ soc_ar = 'hash_file'; ok = [bool]$Payload.ok }
    foreach ($field in @('sha256', 'path', 'alert_id', 'agent_id', 'execution_id', 'error')) {
        if ($Payload.ContainsKey($field) -and $null -ne $Payload[$field]) {
            $record[$field] = [string]$Payload[$field]
        }
    }
    if ($Payload.ContainsKey('authenticode') -and $null -ne $Payload['authenticode']) {
        $record['authenticode'] = $Payload['authenticode']
    }
    $json = $record | ConvertTo-Json -Compress -Depth 3
    [System.IO.File]::AppendAllText($ArLog, $json + [Environment]::NewLine)
}

function Get-CanonicalWindowsPath([string]$Path) {
    # Lexical resolve: collapse . / .. before the root deny so
    # Temp\..\..\..\Windows\System32\... cannot ride the Temp allow token.
    # GetFullPath does not require the file to exist.
    $full = [string]$Path
    if ([string]::IsNullOrWhiteSpace($full)) { return '' }
    try {
        return [System.IO.Path]::GetFullPath($full.Replace('/', '\'))
    } catch {
        return ''
    }
}

function Test-UnderRegisteredRoot([string]$NormPath) {
    foreach ($root in $RegisteredImageRoots) {
        if ($NormPath.StartsWith($root) -and $NormPath.Length -gt $root.Length) {
            return $true
        }
    }
    return $false
}

# C-IX: only a local drive-letter path is ever hashed. A UNC (\\server\share), device (\\.\)
# or extended (\\?\) path would open an SMB session from LocalSystem to a host the alert
# names (machine-account NTLM egress); relative and drive-relative paths would resolve
# against the working directory. Mirrors _DRIVE_PATH_RE in core/wazuh_hash_file.py.
$DrivePathPattern = '^[a-z]:\\'

function Test-PathAllowed([string]$Path, [string]$AlertRaw) {
    $full = [string]$Path
    if ([string]::IsNullOrWhiteSpace($full)) { return $false }
    if ($full.Trim().Replace('/', '\') -notmatch $DrivePathPattern) { return $false }
    $canon = Get-CanonicalWindowsPath $full
    if ([string]::IsNullOrWhiteSpace($canon)) { return $false }
    if ($canon -notmatch $DrivePathPattern) { return $false }
    $norm = $canon.ToLowerInvariant()

    if (Test-UnderRegisteredRoot $norm) {
        # Fail-closed: only allow when the alert already names this canonical path
        # (the drop target, or the claim-bound source image the pipeline dispatched for).
        if ([string]::IsNullOrWhiteSpace($AlertRaw)) { return $false }
        # Prefer structured target_path / targetFilename / sourceImage if present in JSON.
        $alertCanon = ''
        try {
            $alertObj = $AlertRaw | ConvertFrom-Json
            if ($alertObj.parameters -and $alertObj.parameters.alert -and $alertObj.parameters.alert.data) {
                $d = $alertObj.parameters.alert.data
                if ($d.target_path) { $alertCanon = Get-CanonicalWindowsPath ([string]$d.target_path) }
                elseif ($d.targetFilename) { $alertCanon = Get-CanonicalWindowsPath ([string]$d.targetFilename) }
                elseif ($d.sourceImage) { $alertCanon = Get-CanonicalWindowsPath ([string]$d.sourceImage) }
            }
        } catch {}
        if (-not [string]::IsNullOrWhiteSpace($alertCanon)) {
            return ($alertCanon.ToLowerInvariant() -eq $norm)
        }
        return $AlertRaw.IndexOf($canon, [StringComparison]::OrdinalIgnoreCase) -ge 0
    }

    # User/profile or common drop locations (on the *canonical* path).
    if ($norm -match '\\users\\') { return $true }
    if ($norm -match '\\appdata\\') { return $true }
    if ($norm -match '\\temp\\' -or $norm -match '\\tmp\\') { return $true }
    if ($norm -match '\\downloads\\') { return $true }
    return $false
}

# Spec 888 (deploy-34 D2): the final-path probe. P/Invoke is the only way to reach
# GetFinalPathNameByHandle from Windows PowerShell; the handle is query-only
# (dwDesiredAccess = 0, share-all, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS) so the
# reparse point is traversed to the file that would be hashed without reading a byte.
$FinalPathSource = @'
using System;
using System.Runtime.InteropServices;
using System.Text;

public static class FinalPathProbe
{
    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern IntPtr CreateFileW(
        string lpFileName, uint dwDesiredAccess, uint dwShareMode,
        IntPtr lpSecurityAttributes, uint dwCreationDisposition,
        uint dwFlagsAndAttributes, IntPtr hTemplateFile);

    [DllImport("kernel32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
    public static extern uint GetFinalPathNameByHandleW(
        IntPtr hFile, StringBuilder lpszFilePath, uint cchFilePath, uint dwFlags);

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr hObject);
}
'@

function Get-FinalPath([string]$Path) {
    # Returns the fully resolved path ('C:\...'), or '' when it cannot be determined.
    try { Add-Type -TypeDefinition $FinalPathSource -ErrorAction Stop } catch { return '' }
    $handle = [FinalPathProbe]::CreateFileW(
        $Path, [uint32]0, [uint32]7, [IntPtr]::Zero, [uint32]3, [uint32]0x02000000, [IntPtr]::Zero)
    if ($handle -eq [IntPtr](-1)) { return '' }
    try {
        $capacity = [uint32]1024
        $builder = New-Object System.Text.StringBuilder([int]$capacity)
        $needed = [FinalPathProbe]::GetFinalPathNameByHandleW(
            $handle, $builder, $capacity, [uint32]0)
        if ($needed -eq 0) { return '' }
        if ($needed -ge $capacity) {
            # Return value is the required size including the null when the buffer is short.
            $capacity = [uint32]($needed + 1)
            $builder = New-Object System.Text.StringBuilder([int]$capacity)
            $needed = [FinalPathProbe]::GetFinalPathNameByHandleW(
                $handle, $builder, $capacity, [uint32]0)
            if ($needed -eq 0 -or $needed -ge $capacity) { return '' }
        }
        $final = $builder.ToString()
    } finally {
        [void][FinalPathProbe]::CloseHandle($handle)
    }
    # VOLUME_NAME_DOS results carry the \\?\ prefix; a \\?\UNC\ form cannot occur here
    # (UNC targets were refused at the door) and stays unequal, i.e. refused.
    if ($final.StartsWith('\\?\')) { $final = $final.Substring(4) }
    return $final
}

function Get-Authenticode([string]$Path) {
    # Endpoint's own signature verification. Closed ack vocabulary (spec 275):
    # SignatureStatus {NotTrusted, NotSupportedFileFormat, Incompatible} fold to
    # UnknownError; catalog = IsOSBinary (signed as part of an OS release).
    # A probe failure never fails the hash: it reports UnknownError.
    $block = [ordered]@{
        status         = 'UnknownError'
        signer_subject = ''
        issuer         = ''
        catalog        = $false
    }
    try {
        $sig = Get-AuthenticodeSignature -LiteralPath $Path -ErrorAction Stop
    } catch {
        return $block
    }
    switch ([string]$sig.Status) {
        'Valid' { $block.status = 'Valid' }
        'NotSigned' { $block.status = 'NotSigned' }
        'HashMismatch' { $block.status = 'HashMismatch' }
        default { $block.status = 'UnknownError' }
    }
    if ($null -ne $sig.SignerCertificate) {
        if ($sig.SignerCertificate.Subject) {
            $block.signer_subject = [string]$sig.SignerCertificate.Subject
        }
        if ($sig.SignerCertificate.Issuer) {
            $block.issuer = [string]$sig.SignerCertificate.Issuer
        }
    }
    if ($null -ne $sig.PSObject.Properties['IsOSBinary']) {
        $block.catalog = [bool]$sig.IsOSBinary
    }
    return $block
}

function Get-TargetPath($Msg) {
    $path = ''
    if ($Msg.parameters -and $Msg.parameters.alert -and $Msg.parameters.alert.data) {
        $data = $Msg.parameters.alert.data
        if ($data.target_path) { $path = [string]$data.target_path }
        elseif ($data.targetFilename) { $path = [string]$data.targetFilename }
        elseif ($data.win -and $data.win.eventdata -and $data.win.eventdata.targetFilename) {
            $path = [string]$data.win.eventdata.targetFilename
        }
    }
    if (-not $path -and $Msg.parameters -and $Msg.parameters.extra_args) {
        $extra = @($Msg.parameters.extra_args | ForEach-Object { [string]$_ })
        if ($extra.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($extra[0])) {
            $path = $extra[0]
        }
    }
    if (-not $path -and $Msg.parameters -and $Msg.parameters.alert -and $Msg.parameters.alert.arguments) {
        $args = @($Msg.parameters.alert.arguments | ForEach-Object { [string]$_ })
        if ($args.Count -gt 0) { $path = $args[0] }
    }
    return $path.Trim()
}

$raw = $stdin.ReadLine()
if ([string]::IsNullOrWhiteSpace($raw)) {
    Write-ArJson @{ soc_ar = 'hash_file'; ok = $false; error = 'empty_stdin' }
    exit 2
}

try {
    $msg = $raw | ConvertFrom-Json
} catch {
    Write-ArJson @{ soc_ar = 'hash_file'; ok = $false; error = 'bad_json' }
    exit 2
}

$mode = ([string]$msg.command).Trim().ToLowerInvariant()
# PUT /active-response sends command = add|delete for stateful scripts; also
# accept a bare run (no mode) as hash. delete is a no-op for read-only hash.
if ($mode -eq 'delete') {
    Write-ArJson @{ soc_ar = 'hash_file'; ok = $true; noop = 'delete' }
    exit 0
}

$target = Get-TargetPath $msg
$originId = ''
$agentId = ''
$executionId = ''
if ($msg.parameters -and $msg.parameters.alert) {
    $originId = [string]$msg.parameters.alert.id
    if ($msg.parameters.alert.data -and $msg.parameters.alert.data.origin_alert_id) {
        $originId = [string]$msg.parameters.alert.data.origin_alert_id
    }
    if ($msg.parameters.alert.data -and $msg.parameters.alert.data.execution_id) {
        $executionId = [string]$msg.parameters.alert.data.execution_id
    }
    if ($msg.parameters.alert.agent -and $msg.parameters.alert.agent.id) {
        $agentId = [string]$msg.parameters.alert.agent.id
    }
}
$originId = $originId.Trim()
$agentId = $agentId.Trim()

$base = @{
    soc_ar   = 'hash_file'
    path     = $target
    alert_id = $originId
    agent_id = $agentId
    execution_id = $executionId
}

$executionGuid = [guid]::Empty
if (-not [guid]::TryParse($executionId, [ref]$executionGuid)) {
    $base.ok = $false
    $base.error = 'missing_execution_id'
    Write-ArJson $base
    exit 2
}
$base.execution_id = $executionGuid.ToString()

if ([string]::IsNullOrWhiteSpace($target)) {
    $base.ok = $false
    $base.error = 'missing_path'
    Write-ArJson $base
    exit 2
}

if (-not (Test-PathAllowed -Path $target -AlertRaw $raw)) {
    $base.ok = $false
    $base.error = 'path_denied'
    Write-ArJson $base
    exit 2
}

# Hash the canonical path (same resolution the allowlist used).
$canonTarget = Get-CanonicalWindowsPath $target
if ([string]::IsNullOrWhiteSpace($canonTarget)) {
    $base.ok = $false
    $base.error = 'path_denied'
    Write-ArJson $base
    exit 2
}
$target = $canonTarget
$base.path = $target

if (-not (Test-Path -LiteralPath $target)) {
    $base.ok = $false
    $base.error = 'path_missing'
    Write-ArJson $base
    exit 1
}

$item = Get-Item -LiteralPath $target -ErrorAction SilentlyContinue
if ($null -eq $item -or $item.PSIsContainer) {
    $base.ok = $false
    $base.error = 'not_a_file'
    Write-ArJson $base
    exit 1
}

# Spec 888 (deploy-34 D2): the queued path must be the final path. A junction or symlink
# planted under a user-writable tree would otherwise let a lexical allowlist open (and hash)
# a file it never admitted — refuse on any difference (case-insensitive: NTFS preserves case,
# the allowlists do not) and when the final path cannot be determined.
$finalPath = Get-FinalPath $target
if ([string]::IsNullOrWhiteSpace($finalPath)) {
    $base.ok = $false
    $base.error = 'final_path_unavailable'
    Write-ArJson $base
    exit 2
}
if ($finalPath.ToLowerInvariant() -ne $target.ToLowerInvariant()) {
    $base.ok = $false
    $base.error = 'reparse_target_mismatch'
    Write-ArJson $base
    exit 2
}

try {
    $job = Start-Job -ScriptBlock {
        param($P)
        Get-FileHash -LiteralPath $P -Algorithm SHA256 -ErrorAction Stop
    } -ArgumentList $target
    $done = Wait-Job -Job $job -Timeout $HashTimeoutSec
    if (-not $done) {
        Stop-Job $job -ErrorAction SilentlyContinue
        Remove-Job $job -Force -ErrorAction SilentlyContinue
        $base.ok = $false
        $base.error = 'hash_timeout'
        Write-ArJson $base
        exit 1
    }
    $hashObj = Receive-Job -Job $job -ErrorAction Stop
    Remove-Job $job -Force -ErrorAction SilentlyContinue
    $sha = [string]$hashObj.Hash
    if ([string]::IsNullOrWhiteSpace($sha)) {
        $base.ok = $false
        $base.error = 'hash_empty'
        Write-ArJson $base
        exit 1
    }
    $base.ok = $true
    $base.sha256 = $sha.ToLowerInvariant()
    # Identity half (spec 275): the endpoint's own Authenticode verification.
    # Runs inline after the hash job; a probe failure stays UnknownError, never
    # fails the ok hash.
    $base.authenticode = Get-Authenticode $target
    Write-ArJson $base
    exit 0
} catch {
    $base.ok = $false
    $base.error = 'hash_failed'
    Write-ArJson $base
    exit 1
}
