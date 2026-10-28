# Read-only Windows dest-IP investigation from one Wazuh JSON request.
# The result names a live connection's process and signature; no endpoint state changes.
# https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html
$ArLog = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'

$stdin = New-Object System.IO.StreamReader([Console]::OpenStandardInput())

function Write-ArJson([hashtable]$Payload) {
    # Manual compact JSON so the manager stock `json` decoder (and any
    # soc-investigate-ip prematch) sees {"soc_ar":"investigate_ip" with no spaces.
    $ok = if ($Payload.ok) { 'true' } else { 'false' }
    $aid = ([string]$Payload.alert_id).Replace('"', '')
    $ag = ([string]$Payload.agent_id).Replace('"', '')
    $execution = ([string]$Payload.execution_id).Replace('"', '')
    $dip = ([string]$Payload.dest_ip).Replace('"', '')
    $err = if ($Payload.ContainsKey('error') -and $Payload.error) {
        ',"error":"' + ([string]$Payload.error).Replace('"', '') + '"'
    } else { '' }
    $pidPart = ''
    if ($Payload.ContainsKey('pid') -and $null -ne $Payload.pid -and [string]$Payload.pid -ne '') {
        $pidPart = ',"pid":' + ([int]$Payload.pid)
    }
    $image = ([string]$Payload.image).Replace('\', '\\').Replace('"', '')
    $imagePart = if ($image) { ',"image":"' + $image + '"' } else { '' }
    $sig = ([string]$Payload.signature_status).Replace('"', '')
    $sigPart = if ($sig) { ',"signature_status":"' + $sig + '"' } else { '' }
    $signer = ([string]$Payload.signer).Replace('"', '')
    $signerPart = if ($signer) { ',"signer":"' + $signer + '"' } else { '' }
    $json = '{"soc_ar":"investigate_ip","ok":' + $ok +
            ',"alert_id":"' + $aid +
            '","agent_id":"' + $ag +
            '","execution_id":"' + $execution +
            '","dest_ip":"' + $dip + '"' +
            $pidPart + $imagePart + $sigPart + $signerPart + $err + '}'
    # Do not use Add-Content with a swallowed error action: a share/ACL
    # failure must surface. AppendAllText throws on I/O errors.
    [System.IO.File]::AppendAllText($ArLog, $json + [Environment]::NewLine)
}

function Get-DestIp($Msg) {
    $ip = ''
    if ($Msg.parameters -and $Msg.parameters.alert -and $Msg.parameters.alert.data) {
        $data = $Msg.parameters.alert.data
        if ($data.dest_ip) { $ip = [string]$data.dest_ip }
        elseif ($data.dstip) { $ip = [string]$data.dstip }
        elseif ($data.dst_ip) { $ip = [string]$data.dst_ip }
        elseif ($data.destinationIp) { $ip = [string]$data.destinationIp }
        elseif ($data.destination_ip) { $ip = [string]$data.destination_ip }
        elseif ($data.win -and $data.win.eventdata) {
            $ed = $data.win.eventdata
            if ($ed.destinationIp) { $ip = [string]$ed.destinationIp }
            elseif ($ed.DestinationIp) { $ip = [string]$ed.DestinationIp }
            elseif ($ed.destAddress) { $ip = [string]$ed.destAddress }
            elseif ($ed.DestAddress) { $ip = [string]$ed.DestAddress }
        }
    }
    if (-not $ip -and $Msg.parameters -and $Msg.parameters.extra_args) {
        $extra = @($Msg.parameters.extra_args | ForEach-Object { [string]$_ })
        if ($extra.Count -gt 0 -and -not [string]::IsNullOrWhiteSpace($extra[0])) {
            $ip = $extra[0]
        }
    }
    if (-not $ip -and $Msg.parameters -and $Msg.parameters.alert -and $Msg.parameters.alert.arguments) {
        $args = @($Msg.parameters.alert.arguments | ForEach-Object { [string]$_ })
        if ($args.Count -gt 0) { $ip = $args[0] }
    }
    return $ip.Trim()
}

$raw = $stdin.ReadLine()
if ([string]::IsNullOrWhiteSpace($raw)) {
    Write-ArJson @{ soc_ar = 'investigate_ip'; ok = $false; error = 'empty_stdin' }
    exit 2
}

try {
    $msg = $raw | ConvertFrom-Json
} catch {
    Write-ArJson @{ soc_ar = 'investigate_ip'; ok = $false; error = 'bad_json' }
    exit 2
}

$mode = ([string]$msg.command).Trim().ToLowerInvariant()
# PUT /active-response sends command = add|delete for stateful scripts; also
# accept a bare run (no mode) as investigate. delete is a no-op for read-only.
if ($mode -eq 'delete') {
    Write-ArJson @{ soc_ar = 'investigate_ip'; ok = $true; error = '' }
    exit 0
}

$destIp = Get-DestIp $msg
$originId = ''
$agentId = ''
$executionId = ''
if ($msg.parameters -and $msg.parameters.alert) {
    $originId = [string]$msg.parameters.alert.id
    if ($msg.parameters.alert.data -and $msg.parameters.alert.data.origin_alert_id) {
        $originId = [string]$msg.parameters.alert.data.origin_alert_id
    }
    if ($msg.parameters.alert.agent -and $msg.parameters.alert.agent.id) {
        $agentId = [string]$msg.parameters.alert.agent.id
    }
    if ($msg.parameters.alert.data -and $msg.parameters.alert.data.execution_id) {
        $executionId = [string]$msg.parameters.alert.data.execution_id
    }
}
$originId = $originId.Trim()
$agentId = $agentId.Trim()
$executionId = $executionId.Trim()

$base = @{
    soc_ar   = 'investigate_ip'
    dest_ip  = $destIp
    alert_id = $originId
    agent_id = $agentId
    execution_id = $executionId
}

$parsedExecution = [guid]::Empty
if (-not [guid]::TryParse($executionId, [ref]$parsedExecution)) {
    $base.ok = $false
    $base.error = 'missing_execution_id'
    Write-ArJson $base
    exit 2
}

if ([string]::IsNullOrWhiteSpace($destIp)) {
    $base.ok = $false
    $base.error = 'missing_dest_ip'
    Write-ArJson $base
    exit 2
}

try {
    # Filter at the cmdlet — do not enumerate every connection then match.
    $conns = @(Get-NetTCPConnection -RemoteAddress $destIp -ErrorAction SilentlyContinue)
} catch {
    $conns = @()
}

$conn = $conns | Where-Object { $_.State -eq 'Established' } | Select-Object -First 1
if ($null -eq $conn) {
    $conn = $conns | Select-Object -First 1
}
if ($null -eq $conn -or $null -eq $conn.OwningProcess) {
    $base.ok = $false
    $base.error = 'no_live_conn'
    Write-ArJson $base
    exit 1
}

$pidVal = [int]$conn.OwningProcess
$proc = Get-Process -Id $pidVal -ErrorAction SilentlyContinue
$image = ''
if ($null -ne $proc -and $proc.Path) {
    $image = [string]$proc.Path
}
if ([string]::IsNullOrWhiteSpace($image)) {
    $base.ok = $false
    $base.error = 'no_live_conn'
    $base.pid = $pidVal
    Write-ArJson $base
    exit 1
}

$sigStatus = ''
$signer = ''
try {
    $sig = Get-AuthenticodeSignature -LiteralPath $image -ErrorAction Stop
    $sigStatus = [string]$sig.Status
    if ($null -ne $sig.SignerCertificate -and $sig.SignerCertificate.Subject) {
        $signer = [string]$sig.SignerCertificate.Subject
    }
} catch {
    $sigStatus = 'UnknownError'
}

$base.ok = $true
$base.pid = $pidVal
$base.image = $image
$base.signature_status = $sigStatus
$base.signer = $signer
Write-ArJson $base
exit 0
