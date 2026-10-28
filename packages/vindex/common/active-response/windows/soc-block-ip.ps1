# Wazuh ≥4.2 stateful AR overlay (Windows). Stock block is netsh.exe; this
# script is only the signed-ack overlay. One JSON line on STDIN; check_keys
# handshake on add; HMAC ack via sidecar or SOC_ACK_* env.
# https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html
param([switch]$Readback, [switch]$Revert)

$RulePrefix = 'SOC-block-'
$SidecarName = 'soc-block-ip.secrets.json'
$ArLog = 'C:\Program Files (x86)\ossec-agent\active-response\active-responses.log'

$stdin = New-Object System.IO.StreamReader([Console]::OpenStandardInput())
$stdout = New-Object System.IO.StreamWriter([Console]::OpenStandardOutput())
$stdout.AutoFlush = $true

function Write-ArLog([string]$Message) {
    try {
        $line = '{0} soc-block-ip: {1}' -f ([datetime]::UtcNow.ToString('o')), $Message
        Add-Content -LiteralPath $ArLog -Value $line -ErrorAction SilentlyContinue
    } catch {}
}

function Get-TargetDigest([string]$Target) {
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $hash = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes([string]$Target))
        return ([BitConverter]::ToString($hash) -replace '-', '').ToLowerInvariant()
    } finally {
        $sha.Dispose()
    }
}

function Get-CanonicalAckBody {
    param($Action, $AgentId, $DispatchLeaseRef, $Event, $ExecutionId, [bool]$LocalRulePresent, $Nonce, $TargetDigest, $Ts, $Config)
    # Ordered keys match Python sort_keys; ConvertTo-Json escapes string values.
    if ($DispatchLeaseRef) {
        return ([ordered]@{
            action = [string]$Action; agent_id = [string]$AgentId
            dispatch_lease_ref = [string]$DispatchLeaseRef
            enrollment_ref = [string]$Config.EnrollmentRef; event = [string]$Event
            execution_id = [string]$ExecutionId; local_rule_present = $LocalRulePresent
            nonce = [string]$Nonce; target_digest = [string]$TargetDigest
            tenant_uuid = [string]$Config.TenantUuid; ts = [string]$Ts
            wazuh_instance_id = [string]$Config.WazuhInstanceId
        } | ConvertTo-Json -Compress)
    }
    return ([ordered]@{ action = [string]$Action; agent_id = [string]$AgentId
        enrollment_ref = [string]$Config.EnrollmentRef; event = [string]$Event
        execution_id = [string]$ExecutionId; local_rule_present = $LocalRulePresent
        nonce = [string]$Nonce; target_digest = [string]$TargetDigest
        tenant_uuid = [string]$Config.TenantUuid; ts = [string]$Ts
        wazuh_instance_id = [string]$Config.WazuhInstanceId } | ConvertTo-Json -Compress)
}

function Get-AckSignature {
    param($Canonical, $Key)
    $hmac = New-Object System.Security.Cryptography.HMACSHA256
    $hmac.Key = [Text.Encoding]::UTF8.GetBytes($Key)
    $hash = $hmac.ComputeHash([Text.Encoding]::UTF8.GetBytes($Canonical))
    return ([BitConverter]::ToString($hash) -replace '-', '').ToLowerInvariant()
}

function Get-AckConfig {
    $url = [string]$env:SOC_ACK_URL
    $apiKey = [string]$env:SOC_ACK_API_KEY
    $hmacKey = [string]$env:SOC_ACK_HMAC_KEY
    $tenantUuid = [string]$env:SOC_ACK_TENANT_UUID
    $manager = [string]$env:SOC_ACK_WAZUH_INSTANCE_ID
    $enrollment = [string]$env:SOC_ACK_ENROLLMENT_REF
    $agent = [string]$env:SOC_ACK_AGENT_ID
    $sidecar = Join-Path $PSScriptRoot $SidecarName
    if (Test-Path -LiteralPath $sidecar) {
        $data = Get-Content -LiteralPath $sidecar -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json
        if (-not $url) { $url = [string]$data.ack_url }
        if (-not $apiKey) { $apiKey = [string]$data.api_key }
        if (-not $hmacKey) { $hmacKey = [string]$data.hmac_key }
        if (-not $tenantUuid) { $tenantUuid = [string]$data.tenant_uuid }
        if (-not $manager) { $manager = [string]$data.wazuh_instance_id }
        if (-not $enrollment) { $enrollment = [string]$data.enrollment_ref }
        if (-not $agent) { $agent = [string]$data.agent_id }
    }
    return @{ Url = $url.Trim(); ApiKey = $apiKey.Trim(); HmacKey = $hmacKey.Trim()
              TenantUuid = $tenantUuid.Trim(); WazuhInstanceId = $manager.Trim()
              EnrollmentRef = $enrollment.Trim(); AgentId = $agent.Trim() }
}

function Test-EndpointScope($Config, $Data) {
    try {
        if (([guid]$Config.TenantUuid).ToString() -cne $Config.TenantUuid) { return $false }
        if ($Config.WazuhInstanceId -cnotmatch '^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$') { return $false }
        if ($Config.EnrollmentRef -cnotmatch '^sha256:[a-f0-9]{64}$') { return $false }
        if ($Config.AgentId -cnotmatch '^[0-9]{1,6}$' -or [int]$Config.AgentId -eq 0) { return $false }
        return $Data.action -ceq 'block_ip' -and $Data.tenant_uuid -ceq $Config.TenantUuid -and
            $Data.wazuh_instance_id -ceq $Config.WazuhInstanceId -and
            $Data.enrollment_ref -ceq $Config.EnrollmentRef -and $Data.agent_id -ceq $Config.AgentId
    } catch { return $false }
}

function Invoke-Netsh {
    param([Parameter(ValueFromRemainingArguments = $true)][string[]]$NetshArgs)
    $saved = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    try {
        $output = & netsh @NetshArgs 2>&1 | Out-String
        $code = [int]$LASTEXITCODE
        return @{ Code = $code; Output = [string]$output }
    } finally {
        $ErrorActionPreference = $saved
    }
}

function ConvertTo-BlockAddress([string]$Value) {
    $parts = $Value.Split('/')
    if ($parts.Count -gt 2) { throw 'malformed rule address' }
    $address = [Net.IPAddress]::Parse($parts[0])
    $hostPrefix = if ($address.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork) { '32' } else { '128' }
    if ($parts.Count -eq 2 -and $parts[1] -ne $hostPrefix) { throw 'non-host rule address' }
    if ($address.IsIPv4MappedToIPv6) { $address = $address.MapToIPv4() }
    return $address.ToString()
}

function Get-BlockRuleState([string]$ExecutionId, [string]$TargetIp) {
    $name = $RulePrefix + $ExecutionId
    try {
        # A failed/localized netsh show is not proof of absence. Read the
        # effective store successfully, then match the exact execution name.
        $rules = @(Get-NetFirewallRule -PolicyStore ActiveStore -ErrorAction Stop |
            Where-Object { $_.DisplayName -ceq $name })
        $matches = $rules.Count -gt 0
        foreach ($rule in $rules) {
            if ([string]$rule.Enabled -ne 'True' -or
                [string]$rule.Direction -ne 'Inbound' -or
                [string]$rule.Action -ne 'Block') { $matches = $false }
            $filter = @(Get-NetFirewallAddressFilter -AssociatedNetFirewallRule $rule -ErrorAction Stop)
            if ($filter.Count -ne 1) { $matches = $false; continue }
            $remote = @($filter[0].RemoteAddress)
            if ($remote.Count -ne 1) { $matches = $false; continue }
            if ((ConvertTo-BlockAddress ([string]$remote[0])) -ne
                (ConvertTo-BlockAddress $TargetIp)) { $matches = $false }
        }
        return @{ Available = $true; Present = ($rules.Count -gt 0); Matches = $matches }
    } catch {
        return @{ Available = $false; Present = $true; Matches = $false }
    }
}

function Add-BlockRule([string]$ExecutionId, [string]$TargetIp) {
    $name = $RulePrefix + $ExecutionId
    $result = Invoke-Netsh advfirewall firewall add rule "name=$name" dir=in action=block "remoteip=$TargetIp" enable=yes
    $state = Get-BlockRuleState -ExecutionId $ExecutionId -TargetIp $TargetIp
    return ($result.Code -eq 0) -and $state.Available -and $state.Matches
}

function Remove-BlockRule([string]$ExecutionId, [string]$TargetIp) {
    $name = $RulePrefix + $ExecutionId
    Invoke-Netsh advfirewall firewall delete rule "name=$name" | Out-Null
    $state = Get-BlockRuleState -ExecutionId $ExecutionId -TargetIp $TargetIp
    return $state.Available -and (-not $state.Present)
}

function Send-Ack {
    param($Config, $Action, $AgentId, $DispatchLeaseRef, $ExecutionId, $Event, [bool]$Present, $Target)
    $ts = [datetime]::UtcNow.ToString('o')
    $nonce = [guid]::NewGuid().ToString('N')
    $digest = Get-TargetDigest $Target
    $canon = Get-CanonicalAckBody -Action $Action -AgentId $AgentId -DispatchLeaseRef $DispatchLeaseRef -Event $Event -ExecutionId $ExecutionId -LocalRulePresent $Present -Nonce $nonce -TargetDigest $digest -Ts $ts -Config $Config
    $sig = Get-AckSignature -Canonical $canon -Key $Config.HmacKey
    try {
        Invoke-WebRequest -Uri $Config.Url -Method POST -ContentType 'application/json' -Body $canon -Headers @{
            'X-API-Key' = $Config.ApiKey
            'X-SOC-Ack-Signature' = $sig
        } -UseBasicParsing -TimeoutSec 10 | Out-Null
    } catch {
        Write-ArLog ("ack failed: " + $_.Exception.Message)
    }
}

$raw = $stdin.ReadLine()
if ([string]::IsNullOrWhiteSpace($raw)) {
    Write-ArLog 'empty STDIN'
    exit 2
}
try {
    $msg = $raw | ConvertFrom-Json
} catch {
    Write-ArLog 'bad STDIN JSON'
    exit 2
}

$mode = ([string]$msg.command).Trim().ToLowerInvariant()
$srcip = ''
$executionId = ''
$agentId = ''
$actionName = 'block_ip'
$dispatchLeaseRef = ''
$expectedState = ''
if ($msg.parameters -and $msg.parameters.alert) {
    $alert = $msg.parameters.alert
    if ($alert.data) {
        $srcip = [string]$alert.data.srcip
        $executionId = [string]$alert.data.execution_id
        $agentId = [string]$alert.data.agent_id
        if ($alert.data.action) { $actionName = [string]$alert.data.action }
        if ($alert.data.dispatch_lease_ref) { $dispatchLeaseRef = [string]$alert.data.dispatch_lease_ref }
        if ($alert.data.expected_state) { $expectedState = [string]$alert.data.expected_state }
    }
    if (-not $agentId -and $alert.agent) { $agentId = [string]$alert.agent.id }
}
$extra = @()
if ($msg.parameters -and $msg.parameters.extra_args) {
    $extra = @($msg.parameters.extra_args | ForEach-Object { [string]$_ })
}
if (-not $executionId -and $extra.Count -gt 0) { $executionId = $extra[-1] }
if (-not $srcip -and $extra.Count -gt 0) { $srcip = $extra[0] }
$srcip = $srcip.Trim()
$executionId = $executionId.Trim()
$agentId = $agentId.Trim()
$actionName = $actionName.Trim()
$dispatchLeaseRef = $dispatchLeaseRef.Trim()
$expectedState = $expectedState.Trim().ToLowerInvariant()

if ($mode -notin @('add', 'delete')) {
    Write-ArLog "unsupported command $mode"
    exit 2
}
if (-not $executionId) {
    Write-ArLog 'missing execution_id'
    exit 2
}
if (-not $agentId) {
    Write-ArLog 'missing agent_id'
    exit 2
}

$config = Get-AckConfig
if (-not $config.Url -or -not $config.ApiKey -or -not $config.HmacKey) {
    Write-ArLog 'missing ack config'
    exit 2
}

if (-not (Test-EndpointScope -Config $config -Data $msg.parameters.alert.data)) {
    Write-ArLog 'endpoint scope mismatch'
    exit 2
}

if ($Revert) {
    # Spec 819: analyst revert of a policy-bound block before its TTL. Stateless entry point
    # (soc-block-ip-revert0, no check_keys): removes only the exact execution rule and sends a
    # lease-bound signed ack. Absence is reported only when the store was read successfully.
    if ($dispatchLeaseRef -cnotmatch '^sha256:[a-f0-9]{64}$' -or -not $srcip) {
        Write-ArLog 'revert binding invalid'
        exit 2
    }
    $ok = Remove-BlockRule -ExecutionId $executionId -TargetIp $srcip
    $state = Get-BlockRuleState -ExecutionId $executionId -TargetIp $srcip
    $present = (-not $state.Available) -or $state.Present
    $event = if ($ok -and -not $present) { 'reverted' } else { 'failed' }
    Send-Ack -Config $config -Action $actionName -AgentId $agentId -DispatchLeaseRef $dispatchLeaseRef -ExecutionId $executionId -Event $event -Present $present -Target $srcip
    if ($event -eq 'reverted') { exit 0 } else { exit 1 }
}

if ($Readback) {
    if ($dispatchLeaseRef -cnotmatch '^sha256:[a-f0-9]{64}$' -or
        $expectedState -notin @('present','absent') -or -not $srcip) {
        Write-ArLog 'readback binding invalid'
        exit 2
    }
    $state = Get-BlockRuleState -ExecutionId $executionId -TargetIp $srcip
    if (-not $state.Available) {
        Send-Ack -Config $config -Action $actionName -AgentId $agentId -DispatchLeaseRef $dispatchLeaseRef -ExecutionId $executionId -Event 'failed' -Present $true -Target $srcip
        exit 1
    }
    if ($expectedState -eq 'present') {
        $present = $state.Present -and $state.Matches
        $event = if ($present) { 'verified' } else { 'failed' }
        Send-Ack -Config $config -Action $actionName -AgentId $agentId -DispatchLeaseRef $dispatchLeaseRef -ExecutionId $executionId -Event $event -Present $state.Present -Target $srcip
        if ($present) { exit 0 } else { exit 1 }
    }
    $absent = -not $state.Present
    $event = if ($absent) { 'reverted' } else { 'failed' }
    Send-Ack -Config $config -Action $actionName -AgentId $agentId -DispatchLeaseRef $dispatchLeaseRef -ExecutionId $executionId -Event $event -Present $state.Present -Target $srcip
    if ($absent) { exit 0 } else { exit 1 }
}

if ($mode -eq 'add') {
    $key = if ($srcip) { $srcip } else { $executionId }
    $keysMsg = '{{"version":1,"origin":{{"name":"soc-block-ip","module":"active-response"}},"command":"check_keys","parameters":{{"keys":["{0}"]}}}}' -f $key
    $stdout.WriteLine($keysMsg)
    $stdout.Flush()
    $respLine = $stdin.ReadLine()
    try {
        $resp = $respLine | ConvertFrom-Json
        $action = ([string]$resp.command).Trim().ToLowerInvariant()
    } catch {
        $action = 'invalid'
    }
    if ($action -eq 'abort') {
        Write-ArLog 'check_keys abort'
        exit 0
    }
    if ($action -ne 'continue') {
        Write-ArLog "check_keys invalid:$action"
        exit 2
    }
    if (-not $srcip) {
        Write-ArLog 'missing srcip'
        exit 2
    }
    $ok = Add-BlockRule -ExecutionId $executionId -TargetIp $srcip
    $state = Get-BlockRuleState -ExecutionId $executionId -TargetIp $srcip
    $present = $state.Available -and $state.Matches
    $event = if ($ok -and $present) { 'applied' } else { 'failed' }
    Send-Ack -Config $config -Action $actionName -AgentId $agentId -DispatchLeaseRef $dispatchLeaseRef -ExecutionId $executionId -Event $event -Present $present -Target $srcip
    if ($ok) { exit 0 } else { exit 1 }
}

$ok = Remove-BlockRule -ExecutionId $executionId -TargetIp $srcip
$state = Get-BlockRuleState -ExecutionId $executionId -TargetIp $srcip
$present = (-not $state.Available) -or $state.Present
$ok = $ok -and (-not $present)
$event = if ($ok) { 'reverted' } else { 'failed' }
Send-Ack -Config $config -Action $actionName -AgentId $agentId -DispatchLeaseRef $dispatchLeaseRef -ExecutionId $executionId -Event $event -Present $present -Target $srcip
if ($ok) { exit 0 } else { exit 1 }
