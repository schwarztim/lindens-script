param($Request, $TriggerMetadata)
########## Version Marker ##########
$Script:ScriptVersion = "2026-01-14-subnet-dns-quiet-fail"
########## Helpers ##########
# Allowlist of DNS suffixes to try when a short hostname is provided (no dot)
$Script:AllowedSuffixes = @(
    "qrg.one",
    "hsn.net",
    "stpete.hsn.net",
    "qvcdev.qvc.net",
    "qvc-intern.de",
    "qvcuk.local",
    "qvcjp.com",
    "hq.cbi.intl",
    "media.qvcuk",
    "ccsginc.com",
    "hsn.net",
    "it.qvc.net",
    "broadcast.qvc",
    "hsnlab.com",
    "gh.cbi.intl",
    "stpete.hsn.com",
    "cbi.intl"
)
# Batch protection
$Script:MaxFlowCombinations = 25
# Basic port risk lists
$Script:HighRiskPorts   = @(22, 23, 3389, 5985, 5986, 5900, 445, 139, 135, 389, 636, 88, 464)
$Script:MediumRiskPorts = @(1433, 1521, 3306, 5432, 27017, 6379, 9200, 9300)

function Convert-IpV4ToInt64 {
    param([string]$Ip)
    $oct = $Ip.Split('.') | ForEach-Object { [int]$_ }
    if ($oct.Count -ne 4 -or ($oct | Where-Object { $_ -lt 0 -or $_ -gt 255 }).Count) {
        throw "Invalid IPv4: $Ip"
    }
    # cast to uint64 before shifting
    $ipInt =
        ([uint64]$oct[0] -shl 24) -bor
        ([uint64]$oct[1] -shl 16) -bor
        ([uint64]$oct[2] -shl 8)  -bor
        ([uint64]$oct[3])
    return $ipInt
}

function Convert-Int64ToIpV4 {
    param([uint64]$IpInt)
    $o1 = [int](($IpInt -shr 24) -band 0xFF)
    $o2 = [int](($IpInt -shr 16) -band 0xFF)
    $o3 = [int](($IpInt -shr 8) -band 0xFF)
    $o4 = [int]($IpInt -band 0xFF)
    return "$o1.$o2.$o3.$o4"
}

function Test-IsIpv4 {
    param([string]$Value)
    if (-not $Value) { return $false }
    return $Value -match '^\s*(\d{1,3}\.){3}\d{1,3}\s*$'
}

function Test-IsCidr {
    param([string]$Value)
    if (-not $Value) { return $false }
    return $Value -match '^\s*(\d{1,3}\.){3}\d{1,3}\s*/\s*(\d{1,2})\s*$'
}

function Get-SubnetStartIp {
    <#
    .SYNOPSIS
        Extracts the network start IP from a CIDR notation subnet.
    .DESCRIPTION
        Given a CIDR like "10.0.1.0/24" or "192.168.1.50/24", returns the
        network address (start IP) of the subnet.
    .PARAMETER Cidr
        The CIDR notation string (e.g., "10.0.0.0/24")
    .OUTPUTS
        Hashtable with: success, startIp, endIp, cidr, prefix, hostCount, error
    #>
    param([Parameter(Mandatory)][string]$Cidr)

    $result = @{
        success   = $false
        startIp   = $null
        endIp     = $null
        cidr      = $Cidr
        prefix    = $null
        hostCount = 0
        error     = $null
    }

    $trimmed = $Cidr.Trim()
    if ($trimmed -notmatch '^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*/\s*(\d{1,2})$') {
        $result.error = "Invalid CIDR format: '$Cidr'"
        return $result
    }

    $ipPart = $matches[1]
    $prefixLen = [int]$matches[2]

    if ($prefixLen -lt 0 -or $prefixLen -gt 32) {
        $result.error = "Invalid prefix length: $prefixLen (must be 0-32)"
        return $result
    }

    try {
        $ipInt = Convert-IpV4ToInt64 -Ip $ipPart
    }
    catch {
        $result.error = "Invalid IP in CIDR: $ipPart"
        return $result
    }

    # Calculate network mask
    if ($prefixLen -eq 0) {
        $mask = [uint64]0
    }
    else {
        $mask = ([uint64]0xFFFFFFFF) -shl (32 - $prefixLen) -band 0xFFFFFFFF
    }

    # Network address (start IP) = IP AND mask
    $networkInt = $ipInt -band $mask

    # Broadcast address (end IP) = network OR (NOT mask)
    $broadcastInt = $networkInt -bor ((-bnot $mask) -band 0xFFFFFFFF)

    $result.success = $true
    $result.startIp = Convert-Int64ToIpV4 -IpInt $networkInt
    $result.endIp = Convert-Int64ToIpV4 -IpInt $broadcastInt
    $result.prefix = $prefixLen
    $result.hostCount = [math]::Pow(2, (32 - $prefixLen))

    return $result
}

function Resolve-HostToIpv4s {
    param([Parameter(Mandatory)] [string] $Hostname)
    $addrs = [System.Net.Dns]::GetHostAddresses($Hostname)
    if (-not $addrs) { return @() }
    $ipv4s = @(
        $addrs |
            Where-Object { $_.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork } |
            ForEach-Object { $_.IPAddressToString }
    )
    return $ipv4s
}

function Resolve-IpOrHostToIpv4 {
    <#
    .SYNOPSIS
        Resolves an IP, hostname, or CIDR to an IPv4 address for flow evaluation.
    .DESCRIPTION
        Handles:
        - IP literals (returned as-is)
        - CIDR notation (extracts network start IP)
        - FQDNs (DNS lookup)
        - Short hostnames (tries allowed suffixes)

        When QuietFailure is enabled, DNS failures return a structured result
        instead of throwing an exception.
    .PARAMETER InputValue
        The IP, hostname, or CIDR to resolve.
    .PARAMETER SideLabel
        Label for error messages (e.g., "src" or "dst").
    .PARAMETER QuietFailure
        If true, returns failure info instead of throwing on DNS errors.
    #>
    param(
        [Parameter(Mandatory)] [string] $InputValue,
        [Parameter(Mandatory)] [string] $SideLabel,
        [switch] $QuietFailure
    )

    $v = ($InputValue ?? "").Trim()

    # Build a failure result helper
    $makeFailure = {
        param([string]$reason, [string]$errorType, [array]$tried)
        return @{
            success    = $false
            resolvedIp = $null
            resolution = @{
                type      = $errorType
                candidate = $v
                tried     = ($tried ?? @())
                error     = $reason
            }
        }
    }

    if ([string]::IsNullOrWhiteSpace($v)) {
        if ($QuietFailure) {
            return (& $makeFailure "Missing value for ${SideLabel}" "MISSING_INPUT" @())
        }
        throw "Missing value for ${SideLabel}"
    }

    # 1) CIDR notation - extract start IP
    if (Test-IsCidr -Value $v) {
        $subnetInfo = Get-SubnetStartIp -Cidr $v
        if (-not $subnetInfo.success) {
            if ($QuietFailure) {
                return (& $makeFailure $subnetInfo.error "INVALID_CIDR" @())
            }
            throw "Invalid CIDR for ${SideLabel}: $($subnetInfo.error)"
        }
        return @{
            success    = $true
            resolvedIp = $subnetInfo.startIp
            resolution = @{
                type       = "CIDR_SUBNET"
                candidate  = $v
                tried      = @()
                startIp    = $subnetInfo.startIp
                endIp      = $subnetInfo.endIp
                prefix     = $subnetInfo.prefix
                hostCount  = $subnetInfo.hostCount
                note       = "Using subnet start IP for search"
            }
        }
    }

    # 2) IP literal
    if (Test-IsIpv4 -Value $v) {
        try {
            [void](Convert-IpV4ToInt64 -Ip $v)
            return @{
                success    = $true
                resolvedIp = $v
                resolution = @{ type = "IP_LITERAL"; candidate = $v; tried = @() }
            }
        } catch {
            if ($QuietFailure) {
                return (& $makeFailure "Invalid IPv4 provided for ${SideLabel}: '$v'" "INVALID_IP" @())
            }
            throw "Invalid IPv4 provided for ${SideLabel}: '$v'"
        }
    }

    # 3) FQDN (contains a dot)
    if ($v -match '\.') {
        try {
            $ips = @(Resolve-HostToIpv4s -Hostname $v)
            if ($ips.Count -eq 0) {
                if ($QuietFailure) {
                    return (& $makeFailure "DNS returned no IPv4 addresses for FQDN: '$v'" "DNS_NO_RESULTS" @($v))
                }
                throw "DNS returned no IPv4 addresses"
            }
            return @{
                success    = $true
                resolvedIp = $ips[0]
                resolution = @{ type = "FQDN"; candidate = $v; tried = @($v); allIpv4 = $ips }
            }
        } catch {
            $errMsg = "Unable to resolve FQDN for ${SideLabel}: '$v'. $($_.Exception.Message)"
            if ($QuietFailure) {
                return (& $makeFailure $errMsg "DNS_LOOKUP_FAILED" @($v))
            }
            throw $errMsg
        }
    }

    # 4) Short hostname -> try suffixes
    $attempts = @()
    $hits = @()
    $dnsErrors = @()

    foreach ($sfx in $Script:AllowedSuffixes) {
        $fqdn = "$v.$sfx"
        $attempts += $fqdn
        try {
            $ips = @(Resolve-HostToIpv4s -Hostname $fqdn)
            if ($ips.Count -gt 0) {
                $hits += @{ fqdn = $fqdn; ips = $ips }
            }
        } catch {
            $dnsErrors += @{ fqdn = $fqdn; error = $_.Exception.Message }
        }
    }

    if ($hits.Count -eq 0) {
        $attemptList = ($attempts -join ", ")
        $errMsg = "Unable to resolve short hostname for ${SideLabel}: '$v'. Tried: $attemptList. Please provide the FQDN to be explicit."

        if ($QuietFailure) {
            return @{
                success    = $false
                resolvedIp = $null
                resolution = @{
                    type       = "DNS_SHORTNAME_FAILED"
                    candidate  = $v
                    tried      = $attempts
                    error      = $errMsg
                    dnsErrors  = $dnsErrors
                }
            }
        }
        throw $errMsg
    }

    $allIps = @()
    foreach ($h in $hits) { $allIps += @($h.ips) }
    $uniqueIps = @($allIps | Sort-Object -Unique)

    if ($uniqueIps.Count -eq 1) {
        $resolved = $uniqueIps | Select-Object -First 1
        return @{
            success    = $true
            resolvedIp = $resolved
            resolution = @{
                type       = "SHORTNAME_SUFFIX_FALLBACK"
                candidate  = $v
                tried      = $attempts
                matches    = $hits
                uniqueIpv4 = $uniqueIps
            }
        }
    }

    $matchSummary = ($hits | ForEach-Object { "$($_.fqdn) -> $([string]::Join('|', $_.ips))" }) -join "; "
    $errMsg = "Ambiguous short hostname for ${SideLabel}: '$v'. Multiple IPv4s resolved across suffixes. Matches: $matchSummary. Please provide the correct FQDN."

    if ($QuietFailure) {
        return @{
            success    = $false
            resolvedIp = $null
            resolution = @{
                type         = "DNS_AMBIGUOUS"
                candidate    = $v
                tried        = $attempts
                matches      = $hits
                uniqueIpv4   = $uniqueIps
                error        = $errMsg
            }
        }
    }
    throw $errMsg
}

function Get-IpRfc1918Class {
    param([string]$Ip)
    if ([string]::IsNullOrWhiteSpace($Ip)) { return "UNKNOWN" }
    $oct = $Ip.Split('.') | ForEach-Object { [int]$_ }
    if ($oct.Count -ne 4 -or ($oct | Where-Object { $_ -lt 0 -or $_ -gt 255 }).Count) {
        return "UNKNOWN"
    }
    $o1, $o2, $o3, $o4 = $oct
    if ($o1 -eq 10) { return "INTERNAL" }
    if ($o1 -eq 172 -and $o2 -ge 16 -and $o2 -le 31) { return "INTERNAL" }
    if ($o1 -eq 192 -and $o2 -eq 168) { return "INTERNAL" }
    return "EXTERNAL"
}

# Extract "zone" from pci_subnets_global docs
# Your sample shows cde_cse_p2pe = "CDE" (this is our zone signal)
function Get-ZoneFromDoc {
    param($doc)
    if (-not $doc) { return $null }
    $z = $null
    if ($doc.PSObject.Properties.Name -contains "cde_cse_p2pe") { $z = $doc.cde_cse_p2pe }
    if ([string]::IsNullOrWhiteSpace([string]$z) -and ($doc.PSObject.Properties.Name -contains "scope")) { $z = $doc.scope }
    return $z
}

# Query by IP Int against pci_subnets_global (StartIPInt / EndIPInt)
function Invoke-SearchByIpInt {
    param(
        [Parameter(Mandatory)] [uint64] $IpInt,
        [Parameter(Mandatory)] [string]  $ServiceName,
        [Parameter(Mandatory)] [string]  $IndexName,
        [Parameter(Mandatory)] [string]  $ApiKey
    )
    $url = "https://$ServiceName.search.windows.net/indexes/$IndexName/docs/search?api-version=2024-07-01"
    $headers = @{
        "api-key"      = $ApiKey
        "Content-Type" = "application/json"
    }
    $bodyObj = @{
        search = "*"
        count  = $true
        filter = "StartIPInt le $IpInt and EndIPInt ge $IpInt"
        top    = 10
    }
    $body = $bodyObj | ConvertTo-Json -Depth 6
    try {
        $resp = Invoke-RestMethod -Method Post -Uri $url -Headers $headers -Body $body
    } catch {
        $raw = $null
        try {
            if ($_.Exception.Response -and $_.Exception.Response.GetResponseStream()) {
                $reader = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
                $raw = $reader.ReadToEnd()
                $reader.Close()
            }
        } catch {}
        throw ("Azure Search request failed. URL: {0}. Body: {1}. SearchError: {2}" -f $url, $body, ($raw ?? $_.Exception.Message))
    }
    if (-not $resp.value -or $resp.value.Count -eq 0) {
        return $null
    }
    # Most specific range = smallest span
    $best = $resp.value |
        ForEach-Object {
            $_ | Add-Member -NotePropertyName range_size -NotePropertyValue ([int64]($_.EndIPInt) - [int64]($_.StartIPInt)) -PassThru
        } |
        Sort-Object range_size, StartIPInt |
        Select-Object -First 1
    return $best
}

function Get-PciScopeCategory {
    param([string]$SrcZone, [string]$DstZone)
    $s = (($SrcZone ?? "")).ToUpper()
    $d = (($DstZone ?? "")).ToUpper()
    if ($s -eq "CDE" -or $d -eq "CDE") { return "CDE_SCOPE" }
    if ($s -eq "CSE" -or $d -eq "CSE") { return "CSE_CONNECTED" }
    return "OUT_OF_SCOPE"
}

function Get-PciImpact {
    param([string]$SrcZone, [string]$DstZone, [string]$PciScopeCategory)
    $s = (($SrcZone ?? "")).ToUpper()
    $d = (($DstZone ?? "")).ToUpper()
    if ( ($s -eq "CDE" -and $d -eq "EXTERNAL") -or ($d -eq "CDE" -and $s -eq "EXTERNAL") ) {
        return "Disallowed: Direct flow between CDE and External is not permitted"
    }
    switch ($PciScopeCategory) {
        "CDE_SCOPE"     { return "Touches CDE (PCI scope likely)" }
        "CSE_CONNECTED" { return "Touches CSE (connected-to-scope); controls required" }
        default         { return "No CDE/CSE segments detected" }
    }
}

# --------- JSON/runtime normalization helpers ----------
function Normalize-BodyValue {
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    if ($Value.GetType().FullName -eq "System.Text.Json.JsonElement") {
        try {
            $vk = $Value.ValueKind.ToString()
            switch ($vk) {
                "String" { return $Value.GetString() }
                "Number" { return $Value.ToString() }
                "True"   { return "true" }
                "False"  { return "false" }
                "Null"   { return $null }
                "Array"  {
                    $arr = @()
                    foreach ($item in $Value.EnumerateArray()) { $arr += (Normalize-BodyValue -Value $item) }
                    return $arr
                }
                default  { return $Value.ToString() }
            }
        } catch { return $Value.ToString() }
    }
    if (($Value -is [System.Collections.IEnumerable]) -and -not ($Value -is [string]) -and -not ($Value -is [hashtable])) {
        $arr = @()
        foreach ($item in $Value) {
            if ($null -ne $item) { $arr += $item }
        }
        return $arr
    }
    return $Value
}

function Get-BodyField {
    param(
        [Parameter(Mandatory)] $Body,
        [Parameter(Mandatory)] [string] $Name
    )
    if ($null -eq $Body) { return $null }
    if ($Body -is [hashtable]) {
        if ($Body.ContainsKey($Name)) { return (Normalize-BodyValue -Value $Body[$Name]) }
        foreach ($k in $Body.Keys) {
            if ($k -and $k.ToString().Equals($Name, [System.StringComparison]::OrdinalIgnoreCase)) {
                return (Normalize-BodyValue -Value $Body[$k])
            }
        }
        return $null
    }
    try { return (Normalize-BodyValue -Value $Body.$Name) } catch { return $null }
}

function Parse-EndpointList {
    param([object]$EndpointText)
    if ($null -eq $EndpointText) { return @() }
    $EndpointText = Normalize-BodyValue -Value $EndpointText
    $tokens = @()
    if ($EndpointText -is [string]) {
        $tokens += $EndpointText
    }
    elseif (($EndpointText -is [System.Collections.IEnumerable]) -and -not ($EndpointText -is [string]) -and -not ($EndpointText -is [hashtable])) {
        foreach ($item in $EndpointText) {
            if ($null -eq $item) { continue }
            $tokens += ([string]$item)
        }
    }
    else {
        $tokens += ([string]$EndpointText)
    }
    $out = @()
    foreach ($t in $tokens) {
        $s = ([string]$t).Trim()
        if ([string]::IsNullOrWhiteSpace($s)) { continue }
        $out += @(
            ($s -split ",") |
                ForEach-Object { $_.Trim() } |
                Where-Object { $_ -ne "" }
        )
    }
    return @($out)
}

function Parse-PortSpec {
    param([object]$PortText)
    $notes = @()
    $t = ((Normalize-BodyValue -Value $PortText) -as [string])
    if ($null -eq $t) { $t = ([string]$PortText) }
    $t = ($t ?? "").Trim()
    if ([string]::IsNullOrWhiteSpace($t) -or $t -match '^(?i:any|\*)$') {
        return @{ valid=$true; any=$true; ports=@(); ranges=@(); notes=@() }
    }
    $ports = New-Object System.Collections.Generic.List[int]
    $ranges = @()
    $valid = $true
    foreach ($tokenRaw in ($t -split ",")) {
        $token = $tokenRaw.Trim()
        if (-not $token) { continue }
        if ($token -match '^\d+$') {
            $p = [int]$token
            if ($p -lt 0 -or $p -gt 65535) { $valid=$false; $notes += "Invalid port out of range: '$token'"; continue }
            $ports.Add($p); continue
        }
        if ($token -match '^(\d+)\s*-\s*(\d+)$') {
            $a = [int]$matches[1]
            $b = [int]$matches[2]
            if ($a -lt 0 -or $a -gt 65535 -or $b -lt 0 -or $b -gt 65535 -or $a -gt $b) {
                $valid=$false; $notes += "Invalid port range: '$token'"; continue
            }
            $ranges += @{ start=$a; end=$b }; continue
        }
        $valid=$false
        $notes += "Invalid token: '$token'"
    }
    $uniquePorts = @($ports | Sort-Object -Unique)
    return @{ valid=$valid; any=$false; ports=$uniquePorts; ranges=$ranges; notes=$notes }
}

function Get-ProtocolSensitivity {
    param([object]$Protocol)
    $p = ((Normalize-BodyValue -Value $Protocol) -as [string])
    if ($null -eq $p) { $p = ([string]$Protocol) }
    $p = ($p ?? "").Trim().ToUpper()
    if ($p -eq "UDP" -or $p -eq "BOTH") { return "ELEVATED" }
    if ($p -eq "TCP") { return "NORMAL" }
    return "UNKNOWN"
}

function Get-FlowBoundaryAndRisk {
    param([string]$SrcZone, [string]$DstZone)
    $s = (($SrcZone ?? "")).ToUpper()
    $d = (($DstZone ?? "")).ToUpper()
    if ($s -eq "CDE" -and $d -ne "CDE") { return @{ flowBoundary="FROM_CDE"; directionRisk="HIGH" } }
    if ($d -eq "CDE" -and $s -ne "CDE") { return @{ flowBoundary="TO_CDE"; directionRisk="HIGH" } }
    if ($s -eq "CSE" -and $d -ne "CSE") { return @{ flowBoundary="FROM_CSE"; directionRisk="MEDIUM" } }
    if ($d -eq "CSE" -and $s -ne "CSE") { return @{ flowBoundary="TO_CSE"; directionRisk="MEDIUM" } }
    if ($s -eq $d) { return @{ flowBoundary="INTRA_ZONE"; directionRisk="LOW" } }
    if ($s -eq "EXTERNAL" -and $d -ne "EXTERNAL") { return @{ flowBoundary="EXTERNAL_TO_INTERNAL"; directionRisk="HIGH" } }
    if ($d -eq "EXTERNAL" -and $s -ne "EXTERNAL") { return @{ flowBoundary="INTERNAL_TO_EXTERNAL"; directionRisk="MEDIUM" } }
    return @{ flowBoundary="INTER_ZONE"; directionRisk="MEDIUM" }
}

function Get-PortRisk {
    param(
        [hashtable]$DstPortsParsed,
        [string]$PciScopeCategory
    )
    $reasons = @()
    if (-not $DstPortsParsed.valid) {
        return @{ portRiskLevel="UNKNOWN"; portRiskReasons=@("Destination port string could not be parsed deterministically.") }
    }
    if ($DstPortsParsed.any -eq $true) {
        $reasons += "Destination ports are 'Any' which increases exposure and review complexity."
        return @{ portRiskLevel="UNKNOWN"; portRiskReasons=$reasons }
    }
    $expanded = New-Object System.Collections.Generic.List[int]
    foreach ($p in $DstPortsParsed.ports) { $expanded.Add([int]$p) }
    foreach ($r in $DstPortsParsed.ranges) {
        $span = [int]$r.end - [int]$r.start
        if ($span -gt 2000) {
            $reasons += "Large destination port range ($($r.start)-$($r.end)) not fully expanded for risk evaluation."
            continue
        }
        for ($i = [int]$r.start; $i -le [int]$r.end; $i++) { $expanded.Add($i) }
    }
    $unique = @($expanded | Sort-Object -Unique)
    $highHits = @($unique | Where-Object { $Script:HighRiskPorts -contains $_ })
    if ($highHits.Count -gt 0) {
        $reasons += "High-risk destination ports detected: $($highHits -join ', ')."
        if (($PciScopeCategory ?? "") -eq "CDE_SCOPE") { $reasons += "High-risk ports to/from CDE require strict justification and controls." }
        return @{ portRiskLevel="HIGH"; portRiskReasons=$reasons }
    }
    $medHits = @($unique | Where-Object { $Script:MediumRiskPorts -contains $_ })
    if ($medHits.Count -gt 0) {
        $reasons += "Medium-risk destination ports detected: $($medHits -join ', ')."
        if (($PciScopeCategory ?? "") -eq "CDE_SCOPE") { $reasons += "Database/service ports involving CDE often require additional review and monitoring." }
        return @{ portRiskLevel="MEDIUM"; portRiskReasons=$reasons }
    }
    if (@($unique | Where-Object { $_ -in @(80,443) }).Count -gt 0 -and (($PciScopeCategory ?? "") -eq "CDE_SCOPE")) {
        $reasons += "Web ports (80/443) involving CDE: ensure inspection/logging and least privilege."
        return @{ portRiskLevel="MEDIUM"; portRiskReasons=$reasons }
    }
    return @{ portRiskLevel="LOW"; portRiskReasons=@("No high/medium-risk destination ports detected.") }
}

function Evaluate-FirewallFlow {
    param(
        [Parameter(Mandatory)] [string]$SrcInput,
        [Parameter(Mandatory)] [string]$DstInput,
        [object]$Protocol,
        [object]$SrcPort,
        [object]$DstPort,
        [object]$Context,
        [Parameter(Mandatory)] [string]$ServiceName,
        [Parameter(Mandatory)] [string]$IndexName,
        [Parameter(Mandatory)] [string]$ApiKey
    )

    # Use quiet failure mode to capture DNS errors without throwing
    $srcRes = Resolve-IpOrHostToIpv4 -InputValue $SrcInput -SideLabel "src" -QuietFailure
    $dstRes = Resolve-IpOrHostToIpv4 -InputValue $DstInput -SideLabel "dst" -QuietFailure

    # Check for resolution failures
    $resolutionFailures = @()
    if (-not $srcRes.success) {
        $resolutionFailures += @{
            side   = "source"
            input  = $SrcInput
            error  = $srcRes.resolution.error
            type   = $srcRes.resolution.type
            tried  = $srcRes.resolution.tried
        }
    }
    if (-not $dstRes.success) {
        $resolutionFailures += @{
            side   = "destination"
            input  = $DstInput
            error  = $dstRes.resolution.error
            type   = $dstRes.resolution.type
            tried  = $dstRes.resolution.tried
        }
    }

    # If either side failed to resolve, return a structured failure response
    if ($resolutionFailures.Count -gt 0) {
        return @{
            scriptVersion       = $Script:ScriptVersion
            srcInput            = $SrcInput
            dstInput            = $DstInput
            resolutionSuccess   = $false
            resolutionFailures  = $resolutionFailures
            srcResolution       = $srcRes.resolution
            dstResolution       = $dstRes.resolution
            protocol            = ([string](Normalize-BodyValue -Value $Protocol))
            srcPort             = ([string](Normalize-BodyValue -Value $SrcPort))
            dstPort             = ([string](Normalize-BodyValue -Value $DstPort))
            context             = ([string](Normalize-BodyValue -Value $Context))
            # Indicate this flow could not be evaluated
            evaluationStatus    = "FAILED"
            evaluationError     = "Unable to resolve one or more endpoints. See resolutionFailures for details."
            # Null out fields that require successful resolution
            srcResolvedIp       = $null
            dstResolvedIp       = $null
            srcIp               = $null
            dstIp               = $null
            src                 = $null
            dst                 = $null
            pciScopeCategory    = $null
            pciImpact           = $null
            hardBlock           = $null
            hardBlockReason     = $null
            flowBoundary        = $null
            directionRisk       = $null
            protocolSensitivity = $null
            portsParsed         = $null
            portRiskLevel       = $null
            portRiskReasons     = $null
            notes               = "Resolution failed for: " + (($resolutionFailures | ForEach-Object { "$($_.side) ('$($_.input)')" }) -join ", ")
        }
    }

    # Both resolved successfully
    $srcResolvedIp = $srcRes.resolvedIp
    $dstResolvedIp = $dstRes.resolvedIp

    $srcInt = Convert-IpV4ToInt64 -Ip $srcResolvedIp
    $dstInt = Convert-IpV4ToInt64 -Ip $dstResolvedIp

    $srcBest = Invoke-SearchByIpInt -IpInt $srcInt -ServiceName $ServiceName -IndexName $IndexName -ApiKey $ApiKey
    $dstBest = Invoke-SearchByIpInt -IpInt $dstInt -ServiceName $ServiceName -IndexName $IndexName -ApiKey $ApiKey

    # Zone mapping: use cde_cse_p2pe first, then fallback
    $srcZone = if ($srcBest) { Get-ZoneFromDoc -doc $srcBest } else { $null }
    $dstZone = if ($dstBest) { Get-ZoneFromDoc -doc $dstBest } else { $null }
    if ([string]::IsNullOrWhiteSpace([string]$srcZone)) { $srcZone = Get-IpRfc1918Class -Ip $srcResolvedIp }
    if ([string]::IsNullOrWhiteSpace([string]$dstZone)) { $dstZone = Get-IpRfc1918Class -Ip $dstResolvedIp }

    # Build src/dst objects for UI
    $srcObj = if ($srcBest) {
        @{
            segment_name = ($srcBest.subnets ?? $srcBest.ip ?? $null)
            cidr         = ($srcBest.CIDR ?? $null)
            zone         = $srcZone
            location     = ($srcBest.location ?? $null)
        }
    } else {
        @{ segment_name=$null; cidr=$null; zone=$srcZone; location=$null }
    }
    $dstObj = if ($dstBest) {
        @{
            segment_name = ($dstBest.subnets ?? $dstBest.ip ?? $null)
            cidr         = ($dstBest.CIDR ?? $null)
            zone         = $dstZone
            location     = ($dstBest.location ?? $null)
        }
    } else {
        @{ segment_name=$null; cidr=$null; zone=$dstZone; location=$null }
    }

    $pciScopeCategory = Get-PciScopeCategory -SrcZone $srcZone -DstZone $dstZone
    $pciImpact        = Get-PciImpact -SrcZone $srcZone -DstZone $dstZone -PciScopeCategory $pciScopeCategory

    $srcZoneU = (($srcZone ?? "")).ToUpper()
    $dstZoneU = (($dstZone ?? "")).ToUpper()
    $hardBlock = $false
    $hardBlockReason = $null
    if ( ($srcZoneU -eq "CDE" -and $dstZoneU -eq "EXTERNAL") -or ($dstZoneU -eq "CDE" -and $srcZoneU -eq "EXTERNAL") ) {
        $hardBlock = $true
        $hardBlockReason = "External ↔ CDE is not permitted"
    }

    $boundary = Get-FlowBoundaryAndRisk -SrcZone $srcZone -DstZone $dstZone
    $protocolSensitivity = Get-ProtocolSensitivity -Protocol $Protocol
    $srcPortsParsed = Parse-PortSpec -PortText $SrcPort
    $dstPortsParsed = Parse-PortSpec -PortText $DstPort
    $portRisk = Get-PortRisk -DstPortsParsed $dstPortsParsed -PciScopeCategory $pciScopeCategory

    $notesParts = @()
    if ($srcZone -ne $dstZone) { $notesParts += "Cross-zone flow: $srcZone -> $dstZone." }
    if ($pciScopeCategory -eq "CDE_SCOPE") { $notesParts += "Flow includes a CDE network segment." }
    elseif ($pciScopeCategory -eq "CSE_CONNECTED") { $notesParts += "Flow includes a network connected to PCI scope." }
    else { $notesParts += "Flow involves only networks not explicitly tagged as CDE or CSE." }
    if ($hardBlock) { $notesParts += "Per policy, direct connectivity between CDE and External networks must be denied." }
    if (-not $srcPortsParsed.valid -or -not $dstPortsParsed.valid) {
        $notesParts += "Port parsing detected invalid tokens; review port strings for deterministic evaluation."
    }

    # Add note if CIDR was used
    if ($srcRes.resolution.type -eq "CIDR_SUBNET") {
        $notesParts += "Source was CIDR subnet ($SrcInput); using network start IP ($srcResolvedIp) for lookup."
    }
    if ($dstRes.resolution.type -eq "CIDR_SUBNET") {
        $notesParts += "Destination was CIDR subnet ($DstInput); using network start IP ($dstResolvedIp) for lookup."
    }

    return @{
        scriptVersion       = $Script:ScriptVersion
        srcInput            = $SrcInput
        dstInput            = $DstInput
        srcResolvedIp       = $srcResolvedIp
        dstResolvedIp       = $dstResolvedIp
        resolutionSuccess   = $true
        evaluationStatus    = "SUCCESS"
        # Backward compat for existing UI
        srcIp               = $srcResolvedIp
        dstIp               = $dstResolvedIp
        protocol            = ([string](Normalize-BodyValue -Value $Protocol))
        srcPort             = ([string](Normalize-BodyValue -Value $SrcPort))
        dstPort             = ([string](Normalize-BodyValue -Value $DstPort))
        context             = ([string](Normalize-BodyValue -Value $Context))
        src                 = $srcObj
        dst                 = $dstObj
        pciScopeCategory    = $pciScopeCategory
        pciImpact           = $pciImpact
        hardBlock           = $hardBlock
        hardBlockReason     = $hardBlockReason
        flowBoundary        = $boundary.flowBoundary
        directionRisk       = $boundary.directionRisk
        protocolSensitivity = $protocolSensitivity
        portsParsed = @{
            src = $srcPortsParsed
            dst = $dstPortsParsed
        }
        portRiskLevel       = $portRisk.portRiskLevel
        portRiskReasons     = $portRisk.portRiskReasons
        notes               = (($notesParts -join " ").Trim())
        # For rollout debugging
        srcResolution       = $srcRes.resolution
        dstResolution       = $dstRes.resolution
    }
}

########## Main ##########
# Diagnostics
$rawBody = $Request.Body
$rawBodyType = if ($null -eq $rawBody) { "null" } else { $rawBody.GetType().FullName }
$rawBodyLength = 0
try {
    if ($rawBody -is [string]) { $rawBodyLength = $rawBody.Length }
    else { $rawBodyLength = ($rawBody | ConvertTo-Json -Depth 6).Length }
} catch { $rawBodyLength = -1 }

$body = $Request.Body
if ($body -is [string]) {
    try { $body = $body | ConvertFrom-Json }
    catch {
        $err = @{
            scriptVersion = $Script:ScriptVersion
            error   = "Invalid JSON body"
            debug = @{
                method = $Request.Method
                contentType = ($Request.Headers["Content-Type"] ?? $Request.Headers["content-type"])
                rawBodyType = $rawBodyType
                rawBodyLength = $rawBodyLength
            }
        }
        Push-OutputBinding -Name Response -Value @{
            StatusCode = 400
            Headers    = @{ "Content-Type"="application/json" }
            Body       = ($err | ConvertTo-Json -Depth 10)
        }
        return
    }
}

if (-not $body) {
    Push-OutputBinding -Name Response -Value @{
        StatusCode = 400
        Headers    = @{ "Content-Type"="application/json" }
        Body       = (@{
            scriptVersion = $Script:ScriptVersion
            error="Missing body"
            debug = @{
                method = $Request.Method
                contentType = ($Request.Headers["Content-Type"] ?? $Request.Headers["content-type"])
                rawBodyType = $rawBodyType
                rawBodyLength = $rawBodyLength
            }
        } | ConvertTo-Json -Depth 10)
    }
    return
}

$srcInputRaw = Get-BodyField -Body $body -Name "srcIp"
$dstInputRaw = Get-BodyField -Body $body -Name "dstIp"
$protocol    = Get-BodyField -Body $body -Name "protocol"
$srcPort     = Get-BodyField -Body $body -Name "srcPort"
$dstPort     = Get-BodyField -Body $body -Name "dstPort"
$context     = Get-BodyField -Body $body -Name "context"

$serviceName = $env:SEARCH_SERVICE_NAME
$indexName   = $env:SEARCH_INDEX_NAME
$apiKey      = $env:SEARCH_API_KEY

if (-not $serviceName -or -not $indexName -or -not $apiKey) {
    Push-OutputBinding -Name Response -Value @{
        StatusCode = 500
        Headers    = @{ "Content-Type"="application/json" }
        Body       = (@{
            scriptVersion = $Script:ScriptVersion
            error="Missing app settings. Require SEARCH_SERVICE_NAME, SEARCH_INDEX_NAME, SEARCH_API_KEY."
        } | ConvertTo-Json -Depth 6)
    }
    return
}

$srcList = Parse-EndpointList -EndpointText $srcInputRaw
$dstList = Parse-EndpointList -EndpointText $dstInputRaw

if ($srcList.Count -eq 0 -or $dstList.Count -eq 0) {
    $err = @{
        scriptVersion = $Script:ScriptVersion
        error = "Both 'srcIp' and 'dstIp' must contain at least one IP, hostname, or CIDR subnet."
        debug = @{
            method = $Request.Method
            contentType = ($Request.Headers["Content-Type"] ?? $Request.Headers["content-type"])
            rawBodyType = $rawBodyType
            rawBodyLength = $rawBodyLength
            parsedBodyType = $body.GetType().FullName
            srcIpValue = $srcInputRaw
            dstIpValue = $dstInputRaw
            srcList = $srcList
            dstList = $dstList
        }
    }
    Push-OutputBinding -Name Response -Value @{
        StatusCode = 400
        Headers    = @{ "Content-Type"="application/json" }
        Body       = ($err | ConvertTo-Json -Depth 12)
    }
    return
}

$flows = @()
foreach ($s in $srcList) {
    foreach ($d in $dstList) {
        $flows += @{ src = [string]$s; dst = [string]$d }
    }
}

if ($flows.Count -gt $Script:MaxFlowCombinations) {
    $err = @{
        scriptVersion = $Script:ScriptVersion
        error = "Too many flow combinations ($($flows.Count)). Limit is $($Script:MaxFlowCombinations). Reduce the number of comma-separated entries."
        hint  = "Example: 5 sources x 5 destinations = 25 flows (max)."
    }
    Push-OutputBinding -Name Response -Value @{
        StatusCode = 400
        Headers    = @{ "Content-Type"="application/json" }
        Body       = ($err | ConvertTo-Json -Depth 6)
    }
    return
}

# Process all flows - no longer throws on DNS failures
$results = @()
foreach ($f in $flows) {
    $results += Evaluate-FirewallFlow `
        -SrcInput ([string]$f.src) `
        -DstInput ([string]$f.dst) `
        -Protocol $protocol `
        -SrcPort $srcPort `
        -DstPort $dstPort `
        -Context $context `
        -ServiceName $serviceName `
        -IndexName $indexName `
        -ApiKey $apiKey
}

# Separate successful and failed evaluations
$successfulResults = @($results | Where-Object { $_.evaluationStatus -eq "SUCCESS" })
$failedResults = @($results | Where-Object { $_.evaluationStatus -eq "FAILED" })

# Aggregate info
$severityOrder = @{ "OUT_OF_SCOPE"=1; "CSE_CONNECTED"=2; "CDE_SCOPE"=3 }
$highest = $successfulResults |
    Sort-Object @{ Expression = { $severityOrder[$_.pciScopeCategory] }; Descending = $true } |
    Select-Object -First 1

$hardBlocksDetected = @($successfulResults | Where-Object { $_.hardBlock -eq $true }).Count -gt 0
$hasResolutionFailures = $failedResults.Count -gt 0

if ($results.Count -eq 1) {
    $single = $results[0]
    $single.flowCount = 1
    $single.results = @($single)
    $single.aggregate = @{
        highestScope         = $single.pciScopeCategory
        hardBlocksDetected   = $single.hardBlock
        resolutionFailures   = if ($single.evaluationStatus -eq "FAILED") { 1 } else { 0 }
        successfulEvaluations = if ($single.evaluationStatus -eq "SUCCESS") { 1 } else { 0 }
        summary              = if ($single.evaluationStatus -eq "FAILED") {
            "Resolution failed: $($single.evaluationError)"
        } elseif ($single.hardBlock) {
            "Hard block detected: $($single.hardBlockReason)"
        } else {
            "Single flow evaluated."
        }
    }
    $single.inputSummary = @{
        sources      = $srcList
        destinations = $dstList
        protocol     = ([string](Normalize-BodyValue -Value $protocol))
        srcPort      = ([string](Normalize-BodyValue -Value $srcPort))
        dstPort      = ([string](Normalize-BodyValue -Value $dstPort))
        context      = ([string](Normalize-BodyValue -Value $context))
    }
    Push-OutputBinding -Name Response -Value @{
        StatusCode = 200
        Headers    = @{ "Content-Type" = "application/json" }
        Body       = ($single | ConvertTo-Json -Depth 14)
    }
    return
}

# Multiple flows
$aggregateSummary = "Evaluated $($results.Count) flows."
if ($successfulResults.Count -gt 0 -and $highest) {
    $aggregateSummary += " Highest PCI scope: $($highest.pciScopeCategory)."
}
if ($hardBlocksDetected) {
    $aggregateSummary += " One or more flows are disallowed (hard block)."
}
if ($hasResolutionFailures) {
    $aggregateSummary += " $($failedResults.Count) flow(s) failed DNS resolution."
}

$batchResp = @{
    scriptVersion = $Script:ScriptVersion
    inputSummary = @{
        sources      = $srcList
        destinations = $dstList
        protocol     = ([string](Normalize-BodyValue -Value $protocol))
        srcPort      = ([string](Normalize-BodyValue -Value $srcPort))
        dstPort      = ([string](Normalize-BodyValue -Value $dstPort))
        context      = ([string](Normalize-BodyValue -Value $context))
    }
    flowCount = $results.Count
    results   = $results
    aggregate = @{
        highestScope          = if ($highest) { $highest.pciScopeCategory } else { $null }
        hardBlocksDetected    = $hardBlocksDetected
        resolutionFailures    = $failedResults.Count
        successfulEvaluations = $successfulResults.Count
        summary               = $aggregateSummary
    }
}

Push-OutputBinding -Name Response -Value @{
    StatusCode = 200
    Headers    = @{ "Content-Type" = "application/json" }
    Body       = ($batchResp | ConvertTo-Json -Depth 14)
}
