<# =====================================================================
   Check Point Infinity Portal — MSP Integration (PowerShell 5/7)
   - Auth via /auth/external → caches bearer token
   - /api/v1/tenant/usageReport (JSON or CSV URL in `res`)
   - Account discovery uses Customer/User Center ID/Contract ID (no usage required)
   - Usage mapping aggregates per tenant+service (requires usage > 0)
   - Services: returns exactly ONE service → "Email & Collaboration"
     * Category    = "other"            (allowed by ValidateSet)
     * Subcategory = "email security"   (allowed by ValidateSet)

   Exposed functions:
     - Invoke-Authentication
     - Get-AuthHeaders
     - Get-OrganizationsRawData
     - Get-MappedOrganizations
     - Get-VendorServices
     - Get-OrganizationsUsage

   Env vars: API_URL, CLIENT_ID, ACCESS_KEY (or SECRET_KEY), TENANT_ID
   Optional debug: $Env:CP_DEBUG = 1
===================================================================== #>

# --------------------------
# Script-scoped token cache
# --------------------------
Set-Variable -Name CheckpointBearerToken -Scope Script -Value $null

# ---------------
# Debug helper
# ---------------
function Write-CPDebug {
    param([string]$Msg)
    if ($Env:CP_DEBUG -and $Env:CP_DEBUG -ne '0') {
        Write-Host "[CPDEBUG] $Msg" -ForegroundColor DarkCyan
    }
}

# ---------------
# Utils / Helpers
# ---------------
function Normalize-Blank {
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    $s = $Value.ToString().Trim().Trim('"', "'")
    if ($s.Length -eq 0) { return $null }
    if ($s -match '^(?i:NULL|NONE|N/?A|-)$') { return $null }
    return $s
}

function New-DeterministicGuidFromString {
    param([Parameter(Mandatory)][string]$Text)
    $md5 = [System.Security.Cryptography.MD5]::Create()
    try {
        $bytes = [Text.Encoding]::UTF8.GetBytes($Text.ToLowerInvariant())
        $hash  = $md5.ComputeHash($bytes)   # 16 bytes
        return (New-Object System.Guid -ArgumentList (,[byte[]]$hash))  # PS5-safe single argument
    } finally { $md5.Dispose() }
}

function Convert-FromBase64Url {
    param([Parameter(Mandatory)][string]$Value)
    $p = $Value.Replace('-', '+').Replace('_', '/')
    switch ($p.Length % 4) { 2 { $p += '==' } 3 { $p += '=' } 0 { } default { } }
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($p))
}
function Get-JwtPayload {
    param([Parameter(Mandatory)][string]$Jwt)
    try {
        $parts = $Jwt.Split('.')
        if ($parts.Length -lt 2) { return $null }
        (Convert-FromBase64Url $parts[1]) | ConvertFrom-Json
    } catch { $null }
}
function Test-TokenValid {
    param([string]$Token, [int]$SkewSeconds = 300)
    if ([string]::IsNullOrWhiteSpace($Token)) { return $false }
    $pl = Get-JwtPayload $Token
    if (-not $pl -or -not $pl.exp) { return $false }
    $now = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
    return ($pl.exp - $now -gt $SkewSeconds)
}
function Get-CheckpointToken { (Get-Variable -Name CheckpointBearerToken -Scope Script -ValueOnly) }

# ---------------------
# Authentication (auth)
# ---------------------
function Invoke-Authentication {
    $base = $Env:API_URL
    if ([string]::IsNullOrWhiteSpace($base)) { throw "API_URL env var is required." }
    $base = $base.TrimEnd('/')

    if ([string]::IsNullOrWhiteSpace($Env:CLIENT_ID) -or `
        ([string]::IsNullOrWhiteSpace($Env:ACCESS_KEY) -and [string]::IsNullOrWhiteSpace($Env:SECRET_KEY))) {
        throw "CLIENT_ID and ACCESS_KEY (or SECRET_KEY) env vars are required."
    }

    $ak = if ($Env:ACCESS_KEY) { $Env:ACCESS_KEY.Trim() } else { $Env:SECRET_KEY.Trim() }
    $body = @{ clientId = $Env:CLIENT_ID.Trim(); accessKey = $ak } | ConvertTo-Json

    try {
        $resp = Invoke-RestMethod -Method POST -Uri "$base/auth/external" -Headers @{
            Accept='application/json'; 'Content-Type'='application/json'
        } -Body $body

        $token = if ($resp -is [string]) { $resp }
                 elseif ($resp.token) { $resp.token }
                 elseif ($resp.data -and $resp.data.token) { $resp.data.token }
                 else { $null }

        if (-not $token) { throw "Auth succeeded but no token field found. Raw: $($resp | ConvertTo-Json -Depth 6)" }

        Set-Variable -Name CheckpointBearerToken -Scope Script -Value ([string]$token)

        # Auto-fill TENANT_ID from JWT if missing
        try {
            $pl = Get-JwtPayload $token
            if ($pl -and -not $Env:TENANT_ID) {
                if ($pl.accountId) { $Env:TENANT_ID = $pl.accountId }
                elseif ($pl.tenantId) { $Env:TENANT_ID = $pl.tenantId }
            }
        } catch {}

        $len = (Get-CheckpointToken).Length
        Write-Host ("Authenticated. Token length: {0}" -f $len) -ForegroundColor Green
    }
    catch {
        $msg = $_.Exception.Message
        try {
            $rs = $_.Exception.Response.GetResponseStream()
            if ($rs) { $reader = New-Object IO.StreamReader($rs); $apiErr = $reader.ReadToEnd(); if ($apiErr) { $msg += "`nAPI Error: $apiErr" } }
        } catch {}
        Write-Error "Authentication failed. Details: $msg"
        throw
    }
}

# -----------------------------
# Authorization header provider
# -----------------------------
function Get-AuthHeaders {
    if (-not (Test-TokenValid (Get-CheckpointToken))) {
        Invoke-Authentication
        if (-not (Test-TokenValid (Get-CheckpointToken))) { throw "Failed to obtain a valid bearer token." }
    }
    @{
        "Authorization" = "Bearer $(Get-CheckpointToken)"
        "Accept"        = "application/json"
        "Content-Type"  = "application/json"
    }
}

# -----------------------------
# Int parser (null-safe)
# -----------------------------
function Convert-ToIntSafe {
    param([object]$Value)
    if ($null -eq $Value) { return $null }
    $s = $Value.ToString().Trim()
    if ($s.Length -eq 0) { return $null }
    $s = ($s -replace '[^\d\-]', '')
    $tmp = 0
    if ([int]::TryParse($s, [ref]$tmp)) { return $tmp }
    return $null
}

# ------------------------------------------
# Header resolver for your CSV column names
# ------------------------------------------
function Resolve-UsageHeaderMap {
    param([Parameter(Mandatory)][object]$SampleRow)

    $names = $SampleRow.PSObject.Properties.Name
    function FindFirst([string[]]$cands) {
        foreach ($c in $cands) {
            $hit = $names | Where-Object { $_ -ieq $c } | Select-Object -First 1
            if ($hit) { return $hit }
        }
        return $null
    }

    # IDs / Names (prefer child/customer side)
    $tenantIdCol     = FindFirst @('User Center ID','Customer Id','Child Account Id','Child Tenant Id','Tenant Id','Account Id','Id')
    $tenantNameCol   = FindFirst @('Customer','MSP','Master MSP','Tenant Name','Account Name','Name')
    $contractIdCol   = FindFirst @('Contract ID','ContractId')

    # Product/Service
    $productCol      = FindFirst @('Service Name','Package(SKU)','Product Name','Package Name','Service','Product','Package')

    # Usage columns
    $dailyUnitsCol   = FindFirst @('Daily usage count','Daily Usage Count','Daily Count')
    $subsCountCol    = FindFirst @('Subscriptions count','Subscriptions Count','Subscriptions')
    $paygCountCol    = FindFirst @('Pay-As-You-Go count','Pay As You Go count','Pay-As-You-Go Count','PAYG Count','PAYG')

    Write-CPDebug ("Cols → Id:`"$tenantIdCol`" | Name:`"$tenantNameCol`" | Product:`"$productCol`" | Units:`"$dailyUnitsCol/$subsCountCol+$paygCountCol`" | Contract:`"$contractIdCol`"")

    [PSCustomObject]@{
        TenantId       = $tenantIdCol
        TenantName     = $tenantNameCol
        ContractId     = $contractIdCol
        ProductName    = $productCol
        DailyUnitsCol  = $dailyUnitsCol
        SubsCountCol   = $subsCountCol
        PaygCountCol   = $paygCountCol
    }
}

# ----------------------------------------------------
# Normalize rows (supports account discovery w/o units)
# ----------------------------------------------------
function Normalize-UsageRows {
    param(
        [Parameter()][object[]]$Raw = @(),
        [Parameter(Mandatory)][bool]$Summarized,
        [Parameter()][bool]$RequireUnits = $true
    )
    if ($null -eq $Raw -or $Raw.Count -eq 0) { return @() }

    $hdr = Resolve-UsageHeaderMap -SampleRow $Raw[0]
    $out = New-Object System.Collections.ArrayList

    foreach ($r in $Raw) {
        # id + name (+ contractId)
        $tid   = $null
        $tname = $null
        $cid   = $null
        if ($hdr.TenantId)   { $tid   = Normalize-Blank $r.$($hdr.TenantId) }
        if ($hdr.TenantName) { $tname = Normalize-Blank $r.$($hdr.TenantName) }
        if ($hdr.ContractId) { $cid   = Normalize-Blank $r.$($hdr.ContractId) }
        if (-not $tid)   { $tid   = Normalize-Blank $r.tenantId }
        if (-not $tname) { $tname = Normalize-Blank $r.tenantName }

        # product
        $svc = $null
        if ($hdr.ProductName) { $svc = Normalize-Blank $r.$($hdr.ProductName) }
        if (-not $svc) { $svc = Normalize-Blank $r.productName }
        if ($Summarized -and -not $svc) { $svc = 'All Services' }

        # usage: Daily → (Subs + PayG) → usedUnits
        $units = $null
        if ($hdr.DailyUnitsCol) { $units = Convert-ToIntSafe ($r.$($hdr.DailyUnitsCol)) }
        if ($null -eq $units) {
            $subs = $null; $payg = $null
            if ($hdr.SubsCountCol) { $subs = Convert-ToIntSafe ($r.$($hdr.SubsCountCol)) }
            if ($hdr.PaygCountCol) { $payg = Convert-ToIntSafe ($r.$($hdr.PaygCountCol)) }
            if ($subs -ne $null -or $payg -ne $null) {
                if ($subs -eq $null) { $subs = 0 }
                if ($payg -eq $null) { $payg = 0 }
                $units = $subs + $payg
            }
        }
        if ($null -eq $units -and $r.PSObject.Properties.Name -contains 'usedUnits') {
            $units = Convert-ToIntSafe $r.usedUnits
        }

        if ($RequireUnits) {
            if ($tname -and $units -ne $null) {
                [void]$out.Add([PSCustomObject]@{
                    tenantId    = $tid
                    tenantName  = $tname
                    contractId  = $cid
                    productName = $svc
                    usedUnits   = [int]$units
                })
            }
        } else {
            if ($tname) {
                [void]$out.Add([PSCustomObject]@{
                    tenantId    = $tid
                    tenantName  = $tname
                    contractId  = $cid
                    productName = $svc
                    usedUnits   = ($units -ne $null) ? [int]$units : $null
                })
            }
        }
    }

    Write-CPDebug ("Normalized rows: {0}" -f $out.Count)
    return $out
}

# -------------------------------------------------------------
# Robust usageReport invoker (handles JSON + CSV 'res' link)
# -------------------------------------------------------------
function Invoke-UsageReport {
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][int]$Year,
        [Parameter(Mandatory)][bool]$Summarized,
        [Parameter()][bool]$RequireUnits = $true
    )

    $base    = $Env:API_URL.TrimEnd('/')
    $headers = Get-AuthHeaders

    function Parse-UsageResp($resp, [bool]$isSumm, [bool]$reqUnits) {
        if ($null -eq $resp) { return @() }

        if ($resp.responseData) { $raw = @($resp.responseData); return ($raw.Count) ? (Normalize-UsageRows -Raw $raw -Summarized:$isSumm -RequireUnits:$reqUnits) : @() }
        if ($resp.items)        { $raw = @($resp.items);        return ($raw.Count) ? (Normalize-UsageRows -Raw $raw -Summarized:$isSumm -RequireUnits:$reqUnits) : @() }
        if ($resp.report)       { $raw = @($resp.report);       return ($raw.Count) ? (Normalize-UsageRows -Raw $raw -Summarized:$isSumm -RequireUnits:$reqUnits) : @() }

        if ($resp.res -and ($resp.success -eq $true -or -not $resp.success)) {
            $csvUrl = $resp.res
            Write-CPDebug "Downloading CSV: $csvUrl"
            $csvText = $null
            try { $csvText = (Invoke-WebRequest -Uri $csvUrl -Method GET -UseBasicParsing).Content } catch {
                try { $csvText = Invoke-RestMethod -Method GET -Uri $csvUrl } catch {}
            }
            if ([string]::IsNullOrWhiteSpace($csvText)) { return @() }
            $csvRows = $csvText | ConvertFrom-Csv
            return ($csvRows) ? (Normalize-UsageRows -Raw @($csvRows) -Summarized:$isSumm -RequireUnits:$reqUnits) : @()
        }

        if ($resp -is [System.Collections.IEnumerable]) {
            $arr = @($resp)
            return ($arr.Count) ? (Normalize-UsageRows -Raw $arr -Summarized:$isSumm -RequireUnits:$reqUnits) : @()
        }

        if ($resp.success -eq $false -and $resp.message) { return @() }
        return @()
    }

    function Try-One($y, $mWire, [bool]$reqUnitsInner) {
        $tf = ($Summarized ? 'true' : 'false')
        $urls = @(
            "$base/api/v1/tenant/usageReport?tenantId=$TenantId&month=$mWire&year=$y&isSummarized=$tf",
            "$base/api/v1/tenant/usageReport?tenantId=$TenantId&month=$mWire&year=$y&isSummurized=$tf"
        )
        foreach ($u in $urls) {
            Write-CPDebug "Trying usageReport: $u"
            try {
                $resp = Invoke-RestMethod -Method GET -Uri $u -Headers $headers
                $rows = Parse-UsageResp $resp $Summarized $reqUnitsInner
                if ($rows -and $rows.Count -gt 0) { return $rows }
                if ($resp -and $resp.success -eq $false -and $resp.message -match 'Error generation usage report') { continue }
            } catch {
                $m = $_.Exception.Message
                if ($m -match 'Bad Request|500|generation usage report') { continue } else { throw }
            }
        }
        return @()
    }

    $now     = Get-Date
    $currMM  = $now.ToString('MM')
    $currMon = ([cultureinfo]::InvariantCulture.DateTimeFormat.GetMonthName($now.Month))
    $prev    = $now.AddMonths(-1)
    $prevMM  = $prev.ToString('MM')
    $prevMon = ([cultureinfo]::InvariantCulture.DateTimeFormat.GetMonthName($prev.Month))

    $cands = @(
        @{ y=$Year;      m=$currMM }, @{ y=$Year;      m=$currMon.ToUpperInvariant() }, @{ y=$Year;      m=$currMon },
        @{ y=$prev.Year; m=$prevMM }, @{ y=$prev.Year; m=$prevMon.ToUpperInvariant() }, @{ y=$prev.Year; m=$prevMon }
    )

    foreach ($c in $cands) {
        $rows = Try-One -y $c.y -mWire $c.m -reqUnitsInner:$RequireUnits
        if ($rows -and $rows.Count -gt 0) { return $rows }
    }

    return @()
}

# -----------------------------------------
# Organizations via usage report (discovery)
# -----------------------------------------
function Get-OrganizationsRawData {
    if ([string]::IsNullOrWhiteSpace($Env:TENANT_ID)) { throw "TENANT_ID env var is required." }
    $year = (Get-Date).Year

    # Detailed first; do NOT require units so zero-usage orgs still appear
    $rows = Invoke-UsageReport -TenantId $Env:TENANT_ID.Trim() -Year $year -Summarized:$false -RequireUnits:$false
    if (-not $rows -or $rows.Count -eq 0) {
        Write-CPDebug "Detailed returned no rows, trying summarized (no unit requirement)…"
        $rows = Invoke-UsageReport -TenantId $Env:TENANT_ID.Trim() -Year $year -Summarized:$true -RequireUnits:$false
    }
    if ($null -eq $rows) { $rows = @() }
    return $rows
}

function Get-ParentFromToken {
    $t = (Get-CheckpointToken)
    if ([string]::IsNullOrWhiteSpace($t)) { return $null }
    try {
        $pl = Get-JwtPayload $t
        if ($pl.accountId) { return @{ id = $pl.accountId; name = "Parent Account ($($pl.accountId))" } }
        if ($pl.tenantId)  { return @{ id = $pl.tenantId;  name = "Parent Tenant ($($pl.tenantId))" } }
    } catch {}
    return $null
}

function Get-MappedOrganizations {
    Write-Host "Fetching organizations..."

    try {
        $rows = Get-OrganizationsRawData
        $mappedOrgs = @{}

        if ($rows -and $rows.Count -gt 0) {
            # Group by best available key: real ID if present, else normalized name
            $groups = $rows | Group-Object -Property {
                $id = Normalize-Blank ($_.tenantId)
                if ($id) { "ID::$id" }
                else {
                    $nm = Normalize-Blank ($_.tenantName)
                    "NAME::" + ([string]$nm).ToLowerInvariant().Trim()
                }
            }

            foreach ($g in $groups) {
                $rep  = $g.Group | Select-Object -First 1
                $name = Normalize-Blank $rep.tenantName

                # choose best ID: any tenantId → any contractId → deterministic GUID from name
                $id = ($g.Group | ForEach-Object { Normalize-Blank $_.tenantId } | Where-Object { $_ } | Select-Object -First 1)
                if (-not $id) {
                    $id = ($g.Group | ForEach-Object { Normalize-Blank $_.contractId } | Where-Object { $_ } | Select-Object -First 1)
                }
                if (-not $id) {
                    $id = (New-DeterministicGuidFromString $name).ToString()
                }

                if ($name -and -not $mappedOrgs.ContainsKey($id)) {
                    $mappedOrgs[$id] = @{ id = "$id"; name = "$name" }
                }
            }
        }

        if ($mappedOrgs.Count -eq 0) {
            $parent = Get-ParentFromToken
            if ($parent) {
                $mappedOrgs[$parent.id] = $parent
                Write-Host "No usage rows; returning parent as fallback." -ForegroundColor Yellow
            }
        }

        [System.GC]::GetTotalMemory('forcefullcollection') | Out-Null
    }
    catch {
        Write-Host "An error occured while fetching organizations. Details: $_" -ForegroundColor Red
    }

    if ($mappedOrgs.Count -eq 0) {
        Write-Host "No valid organizations found." -ForegroundColor Yellow
        return @{}
    }

    Write-Host "$($mappedOrgs.Count) organizations mapped." -ForegroundColor Green
    return $mappedOrgs
}

# --------------------------
# Services (return ONE: Email & Collaboration)
# --------------------------
function Get-VendorServices {
    [CmdletBinding()] param()

    $base    = $Env:API_URL.TrimEnd('/')
    $headers = Get-AuthHeaders

    try {
        $resp = Invoke-RestMethod -Method GET -Uri "$base/api/v1/tenant/app/products" -Headers $headers
        $products = if ($resp.tenantAppsProducts) { $resp.tenantAppsProducts }
                    elseif ($resp.responseData)   { $resp.responseData }
                    else                           { $resp }

        # Find any product that looks like Email & Collaboration (handles typos/variants)
        $desc = $null
        foreach ($p in $products) {
            $name = ($p.displayName ?? $p.name ?? $p.productName ?? "") + ""
            $name = $name.Trim()
            if (($name -match '(?i)email') -and ($name -match '(?i)collab')) {
                $desc = Normalize-Blank ($p.desc ?? $p.description)
                break
            }
            if (($name -match '(?i)email') -and ($name -match '(?i)collab..t')) {
                $desc = Normalize-Blank ($p.desc ?? $p.description)
                break
            }
        }

        # Return exactly ONE service with allowed taxonomy
        return ,([PSCustomObject]@{
            Name        = "Email & Collaboration"
            Description = ($desc ?? "Check Point Harmony Email & Collaboration")
            Category    = "other"           # stays inside your ValidateSet
            Subcategory = "email security"  # <-- VALIDATESET COMPLIANT
        })
    }
    catch {
        Write-Warning "Could not fetch products. Details: $($_.Exception.Message)"
        return ,([PSCustomObject]@{
            Name        = "Email & Collaboration"
            Description = "Check Point Harmony Email & Collaboration"
            Category    = "other"
            Subcategory = "email security"
        })
    }
}

# ---------------------------------------------------------
# Usage (detailed per service) → { id, name, service, usage }
# ---------------------------------------------------------
function Get-OrganizationsUsage {
    Write-Host "Fetching usage records..."

    try {
        if ([string]::IsNullOrWhiteSpace($Env:TENANT_ID)) { throw "TENANT_ID env var is required." }
        $year = (Get-Date).Year

        # Prefer detailed rows (richer); require units here
        $rows = Invoke-UsageReport -TenantId $Env:TENANT_ID.Trim() -Year $year -Summarized:$false -RequireUnits:$true
        if (-not $rows -or $rows.Count -eq 0) {
            $rows = Invoke-UsageReport -TenantId $Env:TENANT_ID.Trim() -Year $year -Summarized:$true -RequireUnits:$true
        }
        if ($null -eq $rows -or $rows.Count -eq 0) {
            Write-Host "No usage rows returned." -ForegroundColor Yellow
            return @{}
        }

        # Aggregate by tenant+service
        $mappedUsage = @{}
        foreach ($r in $rows) {
            $name = $r.tenantName
            $svc  = if ($r.productName) { $r.productName } else { 'All Services' }
            $id   = Normalize-Blank $r.tenantId
            if (-not $id) { $id = Normalize-Blank $r.contractId }
            if (-not $id) { $id = (New-DeterministicGuidFromString $name).ToString() }

            $units = $r.usedUnits
            if ($name -and $svc -and ($units -ne $null) -and $units -gt 0) {
                $key = "$id|$svc"
                if ($mappedUsage.ContainsKey($key)) {
                    $mappedUsage[$key].usage += [int]$units
                } else {
                    $mappedUsage[$key] = @{
                        id      = "$id"
                        name    = "$name"
                        service = "$svc"
                        usage   = [int]$units
                    }
                }
            }
        }

        [System.GC]::GetTotalMemory('forcefullcollection') | Out-Null
    }
    catch {
        Write-Error "An error occured while fetching usage. Details: $($_.Exception.Message)"
        return @{}
    }

    if ($mappedUsage.Count -eq 0) {
        Write-Host "No organizations with valid usage." -ForegroundColor Yellow
        return @{}
    }

    Write-Host "$($mappedUsage.Count) usage records mapped." -ForegroundColor Green
    return $mappedUsage
}
