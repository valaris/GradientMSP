<# =====================================================================
   Check Point Infinity Portal — MSP Integration (PowerShell)
   ---------------------------------------------------------------------
   Required ENV:
     - API_URL     : https://cloudinfra-gw-<region>.portal.checkpoint.com
     - CLIENT_ID   : External API Key clientId
     - ACCESS_KEY  : External API Key accessKey  (SECRET_KEY also accepted)
     - TENANT_ID   : Top-level tenant/account GUID for usage reports

   Functions (kept to your original naming where possible):
     - Invoke-Authentication     → mints & caches bearer token
     - Get-AuthHeaders           → returns Authorization header, auto-auths if needed
     - Get-OrganizationsRawData  → summarized usage report rows (one per tenant)
     - Get-MappedOrganizations   → maps { id, name } from usage rows
     - Get-VendorServices        → lists products/services for the tenant
     - Get-OrganizationsUsage    → detailed per-service rows → { id, name, service, usage }
===================================================================== #>

# --------------------------
# Script-scoped token cache
# --------------------------
Set-Variable -Name CheckpointBearerToken -Scope Script -Value $null

# ---------------
# Utility helpers
# ---------------
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

function Get-CheckpointToken {
    (Get-Variable -Name CheckpointBearerToken -Scope Script -ValueOnly)
}

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

        # token may be a string, or inside { token } or { data: { token } }
        $token = if ($resp -is [string]) { $resp }
                 elseif ($resp.token) { $resp.token }
                 elseif ($resp.data -and $resp.data.token) { $resp.data.token }
                 else { $null }

        if (-not $token) {
            throw "Auth succeeded but no token field found. Raw response: $($resp | ConvertTo-Json -Depth 6)"
        }

        # Cache in script scope (and optional global for quick REPL inspection)
        Set-Variable -Name CheckpointBearerToken -Scope Script -Value ([string]$token)
        # Set-Variable -Name CP_BearerToken -Scope Global -Value ([string]$token)  # uncomment if you want a global copy

        # Optional: show tenant/account id for sanity
        $acctDisp = '<unknown>'
        try {
            $pl = Get-JwtPayload $token
            if ($pl) {
                if ($pl.accountId) { $acctDisp = $pl.accountId }
                elseif ($pl.tenantId) { $acctDisp = $pl.tenantId }
                if (-not $Env:TENANT_ID -and $acctDisp -ne '<unknown>') { $Env:TENANT_ID = $acctDisp }
            }
        } catch {}

        $len = (Get-CheckpointToken).Length
        Write-Host ("Authenticated. Token length: {0} | Tenant/Account: {1}" -f $len, $acctDisp) -ForegroundColor Green
    }
    catch {
        $msg = $_.Exception.Message
        try {
            $rs = $_.Exception.Response.GetResponseStream()
            if ($rs) {
                $reader = New-Object IO.StreamReader($rs)
                $apiErr = $reader.ReadToEnd()
                if ($apiErr) { $msg += "`nAPI Error: $apiErr" }
            }
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

# -------------------------------------------------------------
# Robust usageReport invoker (tries month formats & previous mo)
# -------------------------------------------------------------
function Invoke-UsageReport {
    param(
        [Parameter(Mandatory)][string]$TenantId,
        [Parameter(Mandatory)][int]$Year,
        [Parameter(Mandatory)][bool]$Summarized
    )

    $base    = $Env:API_URL.TrimEnd('/')
    $headers = Get-AuthHeaders

    function Try-One($y, $mWire) {
        $url = "$base/api/v1/tenant/usageReport?tenantId=$TenantId&month=$mWire&year=$y&isSummurized=$($Summarized.ToString().ToLower())"
        try {
            $resp = Invoke-RestMethod -Method GET -Uri $url -Headers $headers
            # normalize envelopes
            if ($resp.responseData) { $resp = $resp.responseData }
            elseif ($resp.items)    { $resp = $resp.items }
            elseif ($resp.report)   { $resp = $resp.report }

            # some gateways return { success:false, message:"Error generation usage report" }
            if ($resp -is [hashtable] -and $resp.success -eq $false) {
                if ($resp.message -match 'Error generation usage report|Authentication required') {
                    return $null
                }
            }
            return $resp
        } catch {
            $m = $_.Exception.Message
            if ($m -match 'Bad Request|500|generation usage report') { return $null }
            throw
        }
    }

    # Current month candidates
    $now       = Get-Date
    $monthName = ([cultureinfo]::InvariantCulture.DateTimeFormat.GetMonthName($now.Month))
    $cands = @(
        @{ y = $Year; m = $monthName.ToUpperInvariant() },
        @{ y = $Year; m = $monthName },
        @{ y = $Year; m = $now.ToString('MM') }
    )

    # Previous month candidates (if current fails)
    $prev       = $now.AddMonths(-1)
    $prevName   = ([cultureinfo]::InvariantCulture.DateTimeFormat.GetMonthName($prev.Month))
    $cands    += @(
        @{ y = $prev.Year; m = $prevName.ToUpperInvariant() },
        @{ y = $prev.Year; m = $prevName },
        @{ y = $prev.Year; m = $prev.ToString('MM') }
    )

    foreach ($c in $cands) {
        $rows = Try-One -y $c.y -mWire $c.m
        if ($rows) {
            return @{ year = $c.y; month = $c.m; rows = $rows }
        }
    }

    throw "usageReport failed for all month formats (current and previous)."
}

# -----------------------------------------
# Organizations via summarized usage report
# -----------------------------------------
function Get-OrganizationsRawData {
    if ([string]::IsNullOrWhiteSpace($Env:TENANT_ID)) { throw "TENANT_ID env var is required." }
    $year   = (Get-Date).Year
    $result = Invoke-UsageReport -TenantId $Env:TENANT_ID.Trim() -Year $year -Summarized:$true
    return $result.rows
}

function Get-MappedOrganizations {
    Write-Host "Fetching organizations..."

    try {
        $rows = Get-OrganizationsRawData

        if (-not $rows -or $rows.Count -eq 0) {
            Write-Host "No organizations data found." -ForegroundColor Yellow
            return @{}
        }

        $mappedOrgs = @{}
        foreach ($r in $rows) {
            $id   = $r.tenantId
            $name = $r.tenantName
            if ($id -and $name -and -not $mappedOrgs.ContainsKey($id)) {
                $mappedOrgs[$id] = @{ id = $id; name = $name }
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
# Services / Products (list)
# --------------------------
function Get-VendorServices {
    [CmdletBinding()]
    param()

    $base = $Env:API_URL.TrimEnd('/')

    try {
        $resp = Invoke-RestMethod -Method GET -Uri "$base/api/v1/tenant/app/products" -Headers (Get-AuthHeaders)

        # shape: { success, tenantAppsProducts: [...] } OR envelope/array
        $products = if ($resp.tenantAppsProducts) { $resp.tenantAppsProducts }
                    elseif ($resp.responseData)   { $resp.responseData }
                    else                           { $resp }

        $names = @()
        foreach ($p in $products) {
            if     ($p.displayName) { $names += $p.displayName }
            elseif ($p.name)        { $names += $p.name }
            elseif ($p.productName) { $names += $p.productName }
        }

        # Keep your original single-object return shape
        [PSCustomObject]@{
            Name        = "Infinity Portal Services"
            Description = ($(if ($names.Count) { "Products: " + ($names -join ", ") } else { "Check Point product catalog for this tenant" }))
            Category    = "other"
            Subcategory = "other"
        }
    }
    catch {
        Write-Warning "Could not fetch products. Details: $($_.Exception.Message)"
        [PSCustomObject]@{
            Name        = "Infinity Portal Services"
            Description = "Product catalog unavailable"
            Category    = "other"
            Subcategory = "other"
        }
    }
}

# ---------------------------------------------------------
# Usage (detailed per service) → { id, name, service, usage }
# ---------------------------------------------------------
function Get-OrganizationsUsage {
    Write-Host "Fetching usage records..."

    try {
        if ([string]::IsNullOrWhiteSpace($Env:TENANT_ID)) { throw "TENANT_ID env var is required." }

        $year   = (Get-Date).Year
        $result = Invoke-UsageReport -TenantId $Env:TENANT_ID.Trim() -Year $year -Summarized:$false
        $resp   = $result.rows

        $mappedUsage = @{}

        foreach ($row in $resp) {
            $tid   = $row.tenantId
            $tname = $row.tenantName
            $svc   = $row.productName
            if (-not $svc) { $svc = $row.packageName }
            $units = $row.usedUnits

            if ($tid -and $tname -and $svc -and ($units -ne $null) -and $units -gt 0) {
                # key on tenantId + service
                $key = "$tid|$svc"
                $mappedUsage[$key] = @{
                    id      = $tid
                    name    = $tname
                    service = $svc
                    usage   = [int]$units
                }
            }
        }

        [System.GC]::GetTotalMemory('forcefullcollection') | Out-Null
    }
    catch {
        Write-Error "An error occured while fetching usage. Details: $($_.Exception.Message)"
    }

    if ($mappedUsage.Count -eq 0) {
        Write-Host "No organizations with valid usage." -ForegroundColor Yellow
        return @{}
    }

    Write-Host "$($mappedUsage.Count) usage records mapped." -ForegroundColor Green
    return $mappedUsage
}

# -----------------
# (Optional) tests:
# -----------------
# .\PSMain.ps1 authenticate
# $h = Get-AuthHeaders
# $base = $Env:API_URL.TrimEnd('/')
# Invoke-RestMethod -Method GET -Uri "$base/api/v1/tenant/app/products" -Headers $h
# Get-MappedOrganizations | Out-Host
# Get-OrganizationsUsage  | Out-Host
