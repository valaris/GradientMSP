function Invoke-Authentication {
    $url = "$($Env:API_URL)/account";
    $authHeaders = Get-AuthHeaders

    try {
        $response = Invoke-RestMethod -Method Get -Uri $url -Headers $authHeaders
        Write-Host "Successfully connected to Slide API" -ForegroundColor Green
    }
    catch {
        Write-Error "Authentication failed. See details: $_"
    }
}
function Get-AuthHeaders {
    return @{
        "Authorization" = "Bearer $Env:SECRET_TOKEN"
        "Content-Type"  = "application/json"
    }
}

function Get-OrganizationsRawData {
    $url = "$($ENV:API_URL)/client"
    $authHeaders = Get-AuthHeaders

    $organizations = Invoke-RestMethod -Method Get -Uri $url -Headers $authHeaders

    return $organizations.data
}

function Get-MappedOrganizations {
    try {
        $organizations = Get-OrganizationsRawData

        if ($organizations.Count -eq 0) {
            Write-Host "No organizations data found." -ForegroundColor Yellow
            return @{}
        }

        $mappedOrgs = @{}

        foreach ($org in $organizations) {
          if ($org.client_id -AND $org.name) {
                $mappedOrgs[$org.client_id] = @{
                    id   = $org.client_id
                    name = $org.name
                }
            }
        }

        # Force full garbage collection.
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

function Get-VendorServices {
    [CmdletBinding()]
    Param()

    $url = "$($Env:API_URL)/device"
    $headers = Get-AuthHeaders

    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get

        if (-not $response.data) {
            Write-Host "No devices found." -ForegroundColor Yellow
            return @()
        }

        # Get all unique service_model_name values
        $uniqueServices = $response.data |
            Where-Object { $_.service_model_name } |
            Select-Object -ExpandProperty service_model_name -Unique

        $services = @()

        foreach ($name in $uniqueServices) {
            $service = [PSCustomObject]@{
                Name        = $name
                Description = $name
                Category    = "other"
                Subcategory = "other"
            }
            $services += $service
        }

        Write-Host "$($services.Count) unique vendor services generated." -ForegroundColor Green
        return $services
    }
    catch {
        Write-Host "Failed to fetch vendor services. $_" -ForegroundColor Red
        return @()
    }
}

function Get-OrganizationsUsage {
    Write-Host "Fetching usage records..."

    $url = "$($Env:API_URL)/device"
    $headers = Get-AuthHeaders

    try {
        $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get

        if (-not $response.data) {
            Write-Host "No device data found." -ForegroundColor Yellow
            return @{}
        }

        $mappedUsage = @{}

        $grouped = $response.data |
            Where-Object { $_.client_id -and $_.service_model_name } |
            Group-Object client_id, service_model_name

        foreach ($group in $grouped) {
            $first = $group.Group[0]

            $key = "$($first.client_id)-$($first.service_model_name)"
		$mappedUsage[$key] = @{
                client_id = $first.client_id
                name      = $first.display_name
                service   = $first.service_model_name
                usage     = $group.Count
            }

        }

        [System.GC]::GetTotalMemory('forcefullcollection') | Out-Null
    }
    catch {
        Write-Error "An error occurred while fetching usage. Details: $_" -ForegroundColor Red
    }

    if ($mappedUsage.Count -eq 0) {
        Write-Host "No usage records found." -ForegroundColor Yellow
        return @{}
    }

    Write-Host "$($mappedUsage.Count) usage records mapped." -ForegroundColor Green
    return $mappedUsage
}
