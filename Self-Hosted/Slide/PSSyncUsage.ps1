Function Invoke-SyncUsage {
    Process {
        try {
            Write-Host "Starting call"
            $ServiceIds = Invoke-GetServiceIds
            $usageRecords = Get-OrganizationsUsage

            if (-not $usageRecords) {
                Write-Error "Failed to retrieve usage data."
                return
            }

            foreach ($record in $usageRecords.Values) {
                Write-Host "$($record.name) | $($record.client_id) has $($record.usage) seats used for $($record.service), attempting to create billing request..." -ForegroundColor Green

                try {
                    $body = Initialize-PSCreateBillingRequest -ClientOId $null -AccountId $record.client_id -UnitCount $record.usage
                    $body = $body | Select-Object -Property * -ExcludeProperty clientOId

                    New-PSBilling $ServiceIds[$record.service] $body
                }
                catch {
                    Write-Host "Account mapping pending in Reconcile for $($record.name)" -ForegroundColor Yellow
                    continue
                }
            }
        }
        catch {
            Write-Error $_
            throw 'An error occurred while syncing usage. Script execution stopped.'
        }
    }
}