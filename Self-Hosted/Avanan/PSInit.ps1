Function InitGradientConnection {
    Param(
        [String]
        $Command
    )
    Process {
        If (“authenticate”, ”sync-accounts”, ”sync-services”, "update-status", "sync-usage", "sync-all" -NotContains $Command) {
            Throw “$Command is not a valid action! Please use authenticate, sync-accounts, sync-services, update-status, sync-usage, or sync-all”
        }

        #Load ENV
        Get-Content "$ScriptDir\.env" | ForEach-Object {
            $name, $value = $_.split('=')
            if ([string]::IsNullOrWhiteSpace($name) || $name.Contains('#')) {
                continue
            }
            Set-Item -Path "env:$name" -Value $value
        }

        #Validate ENV
        if ([string]::IsNullOrWhiteSpace($Env:VENDOR_API_KEY) -OR [string]::IsNullOrWhiteSpace($Env:PARTNER_API_KEY)) {
            Throw "Gradient API keys are required in ENV"
        }

        #Validate ENV
        if (
            [string]::IsNullOrWhiteSpace($Env:CLIENT_ID) -OR
            [string]::IsNullOrWhiteSpace($Env:ACCESS_KEY) -OR
            [string]::IsNullOrWhiteSpace($Env:TENANT_ID) -OR
            [string]::IsNullOrWhiteSpace($Env:API_URL)
        ) {
            Throw "Checkpoint API environment variables are required in ENV"
        }

        #Can add custom ENV validation here

        $GRADIENT_TOKEN = BuildGradientToken $Env:VENDOR_API_KEY $Env:PARTNER_API_KEY

        #Init SDK
        Set-PSConfiguration 'https://app.usegradient.com' '' '' @{
            'Gradient-Token' = $GRADIENT_TOKEN
        }
    }
}
