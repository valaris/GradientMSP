Function Invoke-SyncServices {
    Param(
    ) Process {
        $propsToCreateServices = Get-VendorServices
        return Invoke-CreateServices $propsToCreateServices "https://meetgradient.com" "phil.flamingo@meetgradient.com"
    }
}