Function Invoke-SyncAccounts {
    Param() Process {
        $propsToCreateAccounts = Get-MappedOrganizations
        return Invoke-CreateAccounts $propsToCreateAccounts
    }
}

