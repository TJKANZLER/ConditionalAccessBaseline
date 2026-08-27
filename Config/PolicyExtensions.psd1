@{
    SchemaVersion = '3.0'

    # These are target resource/service-principal application IDs, not mobile client-app IDs.
    # A MAM-capable client accessing Office 365 is already covered by the default CA300 scope.
    # Add an entry only when CA300 must protect a separate resource/API, for example:
    # @{
    #     ApplicationId = '11111111-2222-4333-8444-555555555555'
    #     DisplayName   = 'Contoso protected API'
    # }
    AdditionalMamProtectedResources = @()

    # Add these only when the tenant uses Windows App / Cloud PC resources.
    # Supported entries are Azure Virtual Desktop, Windows 365, and Windows Cloud Login.
    # Example:
    # @{
    #     ApplicationId = '9cdead84-a844-4324-93f2-b2e6bb768d07'
    #     DisplayName   = 'Azure Virtual Desktop'
    # }
    AdditionalWindowsTokenProtectionResources = @()
}
