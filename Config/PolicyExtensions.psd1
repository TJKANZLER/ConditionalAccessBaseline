@{
    SchemaVersion = '1.0'

    # Add only application IDs for third-party apps that support Intune App Protection.
    # Office 365 remains included automatically and the default generated CA300 is unchanged.
    AdditionalMamApplicationIds = @()
}
