@{
    # Analyze both Error and Warning diagnostics so inherited technical debt is
    # visible in GitHub annotations and the job summary. The workflow decides
    # which findings are currently blocking.
    Severity = @(
        'Error'
        'Warning'
    )

    Rules = @{
        # The Intune migration payload executes through Windows PowerShell 5.1
        # on the target device. Explicitly enable syntax compatibility checking
        # because this rule is not enabled by default.
        PSUseCompatibleSyntax = @{
            Enable = $true
            TargetVersions = @(
                '5.1'
            )
        }
    }
}
