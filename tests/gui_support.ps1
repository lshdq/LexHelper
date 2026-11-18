# Shared support policies. Dot-source only; no application launch or system actions here.
function Assert-GuiSupport($Condition,[string]$Message) {if(-not $Condition) {throw $Message}}
function Save-GuiOriginalIdentity($Session,[string]$Directory) {
    $identity=$Session.OriginalIdentity
    $name='process-{0}-{1}.json' -f $identity.ProcessId,$identity.CreationTimeUtcTicks
    $path=Join-Path $Directory $name
    # Persist BEFORE waiting for input-idle/windows. Strings preserve exact UTC ticks.
    $record=[pscustomobject]@{Identity=$identity;IdentityFile=$path;Cleanup=$null}
    $record | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $path -Encoding utf8
    return $record
}
function Get-GuiMsaaChecks($Probe,[string[]]$ExpectedUnicode) {
    $checks=[Collections.Generic.List[object]]::new()
    if(-not $Probe.HeaderAvailable) {
        $checks.Add([pscustomobject]@{Name='MSAA weight column header';Result='NOT EXECUTED';Detail=$Probe.HeaderUnavailableReason})
    } else {
        Assert-GuiSupport (@($Probe.HeaderNames) -ccontains '权重（小值优先）') ('Readable MSAA weight header mismatch: '+($Probe.HeaderNames -join '|'))
        $checks.Add([pscustomobject]@{Name='MSAA weight column header';Result='PASS';Detail=$Probe.HeaderNames})
    }
    if(-not $Probe.UnicodeAvailable) {
        $checks.Add([pscustomobject]@{Name='MSAA actual preview Unicode subitems';Result='NOT EXECUTED';Detail=$Probe.UnicodeUnavailableReason})
    } else {
        foreach($expected in $ExpectedUnicode) {Assert-GuiSupport (@($Probe.UnicodeValues) -ccontains $expected) "Readable MSAA Unicode subitem mismatch: expected exact value $expected"}
        $checks.Add([pscustomobject]@{Name='MSAA actual preview Unicode subitems';Result='PASS';Detail=$Probe.UnicodeValues})
    }
    return $checks.ToArray()
}
function Get-GuiBusyCoverageCheck([bool]$ObservedBusy,[bool]$DeferredCloseLogObserved,[bool]$ExitedNormally,$Checkpoints) {
    if(-not $ObservedBusy) {
        return [pscustomobject]@{Name='real busy import/deferred close';Result='NOT EXECUTED';Detail=@{Reason='Task completed before busy observation; one bounded attempt, no product verdict';Checkpoints=$Checkpoints}}
    }
    Assert-GuiSupport $DeferredCloseLogObserved 'Observed busy, but deferred-close log missing'
    Assert-GuiSupport $ExitedNormally 'Observed busy-close process failed to exit normally'
    return [pscustomobject]@{Name='real busy import/deferred close';Result='PASS';Detail=@{BusyObserved=$true;DeferredCloseLogObserved=$true;ExitedNormally=$true;Checkpoints=$Checkpoints}}
}
function Assert-GuiFirstReadyCommands($Session) {
    foreach($id in @(1102,1104)) {
        Assert-GuiSupport ($Session.Enabled($id) -and $Session.MenuEnabled($id)) "First Ready: backup/restore button and menu must be enabled ($id)"
    }
    foreach($id in @(1002,1103)) {
        Assert-GuiSupport (-not $Session.Enabled($id) -and -not $Session.MenuEnabled($id)) "First Ready: empty model save/install button and menu must be disabled ($id)"
    }
}
