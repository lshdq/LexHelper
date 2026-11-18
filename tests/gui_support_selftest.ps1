param(
    [Parameter(Mandatory=$true)][string]$TemporaryDirectory,
    [ValidateSet('HeaderSuccess','WrongHeader','HeaderSuffix','EmptyReadableHeader','ProviderMissing','UnicodeMissing','WrongUnicode','EmptyReadableUnicode','BusyMissed','BusyBadDeferred','BusyBadExit','BusySuccess','FirstReadySuccess','FirstReadyBackupDisabled','FirstReadyRestoreMenuDisabled','FirstReadyInstallEnabled')][string]$PolicyScenario
)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$OutputEncoding=[Text.Encoding]::UTF8
chcp 65001 | Out-Null
. (Join-Path $PSScriptRoot 'gui_support.ps1')

# Child-process entry tests the SAME policy functions as gui_regression, including exit codes.
if($PolicyScenario) {
    if($PolicyScenario.StartsWith('FirstReady')) {
        # Policy-only fake; Command deliberately throws to prove no system action is clicked.
        $fake=[pscustomobject]@{EnabledIds=@(1102,1104);MenuEnabledIds=@(1102,1104)}
        $fake | Add-Member -MemberType ScriptMethod -Name Enabled -Value {param($id) return $this.EnabledIds -contains $id}
        $fake | Add-Member -MemberType ScriptMethod -Name MenuEnabled -Value {param($id) return $this.MenuEnabledIds -contains $id}
        $fake | Add-Member -MemberType ScriptMethod -Name Command -Value {throw 'No system commands permitted in assertion'}
        switch($PolicyScenario) {
            'FirstReadyBackupDisabled' {$fake.EnabledIds=@(1104)}
            'FirstReadyRestoreMenuDisabled' {$fake.MenuEnabledIds=@(1102)}
            'FirstReadyInstallEnabled' {$fake.EnabledIds+=1103}
        }
        Assert-GuiFirstReadyCommands $fake
        [pscustomobject]@{Name='first Ready command policy fixture';Result='PASS';Detail='Read-only buttons and menus; no commands called; NOT a product run'} | ConvertTo-Json
    } elseif($PolicyScenario.StartsWith('Busy')) {
        Get-GuiBusyCoverageCheck ($PolicyScenario -ne 'BusyMissed') ($PolicyScenario -ne 'BusyBadDeferred') ($PolicyScenario -ne 'BusyBadExit') @{Fixture='classification only'} | ConvertTo-Json -Depth 8
    } else {
        $probe=[pscustomobject]@{HeaderAvailable=$true;HeaderNames=@('编码','词条','权重（小值优先）');HeaderUnavailableReason='fixture provider unavailable';UnicodeAvailable=$true;UnicodeValues=@('我','我们','中国',[char]::ConvertFromUtf32(0x20000));UnicodeUnavailableReason='fixture has no subcolumn capability'}
        switch($PolicyScenario) {
            'WrongHeader' {$probe.HeaderNames=@('编码','词条','错误标题')}
            'HeaderSuffix' {$probe.HeaderNames=@('编码','词条','权重（小值优先）错误')}
            'EmptyReadableHeader' {$probe.HeaderNames=@()}
            'ProviderMissing' {$probe.HeaderAvailable=$false;$probe.UnicodeAvailable=$false}
            'UnicodeMissing' {$probe.UnicodeAvailable=$false}
            'WrongUnicode' {$probe.UnicodeValues=@('错误字段')}
            'EmptyReadableUnicode' {$probe.UnicodeValues=@('',$null)}
        }
        @(Get-GuiMsaaChecks $probe @('我','我们','中国',[char]::ConvertFromUtf32(0x20000))) | ConvertTo-Json -Depth 8
    }
    return
}

$root=[IO.Path]::GetFullPath($TemporaryDirectory).TrimEnd('\')
if($root -notmatch '^D:\\temp\\aiRunner\\opencode\\LexHelper-(?:fix-guitools|test-gui-fixed)-[^\\]+$') {throw 'Use a unique LexHelper-fix-guitools-* or LexHelper-test-gui-fixed-* task root'}
if(-not (Test-Path -LiteralPath $root -PathType Container)) {throw 'Create the unique task root first'}
$cursor=Get-Item -LiteralPath $root
while($null -ne $cursor) {if($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) {throw 'Reparse ancestor forbidden'};$cursor=$cursor.Parent}
$run=Join-Path $root ('selftest-'+[guid]::NewGuid().ToString('N').Substring(0,8));[void](New-Item -ItemType Directory -Path $run)
$oldTemp=$env:TEMP;$oldTmp=$env:TMP;$env:TEMP=$run;$env:TMP=$run
$results=[Collections.Generic.List[object]]::new();$tracked=[Collections.Generic.List[object]]::new();$failure=$null
function Record-Support([string]$Name,$Detail) {$results.Add([pscustomobject]@{Name=$Name;Result='PASS';Detail=$Detail})}
function Expect-Refusal([scriptblock]$Action,[string]$Pattern) {
    $message=$null
    try {& $Action | Out-Null} catch {$message=$_.Exception.Message}
    Assert-GuiSupport ($null -ne $message -and $message -match $Pattern) "Expected refusal /$Pattern/, got: $message"
    return $message
}
function New-Fixture([string]$Path) {
    $s=[LexHelperGuiTest.Session]::new($Path,$run,$false)
    $track=[pscustomobject]@{Session=$s;Record=$null;Disposed=$false}
    $tracked.Add($track)
    $track.Record=Save-GuiOriginalIdentity $s $run
    return $track
}
function Release-Fixture($Track) {$Track.Session.Dispose();$Track.Disposed=$true}
function Invoke-SupportChild([string]$Script,[string[]]$Arguments) {
    $text=@(& (Get-Command pwsh.exe).Source -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $Script @Arguments 2>&1 | ForEach-Object {$_.ToString()})
    return [pscustomobject]@{ExitCode=$LASTEXITCODE;Output=($text -join "`n")}
}
try {
    if(-not ('LexHelperGuiTest.Session' -as [type])) {Add-Type -Path (Join-Path $PSScriptRoot 'gui_native.cs')}
    $compiler=Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
    if(-not (Test-Path -LiteralPath $compiler -PathType Leaf)) {throw "Existing fixture compiler unavailable: $compiler (no install attempted)"}
    $fixture=Join-Path $run 'gui_fixture.exe';$unknown=Join-Path $run 'gui_fixture_unknown.exe'
    foreach($target in @($fixture,$unknown)) {
        & $compiler /nologo /target:winexe /platform:x64 /codepage:65001 "/out:$target" (Join-Path $PSScriptRoot 'gui_fixture.cs')
        Assert-GuiSupport ($LASTEXITCODE -eq 0) 'Test-only fixture compilation failed'
    }
    Record-Support 'C# support and two Win32-only fixtures compile' @{Compiler=$compiler;FixtureSHA256=(Get-FileHash -LiteralPath $fixture).Hash;ProductionBuild='NOT EXECUTED'}
    $message=Expect-Refusal {[LexHelperGuiTest.Session]::new((Join-Path $run 'missing.exe'),$run,$false)} 'CreateProcess failed'
    Record-Support 'CreateProcess failure owns no child' $message

    $t=New-Fixture $fixture;$s=$t.Session;$id=$s.OriginalIdentity
    Assert-GuiSupport ($null -eq $id.CaptureError -and $id.CreationTimeUtcTicks -match '^\d+$') 'Complete original identity missing'
    $roundtrip=(Get-Content -LiteralPath $t.Record.IdentityFile -Raw | ConvertFrom-Json).Identity
    Assert-GuiSupport ($roundtrip.CreationTimeUtcTicks -is [string] -and $roundtrip.CreationTimeUtcTicks -ceq $id.CreationTimeUtcTicks) 'JSON damaged original ticks precision'
    $actual=[Diagnostics.Process]::GetProcessById($id.ProcessId)
    try {Assert-GuiSupport ($actual.StartTime.ToUniversalTime().Ticks.ToString() -ceq $id.CreationTimeUtcTicks) 'Independent UTC creation time mismatch'} finally {$actual.Dispose()}
    Record-Support 'Original identity persisted losslessly before window initialization' $id
    $message=Expect-Refusal {$s.InitializeWindow('LexHelper.IntentionallyMissingFixtureClass',250)} 'Owned main window missing'
    Assert-GuiSupport (-not $s.ForegroundIsOwn() -and -not $s.Process.HasExited) 'Fixture should remain alive, minimized/no-activation after initialization failure'
    $timer=[Diagnostics.Stopwatch]::StartNew();$close=$s.CloseNormally(2000,$false)
    Assert-GuiSupport ($close.State -eq 'Exited' -and $close.ExitCode -eq 0 -and $timer.ElapsedMilliseconds -lt 3000) 'Initialization-failure normal-close did not converge'
    $t.Record.Cleanup=$close
    Record-Support 'Window initialization failure retains identity and normally closes original child' @{Failure=$message;Cleanup=$close;ElapsedMilliseconds=$timer.ElapsedMilliseconds}
    Release-Fixture $t
    $message=Expect-Refusal {$s.Process.WaitForExit(0)} 'closed|disposed|SafeHandle'
    Record-Support 'Dispose releases retained handle' $message

    $t=New-Fixture $fixture;$s=$t.Session;$s.InitializeWindow();$id=$s.OriginalIdentity
    $wrong=([long]::Parse($id.CreationTimeUtcTicks)+1).ToString()
    $message=Expect-Refusal {[LexHelperGuiTest.Session]::new($fixture,$run,$id.ProcessId,$wrong)} 'creation time mismatch'
    Assert-GuiSupport (-not $s.Process.HasExited) 'Time-mismatch attach touched the live fixture'
    Record-Support 'Same PID and EXE but different original creation time refused' @{Identity=$id;RejectedUtcTicks=$wrong;Reason=$message}
    $message=Expect-Refusal {[LexHelperGuiTest.Session]::new($fixture,$run,$id.ProcessId,'')} 'Exact original creation UTC ticks required'
    Record-Support 'Legacy/missing exact timestamp refused' $message
    $message=Expect-Refusal {[LexHelperGuiTest.Session]::new((Get-Command pwsh.exe).Source,$run,$id.ProcessId,$id.CreationTimeUtcTicks)} 'identity incomplete|path mismatch'
    Assert-GuiSupport (-not $s.Process.HasExited) 'EXE-mismatch attach touched fixture'
    Record-Support 'Executable mismatch refused before window actions' $message
    $child=Invoke-SupportChild (Join-Path $PSScriptRoot 'gui_cleanup.ps1') @('-Executable',$fixture,'-TemporaryDirectory',$run,'-RecordedProcessId',"$($id.ProcessId)",'-RecordedCreationTimeUtcTicks',$wrong)
    Assert-GuiSupport ($child.ExitCode -ne 0 -and -not $s.Process.HasExited) 'Cleanup entry accepted mismatched original time'
    Record-Support 'Cleanup script mismatch is nonzero and leaves own fixture untouched' $child
    $child=Invoke-SupportChild (Join-Path $PSScriptRoot 'gui_cleanup.ps1') @('-Executable',$fixture,'-TemporaryDirectory',$run,'-RecordedProcessId',"$($id.ProcessId)",'-TaskStarted',[DateTime]::UtcNow.ToString('o'))
    Assert-GuiSupport ($child.ExitCode -ne 0 -and -not $s.Process.HasExited) 'Legacy TaskStarted invocation was accepted'
    Record-Support 'Cleanup legacy TaskStarted invocation rejected noninteractively' $child
    # Releasing our handle does not end the lifetime. Exact persisted identity can reattach.
    Release-Fixture $t
    $actual=[Diagnostics.Process]::GetProcessById($id.ProcessId)
    try {Assert-GuiSupport (-not $actual.HasExited) 'Dispose unexpectedly ended process lifetime'} finally {$actual.Dispose()}
    $child=Invoke-SupportChild (Join-Path $PSScriptRoot 'gui_cleanup.ps1') @('-Executable',$fixture,'-TemporaryDirectory',$run,'-RecordedProcessId',"$($id.ProcessId)",'-RecordedCreationTimeUtcTicks',$id.CreationTimeUtcTicks)
    Assert-GuiSupport ($child.ExitCode -eq 0) 'Exact-identity cleanup script failed'
    $closed=$child.Output | ConvertFrom-Json
    Assert-GuiSupport ($closed.State -eq 'Exited' -and $closed.Identity.CreationTimeUtcTicks -ceq $id.CreationTimeUtcTicks) 'Cleanup output lost original identity'
    $t.Record.Cleanup=$closed
    Record-Support 'Dispose does not kill; exact-identity script reattaches and normally closes' $closed

    $t=New-Fixture $unknown;$s=$t.Session;$id=$s.OriginalIdentity
    $message=Expect-Refusal {$s.InitializeWindow('LexHelper.MainWindow',250)} 'Owned main window missing'
    $timer=[Diagnostics.Stopwatch]::StartNew();$close=$s.CloseNormally(250,$false)
    Assert-GuiSupport ($close.State -eq 'LeftRunning' -and $close.Identity.CreationTimeUtcTicks -ceq $id.CreationTimeUtcTicks -and -not [string]::IsNullOrEmpty($close.Reason) -and $timer.ElapsedMilliseconds -lt 1500) 'Unsafe-close refusal must report bounded, complete original identity'
    $t.Record.Cleanup=$close
    Record-Support 'Unrecognized window not touched; bounded leftover report is non-null and exact' $close
    Assert-GuiSupport ($s.Process.WaitForExit(15000) -and $s.Process.ExitCode -eq 0) 'Own unknown fixture safety timer did not close normally'
    Record-Support 'Unrecognized fixture self-closes by its own native timer, no forced termination' $id
    $t.Record.Cleanup=$s.CloseNormally(1000,$false)
    Release-Fixture $t

    # Real script entrypoints, but ONLY our unknown-class fixture EXE. It self-closes
    # before the normal 15 s class wait expires, forcing initialization failure.
    # These intentionally failing child runs must still retain/report the original identity.
    foreach($entry in @('gui_smoke.ps1','gui_regression.ps1')) {
        $entryRoot=Join-Path $run ($entry.Replace('.ps1',''));[void](New-Item -ItemType Directory -Path $entryRoot)
        $arguments=@('-Executable',$unknown,'-TemporaryDirectory',$entryRoot)
        if($entry -eq 'gui_regression.ps1') {$arguments+=@('-EvidenceDirectory',$entryRoot)}
        $child=Invoke-SupportChild (Join-Path $PSScriptRoot $entry) $arguments
        Assert-GuiSupport ($child.ExitCode -ne 0) "$entry fixture initialization failure incorrectly passed"
        $reportFile=Join-Path $entryRoot $(if($entry -eq 'gui_smoke.ps1'){'smoke-results.json'}else{'results.json'})
        $entryReport=Get-Content -LiteralPath $reportFile -Raw | ConvertFrom-Json
        $entryRecord=if($entry -eq 'gui_smoke.ps1') {$entryReport.Process}else{@($entryReport.Processes)[0]}
        Assert-GuiSupport ($null -ne $entryReport.Failure -and $entryRecord.Identity.CreationTimeUtcTicks -match '^\d+$' -and $entryRecord.Cleanup.State -eq 'Exited' -and (Test-Path -LiteralPath $entryRecord.IdentityFile)) "$entry lost original startup-failure identity or lifecycle report"
        Record-Support "$entry initialization failure is nonzero with persisted original identity" @{ExitCode=$child.ExitCode;Failure=$entryReport.Failure;Process=$entryRecord;OwnProcessLeftRunning=$entryReport.OwnProcessLeftRunning}
    }

    foreach($case in @(
        @{Name='HeaderSuccess';Exit=0;Skip=0},@{Name='WrongHeader';Exit=1},@{Name='HeaderSuffix';Exit=1},@{Name='EmptyReadableHeader';Exit=1},
        @{Name='ProviderMissing';Exit=0;Skip=2},@{Name='UnicodeMissing';Exit=0;Skip=1},@{Name='WrongUnicode';Exit=1},@{Name='EmptyReadableUnicode';Exit=1},
        @{Name='BusyMissed';Exit=0;Skip=1},@{Name='BusyBadDeferred';Exit=1},@{Name='BusyBadExit';Exit=1},@{Name='BusySuccess';Exit=0;Skip=0},
        @{Name='FirstReadySuccess';Exit=0;Skip=0},@{Name='FirstReadyBackupDisabled';Exit=1},@{Name='FirstReadyRestoreMenuDisabled';Exit=1},@{Name='FirstReadyInstallEnabled';Exit=1}
    )) {
        $child=Invoke-SupportChild $PSCommandPath @('-TemporaryDirectory',$run,'-PolicyScenario',$case.Name)
        Assert-GuiSupport ($child.ExitCode -eq $case.Exit) "Policy $($case.Name): wrong exit $($child.ExitCode): $($child.Output)"
        if($case.Exit -eq 0) {
            $checks=@($child.Output | ConvertFrom-Json)
            Assert-GuiSupport (@($checks | Where-Object Result -eq 'NOT EXECUTED').Count -eq $case.Skip) "Wrong skip count for $($case.Name)"
        }
        Record-Support "Shared classification/nonzero policy: $($case.Name)" $child
    }
} catch {$failure=$_.Exception.Message;$results.Add([pscustomobject]@{Name='support self-test stopped';Result='FAIL';Detail=$failure})} finally {
    foreach($t in $tracked) {
        if(-not $t.Disposed) {
            try {
                $close=$t.Session.CloseNormally(1000,$false);$t.Record.Cleanup=$close
                if($close.State -ne 'Exited') {
                    # Fixtures ONLY have an automatic normal-close timer. Never force-kill.
                    if(-not $t.Session.Process.WaitForExit(15000)) {$failure='Own fixture remains/unknown: '+($close | ConvertTo-Json -Depth 8 -Compress)}
                }
            } finally {Release-Fixture $t}
        }
        if($null -ne $t.Record) {$t.Record | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $t.Record.IdentityFile -Encoding utf8}
    }
    $env:TEMP=$oldTemp;$env:TMP=$oldTmp
}
$report=[pscustomobject]@{Result=$(if($null -eq $failure){'PASS'}else{'FAIL'});Failure=$failure;PassCount=@($results | Where-Object Result -eq 'PASS').Count;Results=$results.ToArray();Processes=@($tracked | ForEach-Object {$_.Record});TemporaryDirectory=$run;LexHelperApplication='NOT EXECUTED';ProductionBuild='NOT EXECUTED';SystemOperations='NOT EXECUTED';ForegroundDialogs='NOT EXECUTED'}
$report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $run 'support-results.json') -Encoding utf8
$report | ConvertTo-Json -Depth 12
if($null -ne $failure) {exit 1}
