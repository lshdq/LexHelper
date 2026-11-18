param(
    [Parameter(Mandatory=$true)][string]$Executable,
    [Parameter(Mandatory=$true)][string]$TemporaryDirectory
)
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$OutputEncoding=[Text.Encoding]::UTF8
chcp 65001 | Out-Null
# Read-only minimized/no-activation. No system commands, dialogs, global keys or force-kill.
$exe=(Resolve-Path -LiteralPath $Executable).Path
$root=[IO.Path]::GetFullPath($TemporaryDirectory).TrimEnd('\')
if(-not $root.StartsWith('D:\temp\aiRunner\opencode\',[StringComparison]::OrdinalIgnoreCase)) {throw 'Unsafe temporary root'}
if(-not (Test-Path -LiteralPath $root -PathType Container)) {throw 'Create the task-specific temporary directory first'}
$cursor=Get-Item -LiteralPath $root
while($null -ne $cursor) {if($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) {throw 'Reparse ancestor forbidden'};$cursor=$cursor.Parent}
$oldTemp=$env:TEMP;$oldTmp=$env:TMP;$env:TEMP=$root;$env:TMP=$root
$session=$null;$record=$null;$failure=$null;$cleanup=$null
. (Join-Path $PSScriptRoot 'gui_support.ps1')
try {
    if(-not ('LexHelperGuiTest.Session' -as [type])) {Add-Type -Path (Join-Path $PSScriptRoot 'gui_native.cs')}
    $session=[LexHelperGuiTest.Session]::new($exe,$root,$false)
    $record=Save-GuiOriginalIdentity $session $root
    $session.InitializeWindow()
    $timer=[Diagnostics.Stopwatch]::StartNew()
    while(-not ($session.MainEnabled() -and $session.Enabled(1001) -and -not $session.Text($session.Main).Contains('[处理中]'))) {
        if($timer.ElapsedMilliseconds -ge 15000) {throw 'Timeout: first GUI Ready'}
        if($session.Process.WaitForExit(25)) {throw 'GUI exited before first Ready'}
    }
    Assert-GuiFirstReadyCommands $session
    foreach($id in @(1001,1002,1102,1103,1104,2002,2005,2007,2008)) {[void]$session.Control($id)}
    if(-not $session.Visible() -or -not $session.Minimized()) {throw 'Expected a visible minimized main window'}
    if($session.ForegroundIsOwn()) {throw 'Default smoke unexpectedly became foreground'}
    if($session.Count() -ne 0) {throw 'Expected empty model'}
    if(($session.Style($session.Main) -band 0x000F0000) -ne 0x000F0000) {throw 'Native window styles missing'}
    $session.Close()
    if(-not $session.Process.WaitForExit(15000)) {throw 'Own GUI did not exit; no force termination'}
    if($session.Process.ExitCode -ne 0) {throw "GUI exit code $($session.Process.ExitCode)"}
} catch {$failure=$_.Exception.Message} finally {
    try {
        if($null -ne $session) {
            $cleanup=$session.CloseNormally(15000,$false)
            if($null -eq $record) {$record=[pscustomobject]@{Identity=$session.OriginalIdentity;IdentityFile=$null;Cleanup=$null}}
            $record.Cleanup=$cleanup
            if($null -ne $record.IdentityFile) {
                try {$record | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $record.IdentityFile -Encoding utf8}
                catch {$failure="Identity journal update failed: $($_.Exception.Message)"}
            }
            if($cleanup.State -ne 'Exited') {Write-Warning ($cleanup | ConvertTo-Json -Depth 8 -Compress)}
        }
    } finally {
        if($null -ne $session) {$session.Dispose()}
        $env:TEMP=$oldTemp;$env:TMP=$oldTmp
    }
}
$left=if($null -ne $cleanup -and $cleanup.State -ne 'Exited') {$cleanup} else {$null}
$report=[pscustomobject]@{Test='GUI minimized/no-activation startup/first Ready/empty state/close';Result=$(if($null -eq $failure -and $null -eq $left){'PASS'}else{'FAIL'});Failure=$failure;Process=$record;OwnProcessLeftRunning=$left;SHA256=(Get-FileHash -LiteralPath $exe).Hash;SystemCommandsClicked=$false;Dialogs='NOT EXECUTED';SystemDeployment='NOT EXECUTED'}
$report | ConvertTo-Json -Depth 10
$report | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $root 'smoke-results.json') -Encoding utf8
if($null -ne $failure -or $null -ne $left) {exit 1}
