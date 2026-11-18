param(
    [Parameter(Mandatory=$true)][string]$Executable,
    [Parameter(Mandatory=$true)][string]$TemporaryDirectory,
    [Parameter(Mandatory=$true)][int]$RecordedProcessId,
    [Parameter(Mandatory=$true)][ValidatePattern('^[0-9]+$')][string]$RecordedCreationTimeUtcTicks,
    [switch]$AllowKnownFixtureDialogs
)
# Copy PID + executable + exact UTC ticks from the SAME original identity record.
# Legacy TaskStarted-only records DO NOT authorize recovery. No PID/name discovery.
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$OutputEncoding=[Text.Encoding]::UTF8
chcp 65001 | Out-Null
$root=[IO.Path]::GetFullPath($TemporaryDirectory).TrimEnd('\')
if(-not $root.StartsWith('D:\temp\aiRunner\opencode\',[StringComparison]::OrdinalIgnoreCase)) {throw 'Unsafe root'}
$cursor=Get-Item -LiteralPath $root
while($null -ne $cursor) {if($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) {throw 'Reparse ancestor forbidden'};$cursor=$cursor.Parent}
$oldTemp=$env:TEMP;$oldTmp=$env:TMP;$env:TEMP=$root;$env:TMP=$root
$session=$null
try {
    if(-not ('LexHelperGuiTest.Session' -as [type])) {Add-Type -Path (Join-Path $PSScriptRoot 'gui_native.cs')}
    # Attachment validates the saved ticks and executable before enumerating ANY window.
    $session=[LexHelperGuiTest.Session]::new($Executable,$root,$RecordedProcessId,$RecordedCreationTimeUtcTicks)
    $result=$session.CloseNormally(20000,[bool]$AllowKnownFixtureDialogs)
    $result | ConvertTo-Json -Depth 8
    if($result.State -ne 'Exited') {throw "Original PID $RecordedProcessId UTC ticks $RecordedCreationTimeUtcTicks remains/unknown: $($result.Reason)"}
} finally {
    if($null -ne $session) {$session.Dispose()}
    $env:TEMP=$oldTemp;$env:TMP=$oldTmp
}
