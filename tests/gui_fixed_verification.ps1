param(
    [Parameter(Mandatory=$true)][string]$TemporaryDirectory,
    [ValidateSet('Support','Default','Interactive')][string]$Batch='Support'
)
# Independent TC-007/009 fixed-artifact runner. Never builds or writes the caller's out.
# Only the explicit Interactive batch may open ordinary synthetic-fixture dialogs.
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$OutputEncoding=[Text.Encoding]::UTF8
chcp 65001 | Out-Null
$root=[IO.Path]::GetFullPath($TemporaryDirectory).TrimEnd('\')
if($root -notmatch '^D:\\temp\\aiRunner\\opencode\\LexHelper-test-gui-fixed-[^\\]+$') {throw 'A unique approved fixed-GUI task directory is required'}
if(-not (Test-Path -LiteralPath $root -PathType Container)) {throw 'Create the approved unique directory first'}
$cursor=Get-Item -LiteralPath $root
while($null -ne $cursor) {if($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) {throw 'Reparse ancestor forbidden'};$cursor=$cursor.Parent}
$oldTemp=$env:TEMP;$oldTmp=$env:TMP;$env:TEMP=$root;$env:TMP=$root
$repo=Split-Path -Parent $PSScriptRoot
$expected=@{Debug='F3DF17565CD3F9A52D0F26B80BC6167D73A9644891FAADEC08ABA28EBE0731E6';Release='604296401DB9755A8AD8C87536220E9127A1348BD3A2D93DA7F8D91AC063CF0C'}
$entries=[Collections.Generic.List[object]]::new()
$failed=$false
function Invoke-GuiBatchChild([string]$Name,[string]$Script,[string[]]$Arguments,[string]$Directory) {
    $output=@(& (Get-Command pwsh.exe).Source -NoProfile -ExecutionPolicy Bypass -File $Script @Arguments 2>&1 | ForEach-Object {$_.ToString()})
    $code=$LASTEXITCODE
    $output | Set-Content -LiteralPath (Join-Path $Directory ($Name+'-stdout.txt')) -Encoding utf8
    return [pscustomobject]@{Name=$Name;ExitCode=$code;Directory=$Directory;Arguments=$Arguments;StartedBy='pwsh.exe -NoProfile -ExecutionPolicy Bypass -File';FinishedUtc=[DateTime]::UtcNow.ToString('o')}
}
try {
    $hashes=@(Get-FileHash -LiteralPath (@('src/gui/main.cpp','resources/app.rc','resources/app.manifest','CMakeLists.txt','CMakePresets.json') | ForEach-Object {Join-Path $repo $_}))
    $hashes+=@(Get-ChildItem -LiteralPath $PSScriptRoot -File -Filter 'gui_*' | Get-FileHash)
    $hashes | Select-Object Path,Algorithm,Hash | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $root ($Batch+'-source-hashes.json')) -Encoding utf8
    foreach($config in @('Debug','Release')) {
        $exe=Join-Path $repo ('out\vs2026\'+$config+'\LexHelper.exe')
        if((Get-FileHash -LiteralPath $exe).Hash -cne $expected[$config]) {throw "Exact $config EXE SHA256 mismatch; refuse launch"}
    }
    if($Batch -eq 'Support') {
        $parse=@(Get-ChildItem -LiteralPath $PSScriptRoot -Filter 'gui_*.ps1' -File | ForEach-Object {
            $tokens=$null;$errors=$null;[void][Management.Automation.Language.Parser]::ParseFile($_.FullName,[ref]$tokens,[ref]$errors)
            [pscustomobject]@{Path=$_.FullName;Errors=@($errors | ForEach-Object {$_.ToString()})}
        })
        $parse | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $root 'powershell-syntax.json') -Encoding utf8
        if(@($parse | Where-Object {$_.Errors.Count -ne 0}).Count) {throw 'GUI PowerShell syntax errors'}
        $entry=Invoke-GuiBatchChild 'support' (Join-Path $PSScriptRoot 'gui_support_selftest.ps1') @('-TemporaryDirectory',$root) $root
        $entries.Add($entry);if($entry.ExitCode -ne 0) {$failed=$true}
    } else {
        foreach($config in @('Debug','Release')) {
            $exe=Join-Path $repo ('out\vs2026\'+$config+'\LexHelper.exe')
            $scripts=if($Batch -eq 'Default') {@('gui_smoke.ps1','gui_regression.ps1')} else {@('gui_regression.ps1')}
            foreach($script in $scripts) {
                $name=$Batch+'-'+$config+'-'+[IO.Path]::GetFileNameWithoutExtension($script)
                $directory=Join-Path $root ($name+'-'+[guid]::NewGuid().ToString('N').Substring(0,8))
                [void](New-Item -ItemType Directory -Path $directory)
                # Bind each individual run, including an intentional diagnostic failure,
                # rather than losing its script hashes when a later batch is rerun.
                $hashes | Select-Object Path,Algorithm,Hash | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath (Join-Path $directory 'source-hashes.json') -Encoding utf8
                $arguments=@('-Executable',$exe,'-TemporaryDirectory',$directory)
                if($script -eq 'gui_regression.ps1') {$arguments+=@('-EvidenceDirectory',$directory)}
                if($Batch -eq 'Interactive') {$arguments+='-Interactive'}
                $entry=Invoke-GuiBatchChild $name (Join-Path $PSScriptRoot $script) $arguments $directory
                $entries.Add($entry);if($entry.ExitCode -ne 0) {$failed=$true}
            }
        }
    }
} finally {
    [pscustomobject]@{Batch=$Batch;Entries=$entries.ToArray();Failed=$failed;ExpectedExecutableHashes=$expected;SystemActions='NOT EXECUTED';GlobalInput='NOT EXECUTED';Build='NOT EXECUTED';TemporaryDirectory=$root} | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath (Join-Path $root ($Batch+'-batch.json')) -Encoding utf8
    $env:TEMP=$oldTemp;$env:TMP=$oldTmp
}
$entries | Format-Table Name,ExitCode,Directory -AutoSize
if($failed) {exit 1}
