param(
    [Parameter(Mandatory=$true)][string]$TemporaryDirectory,
    [ValidateSet('Debug','Release')][string]$Configuration='Release',
    [string]$CMakeExecutable='D:\Program Files\Microsoft Visual Studio\18\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
)
# TC-006 / R1. Independent test-only project; no root CMake or production edits.
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$OutputEncoding=[Text.Encoding]::UTF8
chcp 65001 | Out-Null
$ErrorActionPreference='Stop'
$root=[IO.Path]::GetFullPath($TemporaryDirectory).TrimEnd('\')
if(-not $root.StartsWith('D:\temp\aiRunner\opencode\',[StringComparison]::OrdinalIgnoreCase)) {throw 'Unsafe test directory'}
if(-not (Test-Path -LiteralPath $root -PathType Container)) {throw 'Create test directory first'}
$cursor=Get-Item -LiteralPath $root
while($null -ne $cursor) {if($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) {throw 'Reparse ancestor forbidden'};$cursor=$cursor.Parent}
$env:TEMP=$root;$env:TMP=$root
Get-ChildItem Env: | Where-Object Name -Match '^LEXHELPER_.*SAMPLE$' | ForEach-Object {Remove-Item -LiteralPath "Env:$($_.Name)"}
if(-not [Environment]::Is64BitProcess) {throw 'Run x64 pwsh'}
if(-not (Test-Path -LiteralPath $CMakeExecutable -PathType Leaf)) {throw 'Approved CMake executable missing'}
$ctest=Join-Path (Split-Path $CMakeExecutable) 'ctest.exe'
$build=Join-Path $root 'build'
& $CMakeExecutable -S (Join-Path $PSScriptRoot 'icon_failure') -B $build -G 'Visual Studio 18 2026' -A x64 -T v145 2>&1 | Tee-Object -FilePath (Join-Path $root 'configure.txt')
if($LASTEXITCODE -ne 0) {throw 'Failure-test configure failed'}
& $CMakeExecutable --build $build --config $Configuration --target lexhelper_icon_failure_tests 2>&1 | Tee-Object -FilePath (Join-Path $root 'build.txt')
if($LASTEXITCODE -ne 0) {throw 'Failure-test build failed'}
& $ctest --test-dir $build -C $Configuration --output-on-failure --verbose 2>&1 | Tee-Object -FilePath (Join-Path $root 'ctest.txt')
if($LASTEXITCODE -ne 0) {throw 'Failure-test CTest failed'}
