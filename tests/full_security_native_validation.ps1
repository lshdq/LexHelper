# TC-007 reusable ordinary-token validation. No UAC / GUI / system ACL changes.
# Keeps logs and exact created-root list; never discovers or removes old roots.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$TaskRoot, [switch]$SkipBuild, [switch]$ReuseTask)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 | Out-Null
$base = 'D:\temp\aiRunner\opencode'
if ($TaskRoot -cnotmatch '^D:\\temp\\aiRunner\\opencode\\LexHelper-test-adminprobe-[0-9]{14}-[0-9a-f]{8}$') { throw 'Strict unique D: task path required' }
if ([Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Do not elevate this test runner' }
$p = $base
while ($p) {
    if ((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Reparse ancestor refused' }
    $parent = [IO.Directory]::GetParent($p); $p = if ($parent) { $parent.FullName } else { $null }
}
if (!$SkipBuild -and !$ReuseTask) {
    if (Test-Path -LiteralPath $TaskRoot) { throw 'Task root already exists' }
    New-Item -ItemType Directory -Path $TaskRoot | Out-Null
}
elseif (!(Test-Path -LiteralPath "$TaskRoot\build\CMakeCache.txt")) { throw 'Missing own build' }
foreach ($dir in @('temp', 'evidence')) { if (!(Test-Path -LiteralPath "$TaskRoot\$dir")) { New-Item -ItemType Directory -Path "$TaskRoot\$dir" | Out-Null } }
$env:TEMP = "$TaskRoot\temp"; $env:TMP = $env:TEMP; $env:MSBUILDDEBUGPATH = $env:TEMP
Remove-Item Env:LEXHELPER_CWB_SAMPLE -ErrorAction SilentlyContinue
$project = Split-Path $PSScriptRoot -Parent
$cmake = 'D:\Program Files\Microsoft Visual Studio\18\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
$ctest = Join-Path (Split-Path $cmake) 'ctest.exe'
$evidence = "$TaskRoot\evidence"; $script:results = @(); $script:roots = @(); $script:assertions = 0; $script:failed = 0
function Assert-Contract([bool]$OK, [string]$Name) {
    $script:assertions++
    if (!$OK) { $script:failed++; [Console]::WriteLine("FAIL $Name") } else { [Console]::WriteLine("PASS $Name") }
}
function Invoke-Recorded([string]$Name, [string]$Exe, [string[]]$Arguments, [int]$Expected = 0) {
    $command = '"' + $Exe + '" ' + (($Arguments | ForEach-Object { '"' + $_ + '"' }) -join ' ')
    $text = (& $Exe @Arguments 2>&1 | Out-String); $code = $LASTEXITCODE
    [IO.File]::WriteAllText("$evidence\$Name.log", "COMMAND $command`r`nEXIT $code EXPECTED $Expected`r`n$text", [Text.UTF8Encoding]::new($false))
    $script:results += [pscustomobject]@{Name=$Name; Command=$command; Exit=$code; Expected=$Expected}
    foreach ($match in [regex]::Matches($text, '(?m)^ROOT_CREATED (D:\\temp\\aiRunner\\opencode\\LexHelper-admin-fullsecurity-[0-9a-f]{32})\r?$')) { $script:roots += $match.Groups[1].Value }
    Assert-Contract ($code -eq $Expected) "$Name exit $code (expected $Expected)"
    return $text
}
function Fresh-Root { return "$base\LexHelper-admin-fullsecurity-$([guid]::NewGuid().ToString('N'))" }
if (!$SkipBuild) {
    Invoke-Recorded 'configure' $cmake @('-S',$project,'-B',"$TaskRoot\build",'-G','Visual Studio 18 2026','-A','x64','-DBUILD_TESTING=ON') | Write-Output
}
foreach ($config in @('Debug','Release')) {
    if (!$SkipBuild) {
        Invoke-Recorded "build-$config" $cmake @('--build',"$TaskRoot\build",'--config',$config,'--parallel','1','--','/nodeReuse:false') | Write-Output
        if ($script:results[-1].Exit -ne 0) { throw 'Build failed; raw log retained. Do not test stale executable.' }
    }
    Invoke-Recorded "ctest-$config" $ctest @('--test-dir',"$TaskRoot\build",'-C',$config,'--output-on-failure') | Write-Output
    Copy-Item -LiteralPath "$TaskRoot\build\Testing\Temporary\LastTest.log" -Destination "$evidence\LastTest-$config.log"
    $probe = "$TaskRoot\build\$config\lexhelper_full_security_native_probe.exe"
    $contract = "$TaskRoot\build\$config\lexhelper_full_security_native_contract.exe"
    Invoke-Recorded "selftest-$config" $probe @('--self-test') | Write-Output
    $unused = Fresh-Root
    $refused = Invoke-Recorded "ordinary-diagnose-$config" $probe @('--diagnose','--root',$unused) 3
    Assert-Contract (!(Test-Path -LiteralPath $unused)) 'ordinary diagnose created no root'
    Assert-Contract ($refused -match 'not_elevated' -and $refused -notmatch 'matrix_completed only') 'ordinary diagnose not a privileged matrix'
    $badPaths = @('C:\not-approved', $unused.ToLowerInvariant(), "$unused\", "$unused\child", "$unused`:ads", "\\?\$unused", '\\server\share\x', '\\.\D:\x', "$unused.", ($unused + ('f' * 1024)))
    $i = 0
    foreach ($bad in $badPaths) {
        Invoke-Recorded "badpath-$config-$i" $probe @('--diagnose','--root',$bad) 2 | Write-Output
        Invoke-Recorded "prepare-badpath-$config-$i" $contract @('--prepare-root',$bad) 2 | Write-Output
        $i++
    }
    Invoke-Recorded "noargs-$config" $probe @() 2 | Write-Output
    Invoke-Recorded "extra-$config" $probe @('--diagnose','--root',$unused,'extra') 2 | Write-Output
    Invoke-Recorded "prepare-extra-$config" $contract @('--prepare-root',$unused,'extra') 2 | Write-Output
    Assert-Contract (!(Test-Path -LiteralPath $unused)) 'invalid CLI modes created no accepted root'
    $prepared = Fresh-Root
    $proof = Invoke-Recorded "prepare-$config" $contract @('--prepare-root',$prepared)
    Assert-Contract ((Get-ChildItem -LiteralPath $prepared -Force | Measure-Object).Count -eq 0) 'prepared root completely empty'
    Assert-Contract ($proof -match 'PREPARED_ROOT root=.*; volume=\d+; file_id=\d+; atomic_FILE_CREATE=1; creation_protected_SD=1; owner_current=1; empty=1; no_reparse=1') 'prepare outputs creation/identity proof'
    $aclBefore = (Get-Acl -LiteralPath $prepared).Sddl
    $retry = Invoke-Recorded "prepare-repeat-$config" $contract @('--prepare-root',$prepared) 4
    Assert-Contract ((Get-ChildItem -LiteralPath $prepared -Force | Measure-Object).Count -eq 0 -and (Get-Acl -LiteralPath $prepared).Sddl -eq $aclBefore) 'prepare existing root no overwrite or ACL repair'
    Assert-Contract ($retry -notmatch 'PREPARED_ROOT ') 'failed prepare never claims successful preparation'
    # Re-run real internal contracts on another new root (never the future UAC root).
    $contractRoot = Fresh-Root
    $rootStart = $script:roots.Count
    Invoke-Recorded "contract-$config" $contract @($contractRoot) | Write-Output
    $createdThisContract = @($script:roots | Select-Object -Skip $rootStart)
    $i = 0
    foreach ($existing in $createdThisContract) {
        if ((Get-Item -LiteralPath $existing -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { continue }
        # All roots below were CREATED by this invocation, including deliberately
        # nonempty / unprotected / untrusted-writer roots. Never repair their ACL.
        $sddl = (Get-Acl -LiteralPath $existing).Sddl
        $names = @(Get-ChildItem -LiteralPath $existing -Force | Sort-Object Name | Select-Object -ExpandProperty Name) -join '|'
        Invoke-Recorded "prepare-existing-contract-$config-$i" $contract @('--prepare-root',$existing) 4 | Write-Output
        Assert-Contract ((Get-Acl -LiteralPath $existing).Sddl -eq $sddl -and ((@(Get-ChildItem -LiteralPath $existing -Force | Sort-Object Name | Select-Object -ExpandProperty Name) -join '|') -eq $names)) 'prepare refuses existing fixture root without repair/mutation'
        $i++
    }
    # Independent file-ID cross-check without PInvoke: fsutil is read-only here.
    $fileIdText = Invoke-Recorded "prepared-id-$config" "$env:SystemRoot\System32\fsutil.exe" @('file','queryfileid',$prepared)
    $fileId = [regex]::Match($fileIdText, '0x([0-9a-fA-F]{32})')
    $proofId = [regex]::Match($proof, '; file_id=([0-9]+);')
    Assert-Contract ($fileId.Success -and $proofId.Success -and [UInt64]::Parse($fileId.Groups[1].Value.Substring(16), [Globalization.NumberStyles]::HexNumber) -eq [UInt64]::Parse($proofId.Groups[1].Value)) 'prepared file ID matches independent fsutil'
}
$script:roots = @($script:roots | Select-Object -Unique)
$script:roots | ConvertTo-Json | Set-Content -LiteralPath "$evidence\created-roots.json" -Encoding utf8
$script:results | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath "$evidence\commands.json" -Encoding utf8
foreach ($root in $script:roots) {
    $item = Get-Item -LiteralPath $root -Force
    if (!($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -and (Test-Path -LiteralPath "$root\diagnostic.log")) {
        Copy-Item -LiteralPath "$root\diagnostic.log" -Destination "$evidence\$([IO.Path]::GetFileName($root))-diagnostic.log"
    }
}
Get-ChildItem -LiteralPath "$TaskRoot\build\Debug","$TaskRoot\build\Release" -Filter *.exe | ForEach-Object {
    [pscustomobject]@{Path=$_.FullName; Bytes=$_.Length; SHA256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash}
} | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath "$evidence\exe-identities.json" -Encoding utf8
Get-FileHash -LiteralPath "$project\CMakeLists.txt","$project\tests\full_security_native_probe.cpp","$project\tests\full_security_native_contract_tests.cpp","$project\tests\full_security_native_validation.ps1","$project\src\deploy\deploy.cpp","$project\src\deploy\full_security_query.hpp" -Algorithm SHA256 |
    Select-Object Path,Hash | ConvertTo-Json | Set-Content -LiteralPath "$evidence\source-identities.json" -Encoding utf8
"VALIDATION assertions=$script:assertions; failed=$script:failed; roots=$($script:roots.Count); privileged_matrix=NOT_VERIFIED; cleanup=NOT_PERFORMED" |
    Tee-Object -FilePath "$evidence\summary.log" | Write-Output
if ($script:failed) { exit 1 }
