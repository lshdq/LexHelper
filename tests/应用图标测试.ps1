param(
    [Parameter(Mandatory=$true)][string]$Executable,
    [Parameter(Mandatory=$true)][string]$TemporaryDirectory
)
# TC-001/002/005. Run with pwsh 7 on x64 Windows; no production changes.
[Console]::OutputEncoding=[Text.Encoding]::UTF8
$OutputEncoding=[Text.Encoding]::UTF8
chcp 65001 | Out-Null
$ErrorActionPreference='Stop'
$exe=(Resolve-Path -LiteralPath $Executable).Path
$root=[IO.Path]::GetFullPath($TemporaryDirectory).TrimEnd('\')
if(-not $root.StartsWith('D:\temp\aiRunner\opencode\',[StringComparison]::OrdinalIgnoreCase)) {throw 'Unsafe test directory'}
if(-not (Test-Path -LiteralPath $root -PathType Container)) {throw 'Create test directory first'}
$cursor=Get-Item -LiteralPath $root
while($null -ne $cursor) {if($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) {throw 'Reparse ancestor forbidden'};$cursor=$cursor.Parent}
if(-not [Environment]::Is64BitProcess) {throw 'Run this probe in x64 pwsh'}
$env:TEMP=$root;$env:TMP=$root
Get-ChildItem Env: | Where-Object Name -Match '^LEXHELPER_.*SAMPLE$' | ForEach-Object {Remove-Item -LiteralPath "Env:$($_.Name)"}
Add-Type -Path (Join-Path $PSScriptRoot '应用图标探针.cs')
Add-Type -Path (Join-Path $PSScriptRoot 'gui_native.cs')
. (Join-Path $PSScriptRoot 'gui_support.ps1')
function Assert([bool]$Condition,[string]$Message) {if(-not $Condition) {throw $Message}}
function U16([byte[]]$Data,[int]$Offset) {return [BitConverter]::ToUInt16($Data,$Offset)}
function U32([byte[]]$Data,[int]$Offset) {return [BitConverter]::ToUInt32($Data,$Offset)}
function Hash([byte[]]$Data) {return [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($Data))}
$repo=Split-Path -Parent $PSScriptRoot
$results=[Collections.Generic.List[object]]::new()
$frames=[Collections.Generic.List[object]]::new()
$failure=$null;$session=$null;$record=$null;$cleanup=$null
try {
    [byte[]]$ico=[IO.File]::ReadAllBytes((Join-Path $repo 'resources\app.ico'))
    $sizes=@(16,20,24,32,40,48,64,128,256)
    Assert ($ico.Length -ge 150 -and (U16 $ico 0) -eq 0 -and (U16 $ico 2) -eq 1 -and (U16 $ico 4) -eq 9) 'ICO header/count'
    $end=150
    for($i=0;$i -lt 9;$i++) {
        $p=6+16*$i;$size=$sizes[$i];$dimension=if($size -eq 256){0}else{$size}
        $length=U32 $ico ($p+8);$offset=U32 $ico ($p+12)
        $stride=[int]([Math]::Ceiling($size/32.0)*4)
        Assert ($ico[$p] -eq $dimension -and $ico[$p+1] -eq $dimension -and (U16 $ico ($p+4)) -eq 1 -and (U16 $ico ($p+6)) -eq 32) "ICO directory $size"
        Assert ($offset -eq $end -and $length -eq 40+4*$size*$size+$stride*$size -and [long]$offset+$length -le $ico.Length) "ICO bounds $size"
        Assert ((U32 $ico $offset) -eq 40 -and (U32 $ico ($offset+4)) -eq $size -and (U32 $ico ($offset+8)) -eq $size*2 -and (U16 $ico ($offset+12)) -eq 1 -and (U16 $ico ($offset+14)) -eq 32 -and (U32 $ico ($offset+16)) -eq 0) "DIB header $size"
        $transparent=0;$opaque=0;$partial=0;$blue=0;$light=0
        for($y=0;$y -lt $size;$y++) {for($x=0;$x -lt $size;$x++) {
            $pixel=$offset+40+4*($y*$size+$x);$alpha=$ico[$pixel+3]
            if($alpha -eq 0){$transparent++}elseif($alpha -eq 255){$opaque++}else{$partial++}
            if($alpha -gt 200 -and $ico[$pixel] -gt $ico[$pixel+2]+40){$blue++}
            if($alpha -gt 200 -and $ico[$pixel] -gt 220 -and $ico[$pixel+1] -gt 220 -and $ico[$pixel+2] -gt 220){$light++}
            $mask=$ico[$offset+40+4*$size*$size+$y*$stride+[int][Math]::Floor($x/8)] -band (0x80 -shr ($x%8))
            Assert (($mask -ne 0) -eq ($alpha -eq 0)) "AND/alpha mask mismatch $size"
        }}
        Assert ($transparent -gt 0 -and $opaque -gt 0 -and $partial -gt 0 -and $blue -gt 0 -and $light -gt 0) "Transparency/blue/light pixels $size"
        $data=[byte[]]$ico[$offset..($offset+$length-1)]
        $frames.Add([pscustomobject]@{Size=$size;Length=$length;Hash=(Hash $data);Transparent=$transparent;Opaque=$opaque;Partial=$partial;Blue=$blue;Light=$light})
        $end=$offset+$length
    }
    Assert ($end -eq $ico.Length) 'ICO trailing bytes'
    $results.Add([pscustomobject]@{Name='ICO nine dimensions, bounds, DIB, transparency and masks';Result='PASS';Frames=$frames})
    $generatedHashes=@()
    foreach($iteration in @(1,2)) {
        $generated=Join-Path $root "generated-icon-$iteration.ico"
        & (Join-Path $repo 'resources\生成图标.ps1') -OutputPath $generated | Out-Null
        $generatedHashes+=(Get-FileHash -LiteralPath $generated -Algorithm SHA256).Hash
    }
    Assert ($generatedHashes[0] -eq (Hash $ico) -and $generatedHashes[1] -eq (Hash $ico)) 'Icon generation not reproducible'
    $results.Add([pscustomobject]@{Name='Two local geometric generations byte-identical to checked-in ICO';Result='PASS';SHA256=$generatedHashes[0]})
    [byte[]]$group=[LexHelperIconTest.Native]::Resource($exe,14,101)
    Assert ($group.Length -eq 132 -and (U16 $group 0) -eq 0 -and (U16 $group 2) -eq 1 -and (U16 $group 4) -eq 9) 'RT_GROUP_ICON header'
    $ids=[Collections.Generic.HashSet[int]]::new()
    for($i=0;$i -lt 9;$i++) {
        $p=6+14*$i;$id=U16 $group ($p+12);$frame=$frames[$i]
        Assert ($ids.Add($id)) 'Duplicate RT_ICON id'
        Assert ($group[$p] -eq $ico[6+16*$i] -and $group[$p+1] -eq $ico[7+16*$i] -and (U16 $group ($p+4)) -eq 1 -and (U16 $group ($p+6)) -eq 32 -and (U32 $group ($p+8)) -eq $frame.Length) 'Group dimensions/format/size'
        Assert ((Hash ([LexHelperIconTest.Native]::Resource($exe,3,$id))) -eq $frame.Hash) "RT_ICON payload $($frame.Size)"
        $loaded=[LexHelperIconTest.Native]::Loaded($exe,$frame.Size,$frame.Size,$false)
        Assert ($loaded.Width -eq $frame.Size -and $loaded.Height -eq $frame.Size) 'LoadImage dimensions'
        Assert ($loaded.Pixels -ne [LexHelperIconTest.Native]::Loaded($exe,$frame.Size,$frame.Size,$true).Pixels) 'Icon equals system default'
    }
    [byte[]]$manifest=[LexHelperIconTest.Native]::Resource($exe,24,1)
    Assert ((Hash $manifest) -eq (Hash ([IO.File]::ReadAllBytes((Join-Path $repo 'resources\app.manifest'))))) 'Embedded manifest differs from source'
    [xml]$xml=[Text.Encoding]::UTF8.GetString($manifest)
    $privilege=$xml.SelectSingleNode("//*[local-name()='requestedExecutionLevel']")
    Assert ($privilege.level -eq 'asInvoker' -and $privilege.uiAccess -eq 'false') 'Manifest privilege changed'
    Assert ($xml.SelectSingleNode("//*[local-name()='dpiAwareness']").InnerText -eq 'PerMonitorV2') 'DPI awareness changed'
    $results.Add([pscustomobject]@{Name='EXE group and nine exact payloads, LoadImage/nondefault, unchanged manifest/asInvoker/PerMonitorV2';Result='PASS'})
    $dpiLoads=[Collections.Generic.List[object]]::new()
    foreach($testDpi in @(96,120,144,168,192,240,288)) {
        foreach($small in @($false,$true)) {
            $width=[LexHelperIconTest.Native]::GetSystemMetricsForDpi($(if($small){49}else{11}),$testDpi)
            $height=[LexHelperIconTest.Native]::GetSystemMetricsForDpi($(if($small){50}else{12}),$testDpi)
            $loaded=[LexHelperIconTest.Native]::Loaded($exe,$width,$height,$false)
            Assert ($loaded.Width -eq $width -and $loaded.Height -eq $height) 'DPI resource load dimensions'
            $dpiLoads.Add([pscustomobject]@{Dpi=$testDpi;Small=$small;Width=$width;Height=$height})
        }
    }
    $results.Add([pscustomobject]@{Name='Explicit LoadImage sizes for 96/120/144/168/192/240/288 DPI (not cross-monitor runtime)';Result='PASS';Loads=$dpiLoads})
    $session=[LexHelperGuiTest.Session]::new($exe,$root,$false)
    $record=Save-GuiOriginalIdentity $session $root
    $session.InitializeWindow()
    Assert (-not $session.Elevated()) 'Expected ordinary non-elevated GUI'
    $timer=[Diagnostics.Stopwatch]::StartNew()
    while(-not ($session.MainEnabled() -and $session.Enabled(1001) -and -not $session.Text($session.Main).Contains('[处理中]'))) {
        if($timer.ElapsedMilliseconds -ge 15000){throw 'First ready timeout'}
        if($session.Process.WaitForExit(25)){throw 'GUI exited before ready'}
    }
    Assert-GuiFirstReadyCommands $session
    $dpi=$session.Dpi();Assert ($dpi -gt 0) 'No window DPI'
    $icons=[Collections.Generic.List[object]]::new()
    foreach($small in @($false,$true)) {
        $width=[LexHelperIconTest.Native]::GetSystemMetricsForDpi($(if($small){49}else{11}),$dpi)
        $height=[LexHelperIconTest.Native]::GetSystemMetricsForDpi($(if($small){50}else{12}),$dpi)
        $expected=[LexHelperIconTest.Native]::Loaded($exe,$width,$height,$false)
        $actual=[LexHelperIconTest.Native]::WindowIcon($session.Main,$small,$false)
        Assert ($actual.Width -eq $width -and $actual.Height -eq $height -and $actual.Pixels -eq $expected.Pixels) 'WM_GETICON pixel/DPI mismatch'
        $class=[LexHelperIconTest.Native]::WindowIcon($session.Main,$small,$true)
        Assert ($class.Pixels -eq [LexHelperIconTest.Native]::Loaded($exe,$class.Width,$class.Height,$false).Pixels) 'Class icon mismatch'
        $icons.Add([pscustomobject]@{Small=$small;Width=$width;Height=$height;Pixels=$actual.Pixels;ClassWidth=$class.Width;ClassHeight=$class.Height})
    }
    $userBefore=[LexHelperIconTest.Native]::GetGuiResources($session.Process.Handle,1)
    $gdiBefore=[LexHelperIconTest.Native]::GetGuiResources($session.Process.Handle,0)
    for($i=0;$i -lt 30;$i++) {
        # Validate retained-process identity before each owned-window action.
        [void]$session.Dpi()
        [LexHelperIconTest.Native]::ReloadOwnedWindow($session.Main,$session.Process.Id)
        foreach($icon in $icons) {
            $actual=[LexHelperIconTest.Native]::WindowIcon($session.Main,$icon.Small,$false)
            Assert ($actual.Width -eq $icon.Width -and $actual.Height -eq $icon.Height -and $actual.Pixels -eq $icon.Pixels) 'Reload damaged icon'
        }
    }
    $userAfter=[LexHelperIconTest.Native]::GetGuiResources($session.Process.Handle,1)
    $gdiAfter=[LexHelperIconTest.Native]::GetGuiResources($session.Process.Handle,0)
    Assert ($userBefore -gt 0 -and $gdiBefore -gt 0 -and $userAfter -le $userBefore+2 -and $gdiAfter -le $gdiBefore+2) 'Icon reload resource growth'
    $results.Add([pscustomobject]@{Name='Owned ordinary GUI, class and WM_GETICON pixels at actual DPI, 30 reloads';Result='PASS';Dpi=$dpi;Icons=$icons;UserBefore=$userBefore;UserAfter=$userAfter;GdiBefore=$gdiBefore;GdiAfter=$gdiAfter})
    $session.Close()
    Assert ($session.Process.WaitForExit(15000)) 'WM_CLOSE did not exit (never force kill)'
    Assert ($session.Process.ExitCode -eq 0) 'Nonzero GUI exit'
    $results.Add([pscustomobject]@{Name='Normal WM_CLOSE exit';Result='PASS';ExitCode=$session.Process.ExitCode})
} catch {$failure=$_.Exception.Message} finally {
    if($null -ne $session) {
        try {
            $cleanup=$session.CloseNormally(15000,$false)
            if($record) {$record.Cleanup=$cleanup;$record | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $record.IdentityFile -Encoding utf8}
            if($cleanup.State -ne 'Exited') {$failure="Owned process remains: $($cleanup.State); $failure"}
        } catch {$failure="Cleanup: $($_.Exception.Message); $failure"} finally {$session.Dispose()}
    }
}
$report=[pscustomobject]@{Result=$(if($failure){'FAIL'}else{'PASS'});Failure=$failure;Executable=$exe;SHA256=(Get-FileHash -LiteralPath $exe).Hash;Checks=$results;Cleanup=$cleanup;SystemDeployment='NOT EXECUTED';VisualInspection='NOT EXECUTED';CrossMonitorDpiChange='NOT EXECUTED; theme reload exercises same icon replacement helper'}
$report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $root '应用图标测试结果.json') -Encoding utf8
$report | ConvertTo-Json -Depth 12
if($failure){exit 1}
