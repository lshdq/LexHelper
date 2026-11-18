param(
    [Parameter(Mandatory=$true)][string]$Executable,
    [Parameter(Mandatory=$true)][string]$TemporaryDirectory,
    [Parameter(Mandatory=$true)][string]$EvidenceDirectory,
    [switch]$Interactive
)
# Default is minimized/no-activation, read-only startup/close, no dialogs. -Interactive explicitly
# opts into necessary native open/save/unsaved dialogs, which can temporarily take foreground.
# No TOPMOST/SetForegroundWindow/global SendKeys, system operations, UAC, IME or force-kill.
$ErrorActionPreference='Stop'
[Console]::OutputEncoding=[System.Text.Encoding]::UTF8
$OutputEncoding=[System.Text.Encoding]::UTF8
chcp 65001 | Out-Null
$root=[IO.Path]::GetFullPath($TemporaryDirectory).TrimEnd('\')
if (-not $root.StartsWith('D:\temp\aiRunner\opencode\',[StringComparison]::OrdinalIgnoreCase)) {throw 'Unsafe temporary root'}
if (-not (Test-Path -LiteralPath $root -PathType Container)) {throw 'Create the task-specific temporary root first'}
$cursor=Get-Item -LiteralPath $root
while ($null -ne $cursor) {if ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint) {throw 'Reparse ancestor forbidden'}; $cursor=$cursor.Parent}
$exe=(Resolve-Path -LiteralPath $Executable).Path
$evidence=[IO.Path]::GetFullPath($EvidenceDirectory)
$run=Join-Path $root ('run-'+[guid]::NewGuid().ToString('N').Substring(0,8))
[void](New-Item -ItemType Directory -Path $run)
[void](New-Item -ItemType Directory -Force -Path $evidence)
$oldTemp=$env:TEMP; $oldTmp=$env:TMP; $env:TEMP=$run; $env:TMP=$run
$results=[Collections.Generic.List[object]]::new()
$processRecords=[Collections.Generic.List[object]]::new()
$session=$null; $failure=$null; $alive=$null
$processRecord=$null
$actions=[Collections.Generic.List[object]]::new()
$failureSnapshot=$null
$startedAt=Get-Date
. (Join-Path $PSScriptRoot 'gui_support.ps1')
function Assert($condition,[string]$message) { if (-not $condition) {throw $message} }
function Wait-Until([scriptblock]$condition,[string]$description,[int]$milliseconds=15000) {
    $timer=[Diagnostics.Stopwatch]::StartNew()
    do { if (& $condition) {return}; Start-Sleep -Milliseconds 25 } while($timer.ElapsedMilliseconds -lt $milliseconds)
    throw "Timeout: $description"
}
function Record([string]$name,$detail) { $results.Add([pscustomobject]@{Name=$name;Result='PASS';Detail=$detail}) }
function Find-Dialog([string]$prefix) {
    if($session.Process.HasExited) {return $null}
    @($session.Windows() | Where-Object {$_.Class -eq '#32770' -and $_.Text.StartsWith($prefix)}) | Select-Object -First 1
}
function Wait-Dialog([string]$prefix) { Wait-Until { $null -ne (Find-Dialog $prefix) } "dialog $prefix"; return (Find-Dialog $prefix) }
function Ready { Wait-Until { $session.MainEnabled() -and $session.Enabled(1001) -and -not $session.Text($session.Main).Contains('[处理中]') } 'GUI ready' }
function Select-File([string]$prefix,[string]$path) {
    $actions.Add([pscustomobject]@{Action='SelectFile';Prefix=$prefix;FixturePath=$path;Utc=[DateTime]::UtcNow.ToString('o')})
    $dialog=Wait-Dialog $prefix
    $session.FileName($dialog.Handle,$path)
    $session.DialogButton($dialog.Handle,1)
    Wait-Until { $null -eq (Find-Dialog $prefix) } 'file dialog closed'
}
function Unsaved([int]$choice) {
    $dialog=Wait-Dialog 'LexHelper — 码表尚未另存'
    $session.DialogButton($dialog.Handle,$choice)
    Wait-Until { $null -eq (Find-Dialog 'LexHelper — 码表尚未另存') } 'unsaved dialog closed'
}
function Assert-LoadedCommands {
    foreach($id in @(1001,1002,1102,1103,1104)) {
        Assert ($session.Enabled($id) -and $session.MenuEnabled($id)) "Ready loaded model command button/menu disabled: $id"
    }
}
function Save-New([string]$name) {
    $target=Join-Path $run $name
    $session.Command(1002); Select-File '另存为新 lex：' $target; Ready
    Assert (Test-Path -LiteralPath $target -PathType Leaf) 'Save did not create lex'
    Assert (-not $session.Text($session.Main).Contains('未另存')) 'Successful save did not clear dirty marker'
    Assert-LoadedCommands
    return $target
}
function Import([string]$path,[int]$count) {
    $session.Command(1001); Select-File '打开码表：' $path; Ready
    Assert ($session.Count() -eq $count) "Wrong imported record count; expected $count"
    Assert-LoadedCommands
}
try {
    if(-not ('LexHelperGuiTest.Session' -as [type])) {Add-Type -Path (Join-Path $PSScriptRoot 'gui_native.cs')}
    $fixture=Join-Path $run '合成中文码表.txt'
    [IO.File]::WriteAllText($fixture,"a`t我`t100`na`t我们`t10`ntrxy`t中国`t30`nz`t$([char]::ConvertFromUtf32(0x20000))`t5`n",[Text.UTF8Encoding]::new($false))
    $bad=Join-Path $run '合成错误.txt'
    [IO.File]::WriteAllText($bad,"a`t新`nINVALID`n",[Text.UTF8Encoding]::new($false))
    $second=Join-Path $run '合成第二表.txt'
    [IO.File]::WriteAllText($second,"b`t测试`n",[Text.UTF8Encoding]::new($false))
    $session=[LexHelperGuiTest.Session]::new($exe,$run,[bool]$Interactive)
    $processRecord=Save-GuiOriginalIdentity $session $evidence;$processRecords.Add($processRecord)
    $session.InitializeWindow()
    $ownedPid=$session.Process.Id; Ready
    Assert-GuiFirstReadyCommands $session
    Record 'first Ready read-only backup/restore and empty save/install commands' @{BackupRestoreEnabled=$true;SaveInstallDisabled=$true;ButtonsAndMenus=$true;SystemCommandsClicked=$false}
    $manifest=$session.Manifest()
    Assert ($manifest.Contains('asInvoker') -and $manifest.Contains('PerMonitorV2')) 'Embedded manifest privilege/DPI contract missing'
    Record 'embedded manifest and actual token' @{ExecutionLevel='asInvoker';DpiAwareness='PerMonitorV2';TokenElevated=$session.Elevated()}
    Assert ($session.Count() -eq 0) 'Expected empty ListView'
    Assert (-not $session.Enabled(1002) -and -not $session.Enabled(1103)) 'Save/install should be disabled for empty model'
    Assert (($session.Style($session.Main) -band 0x000F0000) -eq 0x000F0000) 'Native style flags missing'
    Assert ($session.Text($session.Control(2004)).Contains('尚未导入码表')) 'Chinese empty state missing'
    Record 'empty/native/Unicode labels' @{ProcessId=$ownedPid;Dpi=$session.Dpi();PreviewCount=0}

    if(-not $Interactive) {
        Assert ($session.Minimized() -and $session.Visible()) 'Expected a visible minimized native window'
        Assert (-not $session.ForegroundIsOwn()) 'Default launch unexpectedly became foreground'
        Record 'default minimized/no-activation' @{Minimized=$true;OwnForeground=$false;NativeShow='SW_SHOWMINNOACTIVE';Dialogs='NOT EXECUTED'}
        $session.Close()
        Assert ($session.Process.WaitForExit(15000) -and $session.Process.ExitCode -eq 0) 'Default minimized normal-close failed'
        Record 'default minimized normal-close' @{ProcessId=$ownedPid;ExitCode=$session.Process.ExitCode}
    } else {
    $session.MinimumSize(); Start-Sleep -Milliseconds 100
    $client=$session.Client(); $preview=$session.Bounds($session.Control(2005)); $log=$session.Bounds($session.Control(2007))
    Assert ($client.Right -ge (840*$session.Dpi()/96) -and $client.Bottom -ge (570*$session.Dpi()/96)) 'Minimum client size incorrect'
    Assert ($preview.Right -gt $preview.Left -and $preview.Bottom -gt $preview.Top -and $log.Top -gt $preview.Bottom) 'Minimum preview/log layout overlaps'
    Record 'minimum window at actual DPI' @{ClientWidth=$client.Right;ClientHeight=$client.Bottom;Dpi=$session.Dpi()}
    $focusBefore=$session.FocusId();$session.Tab();Start-Sleep -Milliseconds 100;$focusAfter=$session.FocusId()
    Assert ($focusAfter -ne 0 -and $focusAfter -ne $focusBefore) 'Targeted Tab did not move own GUI focus'
    Record 'targeted Tab message' @{Before=$focusBefore;After=$focusAfter;GlobalKeyboardInjection=$false}

    $session.Command(1001); $dialog=Wait-Dialog '打开码表：'
    Assert ($dialog.Class -eq '#32770') 'Open is not native dialog'
    $session.DialogButton($dialog.Handle,2); Ready
    Assert ($session.Count() -eq 0) 'Cancel open modified empty model'
    Record 'standard open dialog/cancel' 'Native #32770; cancel retained empty model'
    Import $fixture 4
    Assert ($session.Text($session.Main).Contains('未另存')) 'Import did not set dirty marker'
    Assert ($session.Text($session.Control(2004)).Contains('单 Unicode 字符 2')) 'Unicode scalar statistics incorrect'
    Record 'loaded model command buttons and menus are synchronized' @{SaveInstallEnabled=$true;BackupRestoreEnabled=$true;SystemCommandsClicked=$false}
    Record 'synthetic Chinese import' @{Count=4;Dirty=$true;SupplementaryCharacter=$true;Document=$session.Text($session.Control(2004))}

    # MSAA/Win32 read-only queries, scoped to the known preview/header HWNDs.
    # Capability detection returns explicit per-field status. No catch surrounds assertions:
    # readable-but-wrong results MUST reach the suite FAIL/nonzero exit path.
    $probe=$session.ProbePreviewAccessibility()
    # Keep the raw capability/value evidence even when a readable semantic field fails.
    $probe | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath (Join-Path $evidence 'msaa-probe.json') -Encoding utf8
    foreach($check in @(Get-GuiMsaaChecks $probe @('我','我们','中国',[char]::ConvertFromUtf32(0x20000)))) {$results.Add($check)}
    try {
        Add-Type -AssemblyName System.Drawing
        $bounds=$session.Bounds($session.Control(2005))
        $bitmap=[Drawing.Bitmap]::new($bounds.Right-$bounds.Left,$bounds.Bottom-$bounds.Top)
        try {
            $graphics=[Drawing.Graphics]::FromImage($bitmap)
            try {$dc=$graphics.GetHdc();try {$session.PrintPreview($dc)}finally {$graphics.ReleaseHdc($dc)}}finally {$graphics.Dispose()}
            $bitmap.Save((Join-Path $evidence 'preview.png'),[Drawing.Imaging.ImageFormat]::Png)
        }finally {$bitmap.Dispose()}
        Record 'own fixture preview capture' 'preview.png; only own ListView client; visual validation recorded separately'
    }catch {$results.Add([pscustomobject]@{Name='own fixture preview capture';Result='NOT EXECUTED';Detail=$_.Exception.Message})}

    $session.Command(1002); $dialog=Wait-Dialog '另存为新 lex：';$session.DialogButton($dialog.Handle,2);Ready
    Assert ($session.Count() -eq 4 -and $session.Text($session.Main).Contains('未另存')) 'Cancel save lost model/dirty'
    Record 'save cancel' 'Model and dirty state retained'
    $existing=Join-Path $run '不得覆盖.lex';[IO.File]::WriteAllText($existing,'GUI sentinel',[Text.UTF8Encoding]::new($false));$before=(Get-FileHash -LiteralPath $existing).Hash
    $session.Command(1002);Select-File '另存为新 lex：' $existing
    $dialog=Wait-Dialog 'LexHelper — 操作未成功';$session.DialogButton($dialog.Handle,1);Ready
    Assert ((Get-FileHash -LiteralPath $existing).Hash -eq $before) 'Existing file changed'
    Assert ($session.Count() -eq 4 -and $session.Text($session.Main).Contains('未另存')) 'Failed save changed model/dirty'
    Record 'reject existing save' @{UnchangedHash=$before;DirtyRetained=$true}

    $saved=Save-New '首次另存.lex';Record 'save new lex' @{Bytes=(Get-Item -LiteralPath $saved).Length;Hash=(Get-FileHash -LiteralPath $saved).Hash}
    $oldDocument=$session.Text($session.Control(2004))
    $session.Command(1001);Select-File '打开码表：' $bad
    $dialog=Wait-Dialog 'LexHelper — 操作未成功';$session.DialogButton($dialog.Handle,1);Ready
    Assert ($session.Count() -eq 4 -and $session.Text($session.Control(2004)) -eq $oldDocument) 'Failed import replaced old model'
    Assert (-not $session.Text($session.Main).Contains('未另存')) 'Failed import changed old clean state'
    Record 'failed import retains old clean model' 'Malformed second line; all 4 old records retained'

    Import $fixture 4
    $session.Command(1001);Unsaved 2;Ready
    Assert ($session.Count() -eq 4 -and $session.Text($session.Main).Contains('未另存')) 'Cancel pending open changed model'
    Record 'unsaved open/cancel' 'Retained model and dirty state'
    $session.Command(1001);Unsaved 7;$dialog=Wait-Dialog '打开码表：';$session.DialogButton($dialog.Handle,2);Ready
    Assert ($session.Count() -eq 4 -and $session.Text($session.Main).Contains('未另存')) 'Cancel file selection after discard changed model unexpectedly'
    Record 'unsaved open/discard then file-dialog cancel' 'Existing in-memory model retained until replacement succeeds'
    $session.Command(1001);Unsaved 6;$dialog=Wait-Dialog '另存为新 lex：';$session.DialogButton($dialog.Handle,2);Ready
    Assert ($null -eq (Find-Dialog '打开码表：') -and $session.Count() -eq 4) 'Canceled save continued pending open'
    Record 'unsaved open/save canceled' 'Pending open not executed'
    $session.Command(1001);Unsaved 6;Select-File '另存为新 lex：' $existing
    $dialog=Wait-Dialog 'LexHelper — 操作未成功';$session.DialogButton($dialog.Handle,1);Ready
    Assert ($null -eq (Find-Dialog '打开码表：') -and $session.Count() -eq 4 -and $session.Text($session.Main).Contains('未另存')) 'Failed save continued pending open or lost dirty model'
    Record 'unsaved open/save failed' 'Existing output rejected; no pending open; dirty model retained'
    $session.Command(1001);Unsaved 7;Select-File '打开码表：' $bad
    $dialog=Wait-Dialog 'LexHelper — 操作未成功';$session.DialogButton($dialog.Handle,1);Ready
    Assert ($session.Count() -eq 4 -and $session.Text($session.Main).Contains('未另存')) 'Failed replacement import lost old dirty model'
    Record 'failed import retains old dirty model' 'Discard choice does not lose previous model when parsing replacement fails'
    $pending=Join-Path $run '打开前另存.lex'
    $session.Command(1001);Unsaved 6;Select-File '另存为新 lex：' $pending;Select-File '打开码表：' $second;Ready
    Assert ((Test-Path -LiteralPath $pending) -and $session.Count() -eq 1) 'Save/open continuation failed'
    Record 'unsaved open/save success continuation' 'Saved old table, then imported 1-record new table'
    $session.Command(1001);Unsaved 7;Select-File '打开码表：' $fixture;Ready
    Assert ($session.Count() -eq 4) 'Discard/open replacement failed'
    Record 'unsaved open/discard success' 'New model imported'

    $session.Close();Unsaved 2;Ready
    Assert (-not $session.Process.HasExited -and $session.Count() -eq 4) 'Cancel exit lost running model'
    Record 'unsaved exit/cancel' 'Process and model retained'
    $session.Close();Unsaved 6;$dialog=Wait-Dialog '另存为新 lex：';$session.DialogButton($dialog.Handle,2);Ready
    Assert (-not $session.Process.HasExited -and $session.Count() -eq 4) 'Cancel save exited unexpectedly'
    Record 'unsaved exit/save canceled' 'Process retained'
    $session.Close();Unsaved 6;Select-File '另存为新 lex：' $existing
    $dialog=Wait-Dialog 'LexHelper — 操作未成功';$session.DialogButton($dialog.Handle,1);Ready
    Assert (-not $session.Process.HasExited -and $session.Count() -eq 4 -and $session.Text($session.Main).Contains('未另存')) 'Failed save exited or lost model'
    Record 'unsaved exit/save failed' 'Process and dirty model retained'
    $exitSave=Join-Path $run '退出前另存.lex'
    $session.Close();Unsaved 6;Select-File '另存为新 lex：' $exitSave
    Assert ($session.Process.WaitForExit(15000)) 'Save-then-exit did not finish'
    Assert ($session.Process.ExitCode -eq 0 -and (Test-Path -LiteralPath $exitSave)) 'Save-then-exit failed'
    Record 'unsaved exit/save success' @{ExitCode=$session.Process.ExitCode;ProcessId=$ownedPid}
    $processRecord.Cleanup=$session.CloseNormally(1000,$false);$processRecord | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $processRecord.IdentityFile -Encoding utf8
    $session.Dispose();$session=$null;$processRecord=$null

    $session=[LexHelperGuiTest.Session]::new($exe,$run,$true)
    $processRecord=Save-GuiOriginalIdentity $session $evidence;$processRecords.Add($processRecord)
    $session.InitializeWindow();Ready;Import $fixture 4
    $discardPid=$session.Process.Id;$session.Close();Unsaved 7
    Assert ($session.Process.WaitForExit(15000) -and $session.Process.ExitCode -eq 0) 'Discard exit failed'
    Record 'unsaved exit/discard' @{ExitCode=$session.Process.ExitCode;ProcessId=$discardPid}
    $processRecord.Cleanup=$session.CloseNormally(1000,$false);$processRecord | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $processRecord.IdentityFile -Encoding utf8
    $session.Dispose();$session=$null;$processRecord=$null

    # Synthetic ~3 MiB, 150k unique rows; real core import and GUI worker, no stub/backdoor.
    $large=Join-Path $run '合成长任务.txt';$writer=[IO.StreamWriter]::new($large,$false,[Text.UTF8Encoding]::new($false))
    try {for($i=0;$i -lt 150000;$i++) {$code=[char](97+[int][Math]::Floor($i/50000));$writer.WriteLine("$code`t测试$i")}} finally {$writer.Dispose()}
    $session=[LexHelperGuiTest.Session]::new($exe,$run,$true)
    $processRecord=Save-GuiOriginalIdentity $session $evidence;$processRecords.Add($processRecord)
    $session.InitializeWindow();Ready
    $busyCheckpoints=[ordered]@{BeforeOpenUtc=[DateTime]::UtcNow.ToString('o');Rows=150000;Attempt=1;MaximumAttempts=1}
    $busyPid=$session.Process.Id;$session.Command(1001);Select-File '打开码表：' $large
    $observedBusy=$session.Text($session.Main).Contains('[处理中]')
    $busyCheckpoints.AfterDialogAndObservationUtc=[DateTime]::UtcNow.ToString('o')
    $busyCheckpoints.ProcessId=$busyPid
    if(-not $observedBusy) {
        Wait-Until { $session.MainEnabled() -and $session.Enabled(1001) -and -not $session.Text($session.Main).Contains('[处理中]') -and $session.Count() -eq 150000 } 'large fixture import completion without busy-close coverage'
        Assert ($session.Count() -eq 150000 -and $session.Text($session.Main).Contains('未另存')) 'Large fixture import did not complete with expected model'
        $busyCheckpoints.ImportCompletionVerifiedUtc=[DateTime]::UtcNow.ToString('o')
        $results.Add((Get-GuiBusyCoverageCheck $false $false $false $busyCheckpoints))
        # No busy window was observed: coverage unavailable, not a product failure or PASS.
        # The normal bounded finally cleanup handles this own dirty fixture instance.
    } else {
    Assert (-not $session.Enabled(1001) -and -not $session.Enabled(1002) -and -not $session.Enabled(1103)) 'Busy commands not disabled'
    $session.Close()
    Wait-Until { $session.Text($session.Main).Contains('[等待安全退出]') -or $null -ne (Find-Dialog 'LexHelper — 码表尚未另存') } 'deferred close observed'
    $dialog=Wait-Dialog 'LexHelper — 码表尚未另存'
    $deferredLog=$session.Text($session.Control(2007)).Contains('收到关闭请求：当前操作不可强制取消')
    Assert $deferredLog 'Busy was observed, but close was not processed/deferred while busy'
    $busyCheckpoints.DeferredCloseObservedUtc=[DateTime]::UtcNow.ToString('o')
    Unsaved 7
    $exitedNormally=$session.Process.WaitForExit(30000) -and $session.Process.ExitCode -eq 0
    $busyCheckpoints.AfterExitWaitUtc=[DateTime]::UtcNow.ToString('o')
    $results.Add((Get-GuiBusyCoverageCheck $true $deferredLog $exitedNormally $busyCheckpoints))
    }
    }
} catch {
    $failure=$_.Exception.Message
    $results.Add([pscustomobject]@{Name='suite stopped';Result='FAIL';Detail=$failure})
    if($null -ne $session -and -not $session.Process.HasExited) {
        try {
            # Own application only: no desktop capture, shell child text or user folders.
            $failureSnapshot=[pscustomobject]@{MainTitle=$session.Text($session.Main);Document=$session.Text($session.Control(2004));Log=$session.Text($session.Control(2007));Windows=@($session.Windows() | Select-Object Class,Text,Id);PreviewCount=$session.Count()}
        } catch {$failureSnapshot=[pscustomobject]@{CaptureError=$_.Exception.Message}}
    }
} finally {
    if($null -ne $session) {
        try {
            # This object exists even if InitializeWindow/Ready/identity persistence failed.
            if($null -eq $processRecord) {$processRecord=[pscustomobject]@{Identity=$session.OriginalIdentity;IdentityFile=$null;Cleanup=$null};$processRecords.Add($processRecord)}
            $processRecord.Cleanup=$session.CloseNormally(15000,[bool]$Interactive)
            if($processRecord.Cleanup.State -ne 'Exited') {$alive=$processRecord.Cleanup}
            if($null -ne $processRecord.IdentityFile) {
                try {$processRecord | ConvertTo-Json -Depth 8 | Set-Content -LiteralPath $processRecord.IdentityFile -Encoding utf8}
                catch {$failure="Identity journal update failed: $($_.Exception.Message)";$results.Add([pscustomobject]@{Name='identity journal';Result='FAIL';Detail=$failure})}
            }
        } finally {$session.Dispose()}
    }
    try {
    $sourceRoot=Split-Path -Parent $PSScriptRoot
    $report=[pscustomobject]@{StartedAt=$startedAt.ToString('o');Mode=$(if($Interactive){'Explicit interactive native dialogs; temporary foreground possible'}else{'Default minimized/no-activation; no dialogs'});Executable=$exe;SHA256=(Get-FileHash -LiteralPath $exe).Hash;GuiSourceSHA256=(Get-FileHash -LiteralPath (Join-Path $sourceRoot 'src/gui/main.cpp')).Hash;ResourceSHA256=(Get-FileHash -LiteralPath (Join-Path $sourceRoot 'resources/app.rc')).Hash;ManifestSHA256=(Get-FileHash -LiteralPath (Join-Path $sourceRoot 'resources/app.manifest')).Hash;OS=[Environment]::OSVersion.VersionString;PowerShell=$PSVersionTable.PSVersion.ToString();TemporaryDirectory=$run;Results=$results.ToArray();SkippedCount=@($results | Where-Object Result -eq 'NOT EXECUTED').Count;Processes=$processRecords.ToArray();Failure=$failure;FailureSnapshot=$failureSnapshot;Actions=$actions.ToArray();OwnProcessLeftRunning=$alive;SystemDeployment='NOT EXECUTED';Elevation='NOT EXECUTED';GlobalInput='NOT EXECUTED';Build='Caller-supplied EXE; no build or binary/source binding proved by this script'}
    $report | ConvertTo-Json -Depth 12
    $report | ConvertTo-Json -Depth 12 | Set-Content -LiteralPath (Join-Path $evidence 'results.json') -Encoding utf8
    } finally {$env:TEMP=$oldTemp;$env:TMP=$oldTmp}
}
if($null -ne $failure -or $null -ne $alive) {exit 1}
