# Exact-list cleanup of THIS independent test only, after persistent evidence.
# Does not scan the shared temporary area, change ACLs, or traverse junctions.
[CmdletBinding()]
param([Parameter(Mandatory)][string]$TaskRoot, [Parameter(Mandatory)][string]$EvidenceDir, [switch]$Apply, [switch]$Resume)
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 | Out-Null
if ($TaskRoot -cnotmatch '^D:\\temp\\aiRunner\\opencode\\LexHelper-test-adminprobe-[0-9]{14}-[0-9a-f]{8}$') { throw 'Invalid task boundary' }
if ($EvidenceDir -cne 'D:\works\LexHelper\.localdoc\测试报告\独立测试-管理员临时诊断') { throw 'Invalid evidence boundary' }
if ((Get-Content -LiteralPath "$EvidenceDir\task-root.txt" -Raw).Trim() -cne $TaskRoot) { throw 'Wrong task ownership record' }
if (!(Test-Path -LiteralPath "$EvidenceDir\final\summary.log")) { throw 'Persist evidence first' }
$user = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
function Check-Ancestors([string]$Path, [bool]$IncludeSelf = $true) {
    $p = if ($IncludeSelf) { $Path } else { [IO.Path]::GetDirectoryName($Path) }
    while ($p) {
        if ((Get-Item -LiteralPath $p -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Reparse ancestor refused: $p" }
        $parent = [IO.Directory]::GetParent($p); $p = if ($parent) { $parent.FullName } else { $null }
    }
}
Check-Ancestors $EvidenceDir
$roots = @($TaskRoot)
foreach ($stage in @('attempt1','attempt2','final')) {
    $directory = "$EvidenceDir\$stage"
    if (!(Test-Path -LiteralPath $directory)) { continue }
    if (Test-Path -LiteralPath "$directory\created-roots.json") {
        $roots += @(Get-Content -LiteralPath "$directory\created-roots.json" -Raw | ConvertFrom-Json)
    }
    foreach ($log in Get-ChildItem -LiteralPath $directory -Filter 'LastTest-*.log') {
        foreach ($match in [regex]::Matches([IO.File]::ReadAllText($log.FullName), '(?m)^Sandbox: (D:\\temp\\aiRunner\\opencode\\LexHelper-deploy-tests-[0-9a-f]{32})\r?$')) { $roots += $match.Groups[1].Value }
    }
}
$roots = @($roots | Sort-Object -Unique)
foreach ($root in $roots) {
    if ([IO.Path]::GetFullPath($root) -cne $root -or ($root -cne $TaskRoot -and $root -cnotmatch '^D:\\temp\\aiRunner\\opencode\\LexHelper-(admin-fullsecurity|deploy-tests)-[0-9a-f]{32}$')) { throw 'Unrecorded / noncanonical boundary' }
}
$origin = $null
if ($Resume) {
    if (!(Test-Path -LiteralPath "$EvidenceDir\cleanup-original-plan.json") -or !(Test-Path -LiteralPath "$EvidenceDir\cleanup-partial-differences.json")) { throw 'Explicit partial-cleanup evidence required for resume' }
    $origin = @(Get-Content -LiteralPath "$EvidenceDir\cleanup-original-plan.json" -Raw | ConvertFrom-Json)
    $known = @($origin.Path)
    $roots = @($roots | Where-Object {
        if (Test-Path -LiteralPath $_) { $true }
        elseif ($known -ccontains $_) { [Console]::WriteLine("ALREADY_REMOVED_OWN_ROOT $_") }
        else { throw 'Missing root not in original owned manifest' }
    })
}
foreach ($process in Get-Process) {
    $path = $null
    try { $path = $process.Path } catch { continue }
    if ($path) { foreach ($root in $roots) { if ($path.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw "Active executable inside task boundary: $root" } } }
}
function Owner-IsCurrent([string]$Path) {
    $owner = (Get-Acl -LiteralPath $Path).GetOwner([Security.Principal.SecurityIdentifier]).Value
    if ($owner -ne $user) { throw "Owner not current user (no take-over): $Path" }
}
function File-Row([IO.FileSystemInfo]$Item) {
    $stream = [IO.File]::Open($Item.FullName, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::None)
    try { $hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($stream)); $bytes = $stream.Length }
    finally { $stream.Dispose() }
    return [pscustomobject]@{Path=$Item.FullName; Kind='File'; Attributes=[long]$Item.Attributes; Bytes=$bytes; SHA256=$hash; Target=''}
}
function Junction-Target([IO.FileSystemInfo]$Item) {
    if ($Item.LinkType -ne 'Junction') { throw 'Only this suite documented root junctions may be unlinked' }
    $target = [string]$Item.LinkTarget
    if ($target.StartsWith('\??\')) { $target = $target.Substring(4) }
    if ($roots -cnotcontains $target) { throw 'Junction does not target another exact recorded own root' }
    return $target
}
function Make-Manifest {
    $rows = [Collections.Generic.List[object]]::new()
    foreach ($root in $roots) {
        Check-Ancestors $root $false
        $item = Get-Item -LiteralPath $root -Force
        Owner-IsCurrent $root
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
            # Do NOT enumerate it. Delete only this root junction object later.
            $rows.Add([pscustomobject]@{Path=$root; Kind='RootJunction'; Attributes=[long]$item.Attributes; Bytes=0; SHA256=''; Target=(Junction-Target $item)})
            continue
        }
        $pending = [Collections.Generic.Stack[IO.FileSystemInfo]]::new(); $pending.Push($item)
        while ($pending.Count) {
            $node = $pending.Pop()
            if ($node.FullName -cne $root -and !$node.FullName.StartsWith($root + '\', [StringComparison]::OrdinalIgnoreCase)) { throw 'Traversal boundary escaped' }
            if ($node.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw "Unexpected descendant reparse point: $($node.FullName)" }
            Owner-IsCurrent $node.FullName
            if ($node.PSIsContainer) {
                $rows.Add([pscustomobject]@{Path=$node.FullName; Kind='Directory'; Attributes=[long]$node.Attributes; Bytes=0; SHA256=''; Target=''})
                foreach ($child in Get-ChildItem -LiteralPath $node.FullName -Force) { $pending.Push($child) }
            } else { $rows.Add((File-Row $node)) }
        }
    }
    return @($rows | Sort-Object Path)
}
$manifest = @(Make-Manifest)
if ($Resume) {
    $byPath = @{}; foreach ($row in $origin) { $byPath[$row.Path] = $row }
    foreach ($row in $manifest) {
        if (!$byPath.ContainsKey($row.Path)) { throw 'New unexpected object after partial cleanup' }
        $was = $byPath[$row.Path]
        if ($was.Kind -cne $row.Kind -or $was.SHA256 -cne $row.SHA256 -or $was.Bytes -ne $row.Bytes -or $was.Target -cne $row.Target) { throw 'Object changed since original cleanup proof' }
        # Clearing a READONLY bit on one own hardlink changes its sibling names.
        # Only this one-way bit removal is permitted; no ACL repair or hash drift.
        if (($row.Attributes -bor $was.Attributes) -ne $was.Attributes -or
            (($row.Attributes -bxor $was.Attributes) -band (-bnot [long][IO.FileAttributes]::ReadOnly))) { throw 'Unexplained attributes after partial cleanup' }
    }
}
$text = ConvertTo-Json -InputObject $manifest -Depth 5 -Compress
$hash = [Convert]::ToHexString([Security.Cryptography.SHA256]::HashData([Text.Encoding]::UTF8.GetBytes($text)))
$bytes = ($manifest | Measure-Object -Property Bytes -Sum).Sum
$summary = [pscustomobject]@{Roots=$roots.Count; Files=@($manifest | Where-Object Kind -eq 'File').Count; Directories=@($manifest | Where-Object Kind -eq 'Directory').Count; RootJunctions=@($manifest | Where-Object Kind -eq 'RootJunction').Count; Bytes=$bytes; ManifestSHA256=$hash; Stage=$(if($Apply){'apply-precheck'}else{'plan'}); ACLChanges=0}
if (!$Apply) {
    [IO.File]::WriteAllText("$EvidenceDir\cleanup-plan.json", $text, [Text.UTF8Encoding]::new($false))
    $roots | ConvertTo-Json | Set-Content -LiteralPath "$EvidenceDir\cleanup-roots.json" -Encoding utf8
    $summary | ConvertTo-Json | Set-Content -LiteralPath "$EvidenceDir\cleanup-plan-summary.json" -Encoding utf8
    $summary | Format-List
    return
}
$old = [IO.File]::ReadAllText("$EvidenceDir\cleanup-plan.json")
if ($old -cne $text) { throw 'Manifest changed since plan; no deletion performed' }
# Evidence, owners, no activity, exclusive opens and full hashes were rechecked.
foreach ($link in $manifest | Where-Object Kind -eq 'RootJunction') {
    Check-Ancestors $link.Path $false
    $item = Get-Item -LiteralPath $link.Path -Force
    if (!(($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -and (Junction-Target $item) -ceq $link.Target)) { throw 'Junction changed before unlink' }
    [IO.Directory]::Delete($link.Path, $false) # unlink only; never traverse target
}
$readonlyCleared = 0
foreach ($file in $manifest | Where-Object Kind -eq 'File') {
    Check-Ancestors $file.Path
    $actual = File-Row (Get-Item -LiteralPath $file.Path -Force)
    if ($actual.SHA256 -cne $file.SHA256 -or $actual.Bytes -ne $file.Bytes -or
        ($actual.Attributes -bor $file.Attributes) -ne $file.Attributes -or
        (($actual.Attributes -bxor $file.Attributes) -band (-bnot [long][IO.FileAttributes]::ReadOnly))) { throw "File changed before exact delete: $($file.Path)" }
    if ($actual.Attributes -band [long][IO.FileAttributes]::ReadOnly) {
        [IO.File]::SetAttributes($file.Path, [IO.FileAttributes]($actual.Attributes -band (-bnot [long][IO.FileAttributes]::ReadOnly)))
        $readonlyCleared++ # Only this suite's exact self-created fixture, not ACL.
    }
    [IO.File]::Delete($file.Path)
}
foreach ($directory in $manifest | Where-Object Kind -eq 'Directory' | Sort-Object { $_.Path.Length } -Descending) {
    Check-Ancestors $directory.Path
    [IO.Directory]::Delete($directory.Path, $false) # empty-only, never recursive
}
foreach ($root in $roots) { if (Test-Path -LiteralPath $root) { throw "Residual task root: $root" } }
$summary.Stage = 'complete'; $summary | Add-Member NoteProperty ReadOnlyFixtureFlagsCleared $readonlyCleared
$summary | ConvertTo-Json | Set-Content -LiteralPath "$EvidenceDir\cleanup-result.json" -Encoding utf8
$summary | Format-List
