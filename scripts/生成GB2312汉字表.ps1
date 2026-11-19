# 开发期离线生成器：只向 stdout 输出头文件；不参与 CMake/程序运行。
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 | Out-Null
$ErrorActionPreference = 'Stop'
[System.Text.Encoding]::RegisterProvider([System.Text.CodePagesEncodingProvider]::Instance)
$encoding = [System.Text.Encoding]::GetEncoding(936,
    [System.Text.EncoderFallback]::ExceptionFallback, [System.Text.DecoderFallback]::ExceptionFallback)
$members = [System.Collections.Generic.HashSet[int]]::new()
$zoneBytes = [System.Collections.Generic.List[byte]]::new()
$levels = @(0, 0)
for ($zone = 16; $zone -le 87; ++$zone) {
    $last = if ($zone -eq 55) { 89 } else { 94 }
    for ($position = 1; $position -le $last; ++$position) {
        $pair = [byte[]]@(($zone + 0xa0), ($position + 0xa0))
        $word = $encoding.GetString($pair)
        if ($word.Length -ne 1 -or [int]$word[0] -lt 0x4e00 -or [int]$word[0] -gt 0x9fff -or
            -not $members.Add([int]$word[0])) { throw 'GB2312 汉字区位重复或映射无效' }
        $zoneBytes.AddRange([System.Text.Encoding]::Unicode.GetBytes($word))
        ++$levels[[int]($zone -ge 56)]
    }
}
if ($levels[0] -ne 3755 -or $levels[1] -ne 3008 -or $members.Count -ne 6763) { throw 'GB2312 字数不符' }
$sorted = @($members | Sort-Object)
$sortedBytes = [System.Collections.Generic.List[byte]]::new()
$bits = [uint64[]]::new(328)
foreach ($scalar in $sorted) {
    $index = $scalar - 0x4e00
    $bits[[int][Math]::Floor($index / 64)] = $bits[[int][Math]::Floor($index / 64)] -bor ([uint64]1 -shl ($index % 64))
    $sortedBytes.AddRange([System.Text.Encoding]::Unicode.GetBytes([string][char]$scalar))
}
$zoneHash = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($zoneBytes.ToArray()))
$sortedHash = [Convert]::ToHexString([System.Security.Cryptography.SHA256]::HashData($sortedBytes.ToArray()))
$lines = [System.Collections.Generic.List[string]]::new()
$lines.Add('#pragma once')
$lines.Add('#include <array>')
$lines.Add('#include <bit>')
$lines.Add('#include <cstdint>')
$lines.Add('')
$lines.Add('// 固定 GB2312 一级 3755 + 二级 3008 汉字；不是 CP936 可编码集合。')
$lines.Add('// 来源、区位范围、再生成方法见 docs/GB2312汉字表来源与生成.md。')
$lines.Add("// 区位序 UTF-16LE SHA-256: $zoneHash")
$lines.Add("// 升序 UTF-16LE SHA-256: $sortedHash")
$lines.Add('namespace lexhelper::detail {')
$lines.Add('// U+4E00..U+9FFF，每个 uint64_t 的最低位对应该块最小码点。')
$lines.Add('inline constexpr std::array<std::uint64_t,328> gb2312_hanzi_bits{')
for ($i = 0; $i -lt $bits.Length; $i += 4) {
    $values = for ($j = $i; $j -lt $i + 4; ++$j) { '0x{0:x16}ULL' -f $bits[$j] }
    $lines.Add('    ' + ($values -join ',') + ',')
}
$lines.Add('};')
$lines.Add('static_assert([] {unsigned count=0;for(auto bits:gb2312_hanzi_bits)count+=std::popcount(bits);return count==6763;}());')
$lines.Add('constexpr bool gb2312_hanzi(char16_t scalar) noexcept {')
$lines.Add('    if(scalar<0x4e00 || scalar>0x9fff)return false;')
$lines.Add('    const auto index=static_cast<unsigned>(scalar)-0x4e00;')
$lines.Add('    return (gb2312_hanzi_bits[index/64] & (std::uint64_t{1}<<(index%64)))!=0;')
$lines.Add('}')
$lines.Add('}')
$lines -join "`n"
