param([ValidateSet('Debug','Release')][string]$Configuration='Debug')
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 | Out-Null
$ErrorActionPreference='Stop'
$root=Split-Path -Parent $PSScriptRoot
$cmake='D:\Program Files\Microsoft Visual Studio\18\BuildTools\Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
$ctest=Join-Path (Split-Path $cmake) 'ctest.exe'
if (!(Test-Path $cmake)) { throw '未找到已批准 VS2026 CMake；不自动安装，请核实工具路径。' }
Push-Location $root
try {
    & $cmake --preset vs2026
    if ($LASTEXITCODE) { throw 'CMake 配置失败' }
    & $cmake --build --preset $Configuration.ToLowerInvariant()
    if ($LASTEXITCODE) { throw '构建失败' }
    & $ctest --preset $Configuration.ToLowerInvariant()
    if ($LASTEXITCODE) { throw 'CTest 失败' }
} finally { Pop-Location }
