param(
    [string]$OutputPath = (Join-Path $PSScriptRoot 'app.ico')
)

# Original LexHelper geometric artwork; this script is the editable vector source.
# Windows / PowerShell 7 build-time tool only. No fonts, network or third-party libraries.
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$OutputEncoding = [System.Text.Encoding]::UTF8
chcp 65001 | Out-Null
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

function New-RoundedRectangle([single]$X, [single]$Y, [single]$Width, [single]$Height, [single]$Radius) {
    $path = [System.Drawing.Drawing2D.GraphicsPath]::new()
    $diameter = 2 * $Radius
    $path.AddArc($X, $Y, $diameter, $diameter, 180, 90)
    $path.AddArc($X + $Width - $diameter, $Y, $diameter, $diameter, 270, 90)
    $path.AddArc($X + $Width - $diameter, $Y + $Height - $diameter, $diameter, $diameter, 0, 90)
    $path.AddArc($X, $Y + $Height - $diameter, $diameter, $diameter, 90, 90)
    $path.CloseFigure()
    return ,$path
}

function New-IconFrame([int]$Size) {
    # Four-times supersampling preserves the silhouette and alpha edges at small sizes.
    $high = [System.Drawing.Bitmap]::new($Size * 4, $Size * 4, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $bitmap = [System.Drawing.Bitmap]::new($Size, $Size, [System.Drawing.Imaging.PixelFormat]::Format32bppArgb)
    $graphics = $null
    $downsample = $null
    $cover = $null
    $spine = $null
    $brushes = @{}
    $memory = [System.IO.MemoryStream]::new()
    $writer = [System.IO.BinaryWriter]::new($memory)
    try {
        foreach ($color in @('185ABC', '10418F', 'F4F9FF', '6DCFFF')) {
            $brushes[$color] = [System.Drawing.SolidBrush]::new([System.Drawing.ColorTranslator]::FromHtml('#' + $color))
        }
        $graphics = [System.Drawing.Graphics]::FromImage($high)
        $graphics.Clear([System.Drawing.Color]::Transparent)
        $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
        $graphics.ScaleTransform([single]($Size * 4 / 256.0), [single]($Size * 4 / 256.0))
        $cover = New-RoundedRectangle 28 20 200 216 20
        $graphics.FillPath($brushes['185ABC'], $cover)
        # The darker spine and light page edge communicate a closed dictionary.
        $spine = New-RoundedRectangle 28 20 34 216 16
        $graphics.FillPath($brushes['10418F'], $spine)
        $graphics.FillRectangle($brushes['F4F9FF'], [single]54, [single]204, [single]156, [single]12)
        # L is a geometric path, never a machine-dependent font glyph.
        $letter = [System.Drawing.PointF[]]@(
            [System.Drawing.PointF]::new(84, 64), [System.Drawing.PointF]::new(112, 64),
            [System.Drawing.PointF]::new(112, 148), [System.Drawing.PointF]::new(180, 148),
            [System.Drawing.PointF]::new(180, 176), [System.Drawing.PointF]::new(84, 176)
        )
        $graphics.FillPolygon($brushes['F4F9FF'], $letter)
        # Omit the nonessential bookmark below 32px to keep 16/20/24px legible.
        if ($Size -ge 32) {
            $bookmark = [System.Drawing.PointF[]]@(
                [System.Drawing.PointF]::new(174, 20), [System.Drawing.PointF]::new(200, 20),
                [System.Drawing.PointF]::new(200, 72), [System.Drawing.PointF]::new(187, 62),
                [System.Drawing.PointF]::new(174, 72)
            )
            $graphics.FillPolygon($brushes['6DCFFF'], $bookmark)
        }
        $downsample = [System.Drawing.Graphics]::FromImage($bitmap)
        $downsample.Clear([System.Drawing.Color]::Transparent)
        $downsample.CompositingMode = [System.Drawing.Drawing2D.CompositingMode]::SourceCopy
        $downsample.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $downsample.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
        $downsample.DrawImage($high, [System.Drawing.Rectangle]::new(0, 0, $Size, $Size), 0, 0, $high.Width, $high.Height, [System.Drawing.GraphicsUnit]::Pixel)

        # ICO DIB: BITMAPINFOHEADER + bottom-up straight BGRA + DWORD-aligned AND mask.
        $maskStride = [int]([Math]::Ceiling($Size / 32.0) * 4)
        $writer.Write([uint32]40)
        $writer.Write([int32]$Size)
        $writer.Write([int32]($Size * 2))
        $writer.Write([uint16]1)
        $writer.Write([uint16]32)
        $writer.Write([uint32]0)
        $writer.Write([uint32]($Size * $Size * 4 + $maskStride * $Size))
        1..4 | ForEach-Object { $writer.Write([uint32]0) }
        for ($y = $Size - 1; $y -ge 0; --$y) {
            for ($x = 0; $x -lt $Size; ++$x) {
                $pixel = $bitmap.GetPixel($x, $y)
                $writer.Write([byte]$pixel.B)
                $writer.Write([byte]$pixel.G)
                $writer.Write([byte]$pixel.R)
                $writer.Write([byte]$pixel.A)
            }
        }
        for ($y = $Size - 1; $y -ge 0; --$y) {
            $row = [byte[]]::new($maskStride)
            for ($x = 0; $x -lt $Size; ++$x) {
                if ($bitmap.GetPixel($x, $y).A -eq 0) {
                    $index = [int][Math]::Floor($x / 8)
                    $row[$index] = $row[$index] -bor (0x80 -shr ($x % 8))
                }
            }
            $writer.Write($row)
        }
        $writer.Flush()
        return ,$memory.ToArray()
    } finally {
        if ($downsample) { $downsample.Dispose() }
        if ($graphics) { $graphics.Dispose() }
        if ($cover) { $cover.Dispose() }
        if ($spine) { $spine.Dispose() }
        foreach ($brush in $brushes.Values) { $brush.Dispose() }
        $bitmap.Dispose()
        $high.Dispose()
        $writer.Dispose()
        $memory.Dispose()
    }
}

$sizes = @(16, 20, 24, 32, 40, 48, 64, 128, 256)
$frames = @($sizes | ForEach-Object { New-IconFrame $_ })
$output = [System.IO.MemoryStream]::new()
$directory = [System.IO.BinaryWriter]::new($output)
try {
    $directory.Write([uint16]0)
    $directory.Write([uint16]1)
    $directory.Write([uint16]$sizes.Count)
    $offset = 6 + $sizes.Count * 16
    for ($i = 0; $i -lt $sizes.Count; ++$i) {
        $dimension = if ($sizes[$i] -eq 256) { 0 } else { $sizes[$i] }
        $directory.Write([byte]$dimension)
        $directory.Write([byte]$dimension)
        $directory.Write([byte]0)
        $directory.Write([byte]0)
        $directory.Write([uint16]1)
        $directory.Write([uint16]32)
        $directory.Write([uint32]$frames[$i].Length)
        $directory.Write([uint32]$offset)
        $offset += $frames[$i].Length
    }
    foreach ($frame in $frames) { $directory.Write([byte[]]$frame) }
    $directory.Flush()
    [System.IO.File]::WriteAllBytes([System.IO.Path]::GetFullPath($OutputPath), $output.ToArray())
} finally {
    $directory.Dispose()
    $output.Dispose()
}
Write-Output ('已生成 {0}：{1} 像素，32 位 BGRA + AND 透明掩码。' -f $OutputPath, ($sizes -join '/'))
