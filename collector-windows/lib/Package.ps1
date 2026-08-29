Set-StrictMode -Version 2.0

function Set-TarAsciiField {
    param([byte[]]$Header, [int]$Offset, [int]$Length, [string]$Value)
    $bytes = [System.Text.Encoding]::ASCII.GetBytes($Value)
    $count = [Math]::Min($Length, $bytes.Length)
    [Array]::Copy($bytes, 0, $Header, $Offset, $count)
}

function Format-TarOctal {
    param([long]$Value, [int]$Length)
    $digits = [Convert]::ToString([Math]::Max(0, $Value), 8)
    return $digits.PadLeft($Length - 1, '0') + [char]0
}

function New-TarHeader {
    param([string]$Name, [long]$Size, [DateTime]$LastWriteTimeUtc)
    $normalized = $Name.Replace('\', '/')
    if ([System.Text.Encoding]::UTF8.GetByteCount($normalized) -gt 100) {
        throw "采集包内部路径超过 tar ustar 限制: $normalized"
    }
    $header = New-Object byte[] 512
    Set-TarAsciiField $header 0 100 $normalized
    Set-TarAsciiField $header 100 8 (Format-TarOctal 420 8)
    Set-TarAsciiField $header 108 8 (Format-TarOctal 0 8)
    Set-TarAsciiField $header 116 8 (Format-TarOctal 0 8)
    Set-TarAsciiField $header 124 12 (Format-TarOctal $Size 12)
    $epoch = [DateTime]::SpecifyKind([DateTime]'1970-01-01', [DateTimeKind]::Utc)
    $mtime = [long]([Math]::Floor(($LastWriteTimeUtc - $epoch).TotalSeconds))
    Set-TarAsciiField $header 136 12 (Format-TarOctal $mtime 12)
    for ($i = 148; $i -lt 156; $i++) { $header[$i] = 32 }
    $header[156] = [byte][char]'0'
    Set-TarAsciiField $header 257 6 ("ustar" + [char]0)
    Set-TarAsciiField $header 263 2 "00"
    Set-TarAsciiField $header 265 32 "OraSentry"
    Set-TarAsciiField $header 297 32 "OraSentry"
    $sum = 0L
    foreach ($value in $header) { $sum += $value }
    $checksum = [Convert]::ToString($sum, 8).PadLeft(6, '0') + [char]0 + ' '
    Set-TarAsciiField $header 148 8 $checksum
    return $header
}

function New-TarGzArchive {
    param(
        [Parameter(Mandatory=$true)][string]$SourceDirectory,
        [Parameter(Mandatory=$true)][string]$DestinationPath
    )
    $source = [System.IO.Path]::GetFullPath($SourceDirectory).TrimEnd('\')
    $destination = [System.IO.Path]::GetFullPath($DestinationPath)
    $temporaryTar = "$destination.$PID.tmp.tar"
    $zeroBlock = New-Object byte[] 512
    try {
        $stream = New-Object System.IO.FileStream($temporaryTar, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        try {
            foreach ($file in Get-ChildItem -LiteralPath $source -File -Recurse | Sort-Object FullName) {
                $relative = $file.FullName.Substring($source.Length).TrimStart('\').Replace('\', '/')
                $header = New-TarHeader -Name $relative -Size $file.Length -LastWriteTimeUtc $file.LastWriteTimeUtc
                $stream.Write($header, 0, $header.Length)
                $input = [System.IO.File]::OpenRead($file.FullName)
                try { $input.CopyTo($stream) } finally { $input.Dispose() }
                $padding = [int]((512 - ($file.Length % 512)) % 512)
                if ($padding -gt 0) { $stream.Write($zeroBlock, 0, $padding) }
            }
            $stream.Write($zeroBlock, 0, 512)
            $stream.Write($zeroBlock, 0, 512)
        } finally {
            $stream.Dispose()
        }

        $tarInput = [System.IO.File]::OpenRead($temporaryTar)
        $gzOutput = New-Object System.IO.FileStream($destination, [System.IO.FileMode]::Create, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        $gzip = New-Object System.IO.Compression.GZipStream($gzOutput, [System.IO.Compression.CompressionMode]::Compress)
        try { $tarInput.CopyTo($gzip) } finally { $gzip.Dispose(); $gzOutput.Dispose(); $tarInput.Dispose() }
    } finally {
        if (Test-Path -LiteralPath $temporaryTar) { Remove-Item -LiteralPath $temporaryTar -Force }
    }
}

function Pack-Collection {
    param([Parameter(Mandatory=$true)]$Context, [Parameter(Mandatory=$true)][string]$ArchiveName)
    $safeName = [System.IO.Path]::GetFileName($ArchiveName)
    if ($safeName -ne $ArchiveName -or $safeName -notmatch '^[A-Za-z0-9_.-]+\.tar\.gz$') {
        throw "非法采集包文件名: $ArchiveName"
    }
    $path = Join-Path $Context.RawBase $safeName
    Write-CollectorLog -Context $Context -Message "正在生成采集包: $safeName"
    New-TarGzArchive -SourceDirectory $Context.RawDir -DestinationPath $path
    $Context.PackageFile = $path
    Write-CollectorLog -Context $Context -Message "采集包已生成: $path"
    return $path
}
