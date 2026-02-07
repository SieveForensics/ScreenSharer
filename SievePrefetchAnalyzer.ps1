$directory = "C:\Windows\Prefetch"

Clear-Host

Write-Host @"
███████╗██╗███████╗██╗   ██╗███████╗
██╔════╝██║██╔════╝██║   ██║██╔════╝
███████╗██║█████╗  ██║   ██║█████╗
╚════██║██║██╔══╝  ╚██╗ ██╔╝██╔══╝
███████║██║███████╗ ╚████╔╝ ███████╗
╚══════╝╚═╝╚══════╝  ╚═══╝  ╚══════╝
"@ -ForegroundColor Cyan

Write-Host ""
Write-Host "  Prefetch Integrity Analyzer Made by Sieve - " -ForegroundColor Blue -NoNewline
Write-Host -ForegroundColor Red "SieveForensics<333"
Write-Host ""

function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if (!(Test-Admin)) {
    Write-Warning "Please Run This Script as Admin."
    Start-Sleep 10
    Exit
}

Start-Sleep -s 1

function Add-Suspicion {
    param(
        [hashtable]$Map,
        [string]$FileName,
        [string]$Reason
    )
    if (-not $Map.ContainsKey($FileName)) {
        $Map[$FileName] = New-Object System.Collections.Generic.List[string]
    }
    $Map[$FileName].Add($Reason)
}

function Get-PrefetchHeaderInfo {
    param([string]$Path)

    # Lee 8 bytes: 4 para signature (ASCII) y 4 para version (LE) si aplica
    $fs = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $br = New-Object System.IO.BinaryReader($fs)
        $sigBytes = $br.ReadBytes(4)
        $sig = [System.Text.Encoding]::ASCII.GetString($sigBytes)
        $ver = $br.ReadInt32()  # little-endian
        return [pscustomobject]@{
            Signature = $sig
            Version   = $ver
        }
    } finally {
        $fs.Close()
    }
}

function Get-ADSStreams {
    param([string]$Path)

    try {
        $streams = Get-Item -LiteralPath $Path -Stream * -ErrorAction Stop
        $streams | Where-Object { $_.Stream -ne ':$DATA' }
    } catch {
        @()
    }
}

$files = Get-ChildItem -Path $directory -Filter *.pf -File -ErrorAction SilentlyContinue

$hashTable = @{}         # hash -> list of file names
$suspiciousFiles = @{}   # file -> list of reasons

foreach ($file in $files) {
    try {
        # 1) Atributos básicos
        if ($file.IsReadOnly) { Add-Suspicion $suspiciousFiles $file.Name "File is read-only" }
        if ($file.Attributes -band [IO.FileAttributes]::Hidden) { Add-Suspicion $suspiciousFiles $file.Name "Hidden attribute set" }
        if ($file.Attributes -band [IO.FileAttributes]::System) { Add-Suspicion $suspiciousFiles $file.Name "System attribute set (unusual for many .pf)" }

        # 2) Header binario (mejor que StreamReader)
        $h = Get-PrefetchHeaderInfo -Path $file.FullName

        $sigTrim = $h.Signature.Trim([char]0)

        if ($sigTrim -notin @("SCCA","MAM")) {
            Add-Suspicion $suspiciousFiles $file.Name "Unexpected PF signature: '$($h.Signature)'"
        }

        if ($h.Version -le 0 -or $h.Version -gt 200) {
            Add-Suspicion $suspiciousFiles $file.Name "Suspicious PF version field: $($h.Version)"
        }

        # ADS detection
        $ads = Get-ADSStreams -Path $file.FullName
        foreach ($s in $ads) {
            # Zone.Identifier puede existir si algo fue marcado como descargado, pero en Prefetch es raro.
            $note = if ($s.Stream -eq "Zone.Identifier") {
                "ADS present: Zone.Identifier (download mark) Size=$($s.Length)"
            } else {
                "ADS present: '$($s.Stream)' Size=$($s.Length)"
            }
            Add-Suspicion $suspiciousFiles $file.Name $note
        }

        $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256
        if ($hashTable.ContainsKey($hash.Hash)) {
            $hashTable[$hash.Hash].Add($file.Name)
        } else {
            $hashTable[$hash.Hash] = [System.Collections.Generic.List[string]]::new()
            $hashTable[$hash.Hash].Add($file.Name)
        }

        if ($file.LastWriteTimeUtc -lt $file.CreationTimeUtc.AddMinutes(-5)) {
            Add-Suspicion $suspiciousFiles $file.Name "Timestamp anomaly: LastWrite older than Creation (UTC)"
        }

    } catch {
        Add-Suspicion $suspiciousFiles $file.Name "Error analyzing file: $($_.Exception.Message)"
    }
}


$repeatedHashes = $hashTable.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 }
foreach ($entry in $repeatedHashes) {
    $list = ($entry.Value -join ", ")
    foreach ($fn in $entry.Value) {
        Add-Suspicion $suspiciousFiles $fn "Duplicate SHA256 with: $list"
    }
}

if ($suspiciousFiles.Count) {
    Write-Host "Suspicious PF files:" -ForegroundColor Yellow
    foreach ($key in ($suspiciousFiles.Keys | Sort-Object)) {
        Write-Host ""
        Write-Host "$key" -ForegroundColor Cyan
        foreach ($reason in $suspiciousFiles[$key]) {
            Write-Host "  - $reason"
        }
    }
} else {
    Write-Host "Prefetch folder is clean."
}
