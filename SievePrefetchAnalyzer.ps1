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

Start-Sleep 1

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

function Get-ADSStreams {
    param([string]$Path)

    try {
        Get-Item -LiteralPath $Path -Stream * -ErrorAction Stop |
        Where-Object { $_.Stream -ne ':$DATA' }
    } catch {
        @()
    }
}

$files = Get-ChildItem -Path $directory -Filter *.pf -File -ErrorAction SilentlyContinue

$hashTable = @{}
$suspiciousFiles = @{}

foreach ($file in $files) {
    try {
        # === Attributes ===
        if ($file.IsReadOnly) {
            Add-Suspicion $suspiciousFiles $file.Name "File is read-only"
        }

        if ($file.Attributes -band [IO.FileAttributes]::Hidden) {
            Add-Suspicion $suspiciousFiles $file.Name "Hidden attribute set"
        }

        if ($file.Attributes -band [IO.FileAttributes]::System) {
            Add-Suspicion $suspiciousFiles $file.Name "System attribute set"
        }

        # === ADS Detection ===
        $ads = Get-ADSStreams -Path $file.FullName
        foreach ($stream in $ads) {
            if ($stream.Stream -eq "Zone.Identifier") {
                Add-Suspicion $suspiciousFiles $file.Name "ADS detected: Zone.Identifier (download mark) Size=$($stream.Length)"
            } else {
                Add-Suspicion $suspiciousFiles $file.Name "ADS detected: '$($stream.Stream)' Size=$($stream.Length)"
            }
        }

        # === Hashing ===
        $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256
        if ($hashTable.ContainsKey($hash.Hash)) {
            $hashTable[$hash.Hash].Add($file.Name)
        } else {
            $hashTable[$hash.Hash] = [System.Collections.Generic.List[string]]::new()
            $hashTable[$hash.Hash].Add($file.Name)
        }

        # === Timestamp Heuristics ===
        if ($file.LastWriteTimeUtc -lt $file.CreationTimeUtc.AddMinutes(-5)) {
            Add-Suspicion $suspiciousFiles $file.Name "Timestamp anomaly: LastWrite older than Creation (UTC)"
        }

    } catch {
        Add-Suspicion $suspiciousFiles $file.Name "Error analyzing file: $($_.Exception.Message)"
    }
}

# === Duplicate Hash Analysis ===
$repeatedHashes = $hashTable.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 }

foreach ($entry in $repeatedHashes) {
    $related = $entry.Value -join ", "
    foreach ($fileName in $entry.Value) {
        Add-Suspicion $suspiciousFiles $fileName "Duplicate SHA256 with: $related"
    }
}

# === Output ===
if ($suspiciousFiles.Count) {
    Write-Host "Suspicious Prefetch files detected:" -ForegroundColor Yellow
    foreach ($file in ($suspiciousFiles.Keys | Sort-Object)) {
        Write-Host ""
        Write-Host "$file" -ForegroundColor Cyan
        foreach ($reason in $suspiciousFiles[$file]) {
            Write-Host "  - $reason"
        }
    }
} else {
    Write-Host "Prefetch folder is clean."
}
