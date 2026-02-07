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

Start-Sleep -s 3

$files = Get-ChildItem -Path $directory -Filter *.pf

$hashTable = @{}
$suspiciousFiles = @{}

foreach ($file in $files) {
    try {
        if ($file.IsReadOnly) {
            if (-not $suspiciousFiles.ContainsKey($file.Name)) {
                $suspiciousFiles[$file.Name] = "$($file.Name) is read-only"
            }
        }

        $reader = [System.IO.StreamReader]::new($file.FullName)
        $buffer = New-Object char[] 3
        $null = $reader.ReadBlock($buffer, 0, 3)
        $reader.Close()

        $firstThreeChars = -join $buffer

        if ($firstThreeChars -ne "MAM") {
            if (-not $suspiciousFiles.ContainsKey($file.Name)) {
                $suspiciousFiles[$file.Name] = "$($file.Name) is not a valid prefetch file"
            }
        }

        $hash = Get-FileHash -Path $file.FullName -Algorithm SHA256

        if ($hashTable.ContainsKey($hash.Hash)) {
            $hashTable[$hash.Hash].Add($file.Name)
        } else {
            $hashTable[$hash.Hash] = [System.Collections.Generic.List[string]]::new()
            $hashTable[$hash.Hash].Add($file.Name)
        }
    } catch {
        Write-Host "Error with file: $($file.FullName): $($_.Exception.Message)"
    }
}

$repeatedHashes = $hashTable.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 }

if ($repeatedHashes) {
    foreach ($entry in $repeatedHashes) {
        foreach ($file in $entry.Value) {
            if (-not $suspiciousFiles.ContainsKey($file)) {
                $suspiciousFiles[$file] = "$file was modified with type or echo"
            }
        }
    }
}

if ($suspiciousFiles.Count) {
    Write-Host "Suspicius PFs files:" -ForegroundColor Yellow
    foreach ($key in $suspiciousFiles.Keys) {
        Write-Host "$key` : $($suspiciousFiles[$key])"
    }
} else {
    Write-Host "Prefetch folder is clean."

}



