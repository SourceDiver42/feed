rule Sightlines_tlsh_57ecf368_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-57ecf368"
        date = "2026-11-01"
        campaign = "tlsh-57ecf368"
        family = ""
        hash = "13ce2b57b35b9a0223b0ea2782752bd2e20f550e2b7f0e9de8ae8d3999bfd402"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-57ecf368.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    Write-Host \"[INFO] Starting DPI TCP 16-20 checks (parallel: $MaxParallel)...\" -ForegroundColor D" ascii
        $s1 = "if ($env:MONITOR_MAX_PARALLEL) { [int]$dpiMaxParallel = $env:MONITOR_MAX_PARALLEL }" ascii
        $s2 = "if ($env:MONITOR_RANGE) { [int]$dpiRangeBytes = $env:MONITOR_RANGE }" ascii
        $s3 = "    $proc = Start-Process -FilePath \"cmd.exe\" -ArgumentList \"/c `\"$($file.FullName)`\"\" -WorkingDirec" ascii
        $s4 = "    Write-Host \"[INFO] Targets: $($Targets.Count) (custom URL overrides suite). Range: $rangeSpec by" ascii
        $s5 = "if ($env:MONITOR_TIMEOUT) { [int]$dpiTimeoutSeconds = $env:MONITOR_TIMEOUT }" ascii
        $s6 = "if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {" ascii
        $s7 = "    Write-Host \"  [$configNum/$($batFiles.Count)] $($file.Name)\" -ForegroundColor Yellow" ascii
        $s8 = "# DPI checker defaults (override via MONITOR_* env vars like in monitor.ps1)" ascii
        $s9 = "    $url = \"https://hyperion-cs.github.io/dpi-checkers/ru/tcp-16-20/suite.v2.json\"" ascii
        $s10 = "$batFiles = Get-ChildItem -Path $targetDir -Filter \"*.bat\" | Where-Object { $_.Name -notlike \"servic" ascii
        $s11 = "    Write-Host \"[WARNING] Ipset will be switched to 'any' for accurate DPI tests.\" -ForegroundColor " ascii
    condition:
        filesize < 1048576 and 9 of them
}
