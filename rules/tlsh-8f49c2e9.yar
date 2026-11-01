rule Sightlines_tlsh_8f49c2e9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8f49c2e9"
        date = "2026-10-29"
        campaign = "tlsh-8f49c2e9"
        family = ""
        hash = "22a2dc9c95971a0a4d24e5568dc6c49bfaf6ce9bcf08e11b92e1470ff4613c47"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8f49c2e9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "param([int]$Seconds = 180, [string]$ProcessName = 'NBA2K*')" ascii
        $s1 = "Copy-Item $repFile (Join-Path $Script:Runtime 'scan-last.txt') -Force" ascii
        $s2 = "    foreach ($a in @(Get-NetIPAddress -ErrorAction SilentlyContinue)) { $local[($a.IPAddress -replac" ascii
        $s3 = "        if (@(Get-Process -Id $gamePids -ErrorAction SilentlyContinue).Count -eq 0) { Write-Host '';" ascii
        $s4 = "$repFile = Join-Path $Script:Runtime ('scan-' + $stamp + '.txt')" ascii
        $s5 = "        foreach ($c in @(Get-NetTCPConnection -OwningProcess @($procName.Keys) -ErrorAction Silently" ascii
        $s6 = "$EacNames = @('EasyAntiCheat*', 'start_protected_game*')" ascii
        $s7 = "    foreach ($p in @(Get-Process -Name (@($ProcessName) + $EacNames) -ErrorAction SilentlyContinue))" ascii
        $s8 = "$report = New-Object System.Collections.Generic.List[string]" ascii
        $s9 = "while ($procs.Count -eq 0 -and (Get-Date) -lt $waitUntil) {" ascii
        $s10 = " (ETW Microsoft-Windows-Kernel-Network)." ascii
        $s11 = "$etl = Join-Path $Script:Runtime 'scan.etl'" ascii
    condition:
        filesize < 1048576 and 12 of them
}
