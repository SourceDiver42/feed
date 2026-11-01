rule Sightlines_tlsh_25c8de05_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-25c8de05"
        date = "2026-10-30"
        campaign = "tlsh-25c8de05"
        family = ""
        hash = "1366102fff4ae8ee4cf146aa0fe447a5a975bdb3d4dbb739a862ba1e986335a0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-25c8de05.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    foreach ($line in [System.IO.File]::ReadAllLines((Join-Path $PSScriptRoot 'targets.txt'))) {" ascii
        $s1 = "function Invoke-CurlBatch($Targets, [string]$PostFile, [int]$Width = 0) {" ascii
        $s2 = "    $conn = if ($ok.Count) { [math]::Round(($ok | Measure-Object -Property ConnMs -Average).Average)" ascii
        $s3 = "function Get-IpBlocked($Table, [int]$TimeoutMs = 3000) {" ascii
        $s4 = "function Format-Summary($S, [string]$Prefix = '', [switch]$NoName) {" ascii
        $s5 = "\"https://hyperion-cs.github.io/dpi-checkers/ru/tcp-16-20/suite.v2.json\"') $Script:Runtime 15" ascii
        $s6 = "        try { $items = ConvertFrom-Json ([System.IO.File]::ReadAllText($file, [System.Text.Encoding]" ascii
        $s7 = "function Get-RunSummary([string]$Id, [string]$Name, $Rows, $CleanBase) {" ascii
        $s8 = "' }) + @($strategies | ForEach-Object { New-Object PSObject -Property @{ Id = $_.Id; Name = $_.Name " ascii
        $s9 = ": ' + ((Get-RotationOrder $settings.alt 'general' | ForEach-Object { $_.Name }) -join ' > ')) Gray" ascii
        $s10 = "    Write-TextNoBom (Join-Path $Script:Runtime 'test-best.txt') ($best.Id + \"`r`n\")" ascii
        $s11 = "param([int]$TimeoutSec = 5, [int]$Parallel = 16, [int]$Rounds = 1, [switch]$NoPrompt, [switch]$Repor" ascii
    condition:
        filesize < 1048576 and 11 of them
}
