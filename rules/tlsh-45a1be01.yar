rule Sightlines_tlsh_45a1be01_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-45a1be01"
        date = "2026-10-29"
        campaign = "tlsh-45a1be01"
        family = ""
        hash = "5aa8f6e5d63ddb8d08f5c51aaccf13ddd8c8f24c6967c1fde82aa3efab7d5ca0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-45a1be01.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    [System.IO.File]::AppendAllText($logFile, $Line + \"`r`n\", $Script:Utf8NoBom)" ascii
        $s1 = "    [System.IO.File]::WriteAllText($logFile, (($all -join \"`r`n\") + \"`r`n\"), $Script:Utf8NoBom)" ascii
        $s2 = ": {3}' -f (Format-Endpoint $x.Ip $x.Port 46), $x.Out, (Get-GeoText $x.Ip 50), (Get-BypassText $x.Own" ascii
        $s3 = "param([int]$Interval = 5, [string]$ProcessName = 'NBA2K*', [string]$Replay, [int]$ReplayPid = 0)" ascii
        $s4 = "        try { $pingTask[$ip] = (New-Object System.Net.NetworkInformation.Ping).SendPingAsync($ip, 10" ascii
        $s5 = ": {4}' -f $now, (Format-Endpoint $x.Ip $x.Port 44), $x.Out, (Get-GeoText $x.Ip 50), (Get-BypassText " ascii
        $s6 = "function Add-PingSample([string]$Ip, [double]$Ms, [string]$Kind) {" ascii
        $s7 = "    $need = @($Ips | Where-Object { -not $geo.ContainsKey($_) } | Select-Object -Unique -First 16)" ascii
        $s8 = "$etlFiles = @((Join-Path $Script:Runtime 'track-a.etl'), (Join-Path $Script:Runtime 'track-b.etl'))" ascii
        $s9 = "ocName.ContainsKey([int]$_.Properties[0].Value) }) } catch { }" ascii
        $s10 = "    if ($tcpProbeAt.ContainsKey($key) -and ((Get-Date) - $tcpProbeAt[$key]).TotalSeconds -lt 20) { r" ascii
        $s11 = "$AppName = if ($ProcessName -like 'NBA2K*') { 'NBA 2K27' } else { $ProcessName.TrimEnd('*') }" ascii
    condition:
        filesize < 1048576 and 12 of them
}
