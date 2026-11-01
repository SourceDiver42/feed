rule Sightlines_tlsh_21f3fcaa_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-21f3fcaa"
        date = "2026-10-30"
        campaign = "tlsh-21f3fcaa"
        family = ""
        hash = "080b32207a65c1f6a39496b75019c58f7e1b1f8e7d934f8e8f2531300323da6b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-21f3fcaa.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    elseif ($v6.PreferV4 -and $v6.Has -and @($v6.Rows | Where-Object { $_.Verdict -eq 'ok' }).Count)" ascii
        $s1 = "    $wasOn = ([System.IO.File]::ReadAllText($updFlag).Trim() -eq 'start')" ascii
        $s2 = " 1024-65535').Trim(); if (Test-PortList $v) { $s.gameudp = $v } else { Write-Color '" ascii
        $s3 = "    $file = Join-Path ([Environment]::GetFolderPath('Desktop')) 'zapret-direct-rules.txt'" ascii
        $s4 = " 1024-65535').Trim(); if (Test-PortList $v) { $s.gametcp = $v } else { Write-Color '" ascii
        $s5 = "function Write-BoxRow([string]$Text, [string]$Color = 'Gray', [int[]]$Rgb = @()) {" ascii
        $s6 = ": https://github.com/{2}/releases' -f $rel.Tag, $Script:Version, $Script:SelfRepo) White" ascii
        $s7 = "    $ps = Join-Path $env:SystemRoot 'System32\\WindowsPowerShell\\v1.0\\powershell.exe'" ascii
        $s8 = ": https://github.com/' + $Script:SelfRepo + '/releases') Yellow; Pause-Menu; return }" ascii
        $s9 = ": zapret {0}, zapret2 {1}, Flowseal {2}.' -f $Script:Version, $Script:Upstream['zapret2'].Base, $Scr" ascii
        $s10 = "?') { $s.notify = 'off'; Save-Settings $s; Sync-UserTask $s | Out-Null; Write-Color '" ascii
        $s11 = "if (-not (Test-Path $Script:Exe) -or -not (Test-Path (Join-Path $Script:Bin 'WinDivert64.sys'))) {" ascii
    condition:
        filesize < 1048576 and 11 of them
}
