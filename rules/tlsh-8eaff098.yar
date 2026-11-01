rule Sightlines_tlsh_8eaff098_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-8eaff098"
        date = "2026-10-30"
        campaign = "tlsh-8eaff098"
        family = ""
        hash = "3abf33d459aa8855ebf1a68b3ce34d478c173ba9e0e8cfb4c2c0a805803ab864"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-8eaff098.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = " {2}' -f $f, @(Get-ListLines $path).Count, (Get-Item $path).LastWriteTime.ToString('yyyy-MM-dd HH:mm" ascii
        $s1 = ": {3} [{4}]' -f (Get-MaskedIp ([string]$info.Ip)), $info.CountryCode, $info.City, $info.Isp, $info.A" ascii
        $s2 = "try { $os = Get-CimInstance Win32_OperatingSystem -ErrorAction Stop; $r.Add('Windows: ' + $os.Captio" ascii
        $s3 = ")' (Join-Path $Script:Runtime 'autohostlist-debug.log') 60" ascii
        $s4 = "if (-not $NoOpen) { try { Start-Process -FilePath 'explorer.exe' -ArgumentList ('/select,\"' + $file " ascii
        $s5 = "function Add-File([string]$Title, [string]$Path, [int]$Tail = 0, [string]$StopAt = '') {" ascii
        $s6 = "' (Join-Path $Script:Runtime 'track-last.txt') 300" ascii
        $s7 = "foreach ($x in @(Get-ProxyWarnings)) { $r.Add('" ascii
        $s8 = "$dbg = Join-Path $Script:Runtime 'debug.log'" ascii
        $s9 = "Write-TextNoBom $file (Protect-ReportText (($r -join \"`r`n\") + \"`r`n\") $(if ($info) { [string]$info." ascii
        $s10 = ")' (Join-Path $Script:Runtime 'args-active.txt')" ascii
        $s11 = "' (Join-Path $Script:Runtime 'autotune.log') 30" ascii
    condition:
        filesize < 1048576 and 12 of them
}
