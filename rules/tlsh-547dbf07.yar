rule Sightlines_tlsh_547dbf07_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-547dbf07"
        date = "2026-10-30"
        campaign = "tlsh-547dbf07"
        family = ""
        hash = "185c721c0071b3eada83ec95078538f907f293f4d7a94b4133ece2111418ec32"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-547dbf07.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "    $a.Add('--blob=discord_udp:@' + (Get-PkgPath 'fake/ACTIVE_DISCORD_UDP.bin'))" ascii
        $s1 = "    $a.Add('--blob=game_udp:@' + (Get-PkgPath 'fake/ACTIVE_GAME_UDP.bin'))" ascii
        $s2 = "    if (Test-Path (Join-Path $src 'tools\\lib.ps1')) { $ver = [regex]::Match([System.IO.File]::ReadAl" ascii
        $s3 = "    $pr = New-ScheduledTaskPrincipal -UserId ($env:USERDOMAIN + '\\' + $env:USERNAME) -LogonType Inte" ascii
        $s4 = "        $appId = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\\WindowsPowerShell\\v1.0\\powershell.exe'" ascii
        $s5 = "$Script:Utf8NoBom   = New-Object System.Text.UTF8Encoding($false)" ascii
        $s6 = "    $keep = @([System.IO.File]::ReadAllLines($f) | Where-Object { $ips -notcontains $_.Trim() })" ascii
        $s7 = "    $logon = New-ScheduledTaskTrigger -AtLogOn -User ($env:USERDOMAIN + '\\' + $env:USERNAME)" ascii
        $s8 = "$Script:HostsLegacyEnd = @('# NBA2K27-zapret2: hosts Flowseal - " ascii
        $s9 = "function Format-Points([double]$X) { return $X.ToString('0.#', [Globalization.CultureInfo]::Invarian" ascii
        $s10 = "    $a.Add('--blob=tls_sferum:@' + (Get-PkgPath 'fake/tls_clienthello_www_sferum_ru.bin'))" ascii
        $s11 = "function Get-TrackBypassedNets([string]$Path = (Join-Path $Script:Runtime 'track-last.txt')) {" ascii
    condition:
        filesize < 1048576 and 12 of them
}
