rule Sightlines_tlsh_be308dc9_acrstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-be308dc9"
        date = "2026-11-01"
        campaign = "tlsh-be308dc9"
        family = "acrstealer"
        hash = "00e9fd3aafdda7a65c790bc7da59fba5f9556d5dc21586b4cad3e0bb06343c2e"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-be308dc9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "        elseif ([long]$v -ge 0x10000 -and [long]$v -le 0x10FFFF) { $r += [System.Char]::ConvertFromU" ascii
        $s1 = "        elseif ([long]$v -ge 0x10000 -and [long]$v -le 0x10FFFF) { $r = [System.Char]::ConvertFromUt" ascii
        $s2 = "} finally {" ascii
        $s3 = "} finally{" ascii
        $s4 = "return $r" ascii
        $s5 = " break }" ascii
    condition:
        filesize < 1048576 and 6 of them
}
