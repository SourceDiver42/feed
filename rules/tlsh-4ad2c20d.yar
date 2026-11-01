rule Sightlines_tlsh_4ad2c20d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-4ad2c20d"
        date = "2026-10-27"
        campaign = "tlsh-4ad2c20d"
        family = ""
        hash = "0e15469a86b39edd8d3b3277b716a627f3ced62f898fcee6f724920cb2729fc0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-4ad2c20d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "$env:TEMP\\\"+[IO.Path]::GetRandomFileName()+\".exe\";[IO.File]::WriteAllBytes($p,$d);Start-Process $p -" ascii
        $s1 = "$c=(New-Object Net.WebClient).DownloadData('http://176.65.144.144/assets/logo.png');$k=[Convert]::Fr" ascii
        $s2 = "WindowStyle 1}" ascii
    condition:
        filesize < 1048576 and 3 of them
}
