rule Sightlines_host_36996cf5_phorpiex
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-36996cf5"
        date = "2026-10-22"
        campaign = "host-36996cf5"
        family = "phorpiex"
        hash = "1b650dc35f75c9b962c54dfd1cacd9bbedf8708a4870218c4bbb07a76b4d1ba3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-36996cf5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <assemblyIdentity type=\"win32\" name=\"Microsoft.VC90.CRT\" version=\"9.0.21022.8\" processorArchit" ascii
        $s1 = "GPADDINGXXPADDINGPADDINGXXPADDINGPADDINGXXPADDING" ascii
        $s2 = "%s:Zone.Identifier" wide
        $s3 = "__wgetmainargs" ascii
        $s4 = "MSVCR90.dll" ascii
        $s5 = "%appdata%" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 5 of them
}
