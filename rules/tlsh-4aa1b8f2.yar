rule Sightlines_tlsh_4aa1b8f2_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-4aa1b8f2"
        date = "2026-11-01"
        campaign = "tlsh-4aa1b8f2"
        family = ""
        hash = "0cb21f1ed9c3db04902d28f21ae8a2605a00781bc87a1fbc9ac918da4a19fe3c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-4aa1b8f2.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "\\Registry\\Machine\\Software\\Classes\\" wide
        $s1 = "\\REGISTRY\\MACHINE\\SOFTWARE\\Classes" wide
        $s2 = "\\REGISTRY\\USER" wide
        $s3 = "Wow6432Node" wide
        $s4 = "t$ WATAUE3" ascii
        $s5 = "@88tE@8;tgH" ascii
        $s6 = "x7H9\\$Ht0H" ascii
        $s7 = "G0H9G8u_A" ascii
        $s8 = "H SUVWATH" ascii
        $s9 = "6T{tmF M" ascii
        $s10 = "f9|$@t1H" ascii
        $s11 = "~Hx1UnBZ" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 10182656 and 12 of them
}
