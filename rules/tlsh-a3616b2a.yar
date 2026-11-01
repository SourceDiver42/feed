rule Sightlines_tlsh_a3616b2a_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a3616b2a"
        date = "2026-10-30"
        campaign = "tlsh-a3616b2a"
        family = ""
        hash = "0e14c230727778d9d4fc0909633ed3904a5da2830003ff105b4f175576c8c037"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a3616b2a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Required key not available" ascii
        $s1 = "Key was rejected by service" ascii
        $s2 = "github version %s (%s)" ascii
        $s3 = ": unrecognized option: " ascii
        $s4 = "Key has been revoked" ascii
        $s5 = "UJn|}ZR.UJ 6|dQ" ascii
        $s6 = "Key has expired" ascii
        $s7 = ".gnu.attributes" ascii
        $s8 = "Cx}J;x}VI.K" ascii
        $s9 = "@8}J8x}JCx}J" ascii
        $s10 = "}.Kx}1Kx9!" ascii
        $s11 = "Ph80Qg 6P" ascii
    condition:
        uint32(0) == 0x464C457F and filesize < 1048576 and 12 of them
}
