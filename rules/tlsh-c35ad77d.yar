rule Sightlines_tlsh_c35ad77d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c35ad77d"
        date = "2026-10-20"
        campaign = "tlsh-c35ad77d"
        family = ""
        hash = "151355d4e162afc65c8f9569e78c02fa071d84041cc0253cfaf98ad5a9e96435"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c35ad77d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "E1A678858AB902D9F4DEF13F7E8C143A9684615D6703C9BB0BF12849254D0913" ascii
        $s4 = "088D193B482A02DC449974A6C9FF150261F9BBAFDA69849E8D98C2D8AC9EF439" ascii
        $s5 = "FA9A7F0BA17A7817533D88BA29C5C119B75A8FD05256EB52C8B76903BB18BE29" ascii
        $s6 = "99952978970AE43F4FAECAA9B132E74A0965981E8BE3153AEDE46611E5905766" ascii
        $s7 = "A59EBB7040529DA1C25434845C93C6CB3B58AF645992F9C541A526B8902092BD" ascii
        $s8 = "<ComputeRoomAcousticsMetrics>b__1_0" ascii
        $s9 = "54 68 69 73 20 69 73 20 6E 6F 72 6D 61 6C" wide
        $s10 = "get_icons8_purchase_order_50" ascii
        $s11 = "get_icons8_graph_report_501" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1671168 and 12 of them
}
