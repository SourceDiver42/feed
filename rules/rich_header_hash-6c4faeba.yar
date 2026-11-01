rule Sightlines_rich_header_hash_6c4faeba_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-6c4faeba"
        date = "2026-10-27"
        campaign = "rich_header_hash-6c4faeba"
        family = ""
        hash = "086502fbbc7b0817f1371e363774201a641a98ea465589495f686cb26c0b5682"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-6c4faeba.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "10.0.20348.1 (WinBuild.160101.0800)" wide
        $s1 = "`0a1b2c3d4e5f6g7h8i9" wide
        $s2 = "KbdLayerDescriptor" ascii
        $s3 = "Right Windows" wide
        $s4 = "Left Windows" wide
        $s5 = "QWERTYUIOP" wide
        $s6 = "Right Shift" wide
        $s7 = "Scroll Lock" wide
        $s8 = "ASDFGHJKL" wide
        $s9 = "Caps Lock" wide
        $s10 = "Num Enter" wide
        $s11 = "Page Down" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 3 of them
}
