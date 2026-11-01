rule Sightlines_rich_header_hash_0fc4db97_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign rich_header_hash-0fc4db97"
        date = "2026-10-24"
        campaign = "rich_header_hash-0fc4db97"
        family = ""
        hash = "1bc82bed6143d2bf1b6b08a7809f4a5e29317d6fddd338a7da3c0223522e4bbf"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/rich_header_hash-0fc4db97.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "10.0.26100.1742 (WinBuild.160101.0800)" wide
        $s1 = "ApiSet Stub DLL" wide
        $s2 = "apisetstub" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 3 of them
}
