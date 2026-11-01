rule Sightlines_tlsh_21a8b41b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-21a8b41b"
        date = "2026-10-31"
        campaign = "tlsh-21a8b41b"
        family = ""
        hash = "2e6bf792d54303a54467102fd873a7d7a993f828e8d19c040e13e428e5f2d9c8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-21a8b41b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "JSON parsing exception: %s [offset %zu: line %d, column %d]" wide
        $s1 = "Unable to open specified trace file for writing: %s" wide
        $s2 = "  - Ensure the library matches the current process architecture: x64" wide
        $s3 = "Failed to load [%s], HRESULT: 0x%X" wide
        $s4 = "Framework '%s' is missing a version." wide
        $s5 = "No framework name specified: %s" wide
        $s6 = "Failed to parse file [%s]. %s" wide
        $s7 = "Expected a JSON object" wide
        $s8 = "TRACE_VERBOSITY" wide
        $s9 = "DOTNET_HOST_%s" wide
        $s10 = "COREHOST_%s" wide
        $s11 = "t6<0|o<9wk" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
