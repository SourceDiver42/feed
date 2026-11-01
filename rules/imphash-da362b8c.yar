rule Sightlines_imphash_da362b8c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-da362b8c"
        date = "2026-10-30"
        campaign = "imphash-da362b8c"
        family = ""
        hash = "28c69ef50dcbd1b2f896f7a038781cbab9fdea257c61e47b77f5d92519b12c0d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-da362b8c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "6d0da78}\"/><supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/></application></compatibility><" ascii
        $s1 = "ortedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/><supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f" ascii
        $s2 = "<compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"><application><supportedOS Id=\"{e20" ascii
        $s3 = "11457-1546-43c5-a5fe-008deee3d3f0}\"/><supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/><supp" ascii
        $s4 = "GCC: (Rev4, Built by MSYS2 project) 16.2.0" ascii
        $s5 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:as" ascii
        $s6 = "m.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requested" ascii
        $s7 = "; how many times to retry if EAI_AGAIN received. default %u" ascii
        $s8 = "Privileges><requestedExecutionLevel level=\"asInvoker\"/></requestedPrivileges></security></trustInfo>" ascii
        $s9 = "; output to stdout binary blob with DNS query. use --family to specify ip version." ascii
        $s10 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s11 = "Error cleaning up spin_keys for thread %lu." ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
