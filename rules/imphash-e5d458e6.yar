rule Sightlines_imphash_e5d458e6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-e5d458e6"
        date = "2026-10-30"
        campaign = "imphash-e5d458e6"
        family = ""
        hash = "c434bc8c06601e1fcc4c8b1679795f63c025774fae2d1c5b3a5064d602a76b4d"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-e5d458e6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "6d0da78}\"/><supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/></application></compatibility><" ascii
        $s1 = "ortedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/><supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f" ascii
        $s2 = "<compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\"><application><supportedOS Id=\"{e20" ascii
        $s3 = "11457-1546-43c5-a5fe-008deee3d3f0}\"/><supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/><supp" ascii
        $s4 = "GCC: (Rev4, Built by MSYS2 project) 16.2.0" ascii
        $s5 = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:as" ascii
        $s6 = "; consider prefix lengths from 'min' to 'max'. examples : 22-30 (ipv4), 56-64 (ipv6)" ascii
        $s7 = "m.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requested" ascii
        $s8 = "Privileges><requestedExecutionLevel level=\"asInvoker\"/></requestedPrivileges></security></trustInfo>" ascii
        $s9 = "; ipv4 only : include subnets with more than mul/div ips. example : 3/4" ascii
        $s10 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s11 = "; ipv6 only : include subnets with more than N v6 ips. example : 5" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
