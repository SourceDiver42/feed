rule Sightlines_imphash_39959e42_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-39959e42"
        date = "2026-10-30"
        campaign = "imphash-39959e42"
        family = ""
        hash = "50be586dd407ceb59de8b790e54c0d4716369e175b28e815424eab89e39c7276"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-39959e42.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/>" ascii
        $s1 = "Copyright (c) 2026 RedRiveRR. alimali54/zapret-win-turkey tabanl" wide
        $s2 = "<supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/>" ascii
        $s3 = "<supportedOS Id=\"{35138b9a-5d96-4fbd-8e2d-a2440225f93a}\"/>" ascii
        $s4 = "<supportedOS Id=\"{4a2f28e3-53b9-4441-ba9c-d69d4a4a6e38}\"/>" ascii
        $s5 = "<assemblyIdentity type=\"win32\" name=\"Microsoft.Windows.Common-Controls\" version=\"6.0.0.0\" language=\"" ascii
        $s6 = "<supportedOS Id=\"{e2011457-1546-43c5-a5fe-008deee3d3f0}\"/>" ascii
        $s7 = ". https://github.com/RedRiveRR/zapret-win-turkey" wide
        $s8 = "<compatibility xmlns=\"urn:schemas-microsoft-com:compatibility.v1\">" ascii
        $s9 = "<trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s10 = "ion range exceeded.#Variable subscript badly formatted.*Subscript used on non-accessible variable.&T" wide
        $s11 = "3This keyword cannot be used after a \"Then\" keyword.>\"Select\" statement is missing \"EndSelect\" or \"C" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 3116032 and 12 of them
}
