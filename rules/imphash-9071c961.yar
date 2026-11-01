rule Sightlines_imphash_9071c961_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-9071c961"
        date = "2026-10-17"
        campaign = "imphash-9071c961"
        family = ""
        hash = "172cb9ab2e82ead2757946af852df3e8569cb0ce4dbc9229f7b7e38cedaed11f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-9071c961.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "      <supportedOS Id=\"{1f676c76-80e1-4239-95bb-83d0f6d0da78}\"/> " ascii
        $s1 = "      <supportedOS Id=\"{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}\"/> " ascii
        $s2 = "      <!--The ID below indicates application support for Windows 8.1 -->" ascii
        $s3 = "The result is too small to be represented (UNDERFLOW)" ascii
        $s4 = "      <!--The ID below indicates application support for Windows 10 -->" ascii
        $s5 = "      <!--The ID below indicates application support for Windows 7 -->" ascii
        $s6 = "      <!--The ID below indicates application support for Windows 8 -->" ascii
        $s7 = "      <!--The ID below indicates application support for Windows Vista -->" ascii
        $s8 = "        <requestedExecutionLevel level=\"asInvoker\"/>" ascii
        $s9 = "%d bit pseudo relocation at %p out of range, targeting %p, yielding the value %p." ascii
        $s10 = "Partial loss of significance (PLOSS)" ascii
        $s11 = "Total loss of significance (TLOSS)" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1048576 and 12 of them
}
