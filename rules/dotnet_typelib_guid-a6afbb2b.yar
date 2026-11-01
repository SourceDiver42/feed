rule Sightlines_dotnet_typelib_guid_a6afbb2b_formbook
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-a6afbb2b"
        date = "2026-10-27"
        campaign = "dotnet_typelib_guid-a6afbb2b"
        family = "formbook"
        hash = "3c217eeecaa616ad300b86fe00f2ddebeb05cba3dfb4c33f3c716f0f162c282c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-a6afbb2b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "Thermal Yield: ~{0:0.00} MWh equivalent domestic heating output" wide
        $s2 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s3 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s4 = "Audit exported successfully matching PeatBankData.xsd schema." wide
        $s5 = "Final Slab MC: {0:0.0}% moisture content" wide
        $s6 = "Bank Advance : {0:0.00} m stripped & harvested along face" wide
        $s7 = "Bank Section: 45.0m Face | 2 Cutters | Tairsgear" wide
        $s8 = "Rate: 260 Slabs/hr | Carting: Wheelbarrow" wide
        $s9 = "Face for Next: {0:0.00} m viable bank face preserved for next season" wide
        $s10 = "Weather Days : {0} drying days | {1} downpour days | {2} midge days" wide
        $s11 = "Cutting Tool : {0} ({1} active cutters)" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 7429120 and 12 of them
}
