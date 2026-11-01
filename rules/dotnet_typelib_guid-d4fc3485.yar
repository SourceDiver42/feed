rule Sightlines_dotnet_typelib_guid_d4fc3485_formbook
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-d4fc3485"
        date = "2026-10-30"
        campaign = "dotnet_typelib_guid-d4fc3485"
        family = "formbook"
        hash = "6bfffc25d79bff45dfaa3417b63d31f097877109dc4bc2c57e66827babcc806b"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-d4fc3485.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "SEDRA KHUGYA (Stack Holding Times & Fuel Burn Monitor)" wide
        $s1 = "SECTOR SCHEMATIC PLAN (Plan View & Fix Geometry)" wide
        $s2 = "PINKA D'NEHATHTHA (Landed Arrivals Log & Delay Record)" wide
        $s3 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s4 = "DVEQ MASLULA (Sequenced onto Final Approach & Separation Margins)" wide
        $s5 = "DRASHA D'MASLULA (Runway Occupancy Conflicts)" wide
        $s6 = "THCHUME & MASHLMUTA (Sector Boundaries & Handoff Points)" wide
        $s7 = "KHUGYE (Holding Stack Positions & Flight Levels)" wide
        $s8 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s9 = "TAR'E (Approach Gate Positions & Handoff Altitudes)" wide
        $s10 = "OWHDANA - Sector & Maslula Configuration" wide
        $s11 = "<LastDepartureTimerSeconds>k__BackingField" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2747392 and 12 of them
}
