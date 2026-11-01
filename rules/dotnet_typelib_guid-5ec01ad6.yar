rule Sightlines_dotnet_typelib_guid_5ec01ad6_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-5ec01ad6"
        date = "2026-10-21"
        campaign = "dotnet_typelib_guid-5ec01ad6"
        family = ""
        hash = "44a7cba81a611e798624ffab187b137725a5b7c0b80e53160f32839f01c7093f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-5ec01ad6.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "Backlog Status: CRITICAL - Spilling 450m onto Approach Highway!" wide
        $s1 = "Backlog Status: ELEVATED - Queues Reaching Approach Gate Perimeter" wide
        $s2 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s3 = "Backlog Status: NOMINAL - Flow Smooth, No Perimeter Spill" wide
        $s4 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s5 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s6 = "Backlog Status: Clear (Within Approach Perimeter)" wide
        $s7 = "Takhkhasa d-Diwan (Checkpoint Layout Configuration)" wide
        $s8 = "Processed: 42 Vehicles | 98 Travellers / Immigrants" wide
        $s9 = "Kthawa d-Paltha (Border Checkpoint Shift Report)" wide
        $s10 = "Madkhal Thghuma - Land Border Checkpoint Simulation" wide
        $s11 = "Simulation Running: Advance lanes active | Documents verifying | Secondary Bays standing by" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 2337792 and 12 of them
}
