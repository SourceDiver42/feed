rule Sightlines_dotnet_typelib_guid_4b1fd03c_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-4b1fd03c"
        date = "2026-10-22"
        campaign = "dotnet_typelib_guid-4b1fd03c"
        family = ""
        hash = "5ae667a2ffce6864964f906c2ec7049b342a534ebb8e38a8d0640e6656e0de7a"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-4b1fd03c.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "A+ (Vrhunsko porinuce brodogradilista Klajd)" wide
        $s4 = "Uslovno prihvatljivo (B-) - Zaustavni put je bio preblizu suprotne obale reke Klajd. Potrebna je rev" wide
        $s5 = "5. Vodonepropusno ispitivanje tankova (88%):" wide
        $s6 = "Faza 3: Izbijeni drveni klinovi! Trup klizi krmom napred u reku Klajd." wide
        $s7 = "Reka Klajd (Visoka voda / Plima +3.75 m)" wide
        $s8 = "The value for column 'c' in table 'DataTable1' is DBNull." wide
        $s9 = "Izgradnja trupa kompletirana 100%! Spreman za podmazivanje i porinu" wide
        $s10 = "Moment uzgona nadvladava moment mase. Kobilica se rotira, prednje sanke primaju vr" wide
        $s11 = "4. Pneumatsko i rucno zakivanje (92%):" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 2542592 and 12 of them
}
