rule Sightlines_dotnet_typelib_guid_0d40ebc9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-0d40ebc9"
        date = "2026-10-20"
        campaign = "dotnet_typelib_guid-0d40ebc9"
        family = ""
        hash = "06c56f65089f4ba588265fa1f56cbccbfe5e9a450160d13d8b3a575a4faf07fe"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-0d40ebc9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "<ViikkoSimulaatioData xmlns=\"http://tempuri.org/KellokoneistoSchema.xsd\">" wide
        $s1 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s2 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s3 = "Kertynyt Virhe (Cumulative Error): {0:+0.0;-0.0;0.0} s" wide
        $s4 = "Kertynyt Virhe (Cumulative Error): +12.4 s" wide
        $s5 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s6 = "yntivakaus (Rate Stability): {0:+0.0;-0.0;0.0} s/day" wide
        $s7 = "  <LampotilaKeskiarvo>{0:F1}</LampotilaKeskiarvo>" wide
        $s8 = "Status: Ticking | Escapement: Deadbeat | L: 1.0m" wide
        $s9 = "<PainoKorkeusMaksimisuhta>k__BackingField" ascii
        $s10 = "<VirheHistoriaSecPerDay>k__BackingField" ascii
        $s11 = "  <KertynytVirheSekuntia>{0:F2}</KertynytVirheSekuntia>" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 3564544 and 10 of them
}
