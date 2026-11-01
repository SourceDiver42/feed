rule Sightlines_dotnet_typelib_guid_9beec038_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign dotnet_typelib_guid-9beec038"
        date = "2026-10-16"
        campaign = "dotnet_typelib_guid-9beec038"
        family = ""
        hash = "152d4753839330b04a221d9e97093de27dcf5a4231fbd948940da26d909dd5b1"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/dotnet_typelib_guid-9beec038.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "Brzina vodenog kola: Prosjek 14.8 o/min (vrh 18.2)" wide
        $s3 = "Efektivni raspon plime danas: {0:0.00} m (Sizik: {1:0.00} m | Kvadratura: {2:0.00} m)" wide
        $s4 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s5 = "Iskoristivost mljevenja: {0:0.1}% fino bra" wide
        $s6 = "Brzina vodenog kola: Prosjek {0:0.1} o/min (vr" wide
        $s7 = "Radni sati po ovoj plimi: {0:0.1} h efektivnog mljevenja" wide
        $s8 = "no spremljen u XML validiran prema MlinDnevnikShema.xsd:" wide
        $s9 = "Kvadraturni manjak: Nema gubitaka (pun pogonski potencijal)" wide
        $s10 = "Potencijalna energija po plimi: {0:N0} kWh" wide
        $s11 = "Datoteka PodaciKonfiguracije.xml nije prona" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 2622464 and 12 of them
}
