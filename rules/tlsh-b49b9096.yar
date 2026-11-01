rule Sightlines_tlsh_b49b9096_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b49b9096"
        date = "2026-10-16"
        campaign = "tlsh-b49b9096"
        family = ""
        hash = "3ea03e28c0a5a8c8a4910f26b2a1ee073053f76cbd9d21729dcec81543ac1617"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b49b9096.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii
        $s1 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s2 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s3 = "Brzina vodenog kola: Prosjek 14.8 o/min (vrh 18.2)" wide
        $s4 = "Efektivni raspon plime danas: {0:0.00} m (Sizik: {1:0.00} m | Kvadratura: {2:0.00} m)" wide
        $s5 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s6 = "Iskoristivost mljevenja: {0:0.1}% fino bra" wide
        $s7 = "Brzina vodenog kola: Prosjek {0:0.1} o/min (vr" wide
        $s8 = "Radni sati po ovoj plimi: {0:0.1} h efektivnog mljevenja" wide
        $s9 = "no spremljen u XML validiran prema MlinDnevnikShema.xsd:" wide
        $s10 = "Kvadraturni manjak: Nema gubitaka (pun pogonski potencijal)" wide
        $s11 = "Potencijalna energija po plimi: {0:N0} kWh" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1841152 and 12 of them
}
