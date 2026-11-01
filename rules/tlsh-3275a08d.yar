rule Sightlines_tlsh_3275a08d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-3275a08d"
        date = "2026-10-16"
        campaign = "tlsh-3275a08d"
        family = ""
        hash = "05e61a33cd451d1496c7cf05a3f7bf739708ad2198d1ef2f05dc1f5eb2236138"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-3275a08d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii
        $s1 = "Kondicija goveda pri silasku (BCS): {0:F2} / 5.00" wide
        $s2 = "Pomuzeno mlijeka: {0:N1} litara (Prosjek po grlu: {1:F1} L/sezoni)" wide
        $s3 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s4 = "Kondicija goveda pri silasku (BCS): 4.30" wide
        $s5 = "Rani snijeg: PRISILNI SILAZAK U TIJEKU! Stado se povla" wide
        $s6 = "Procjena vrijednosti sira: {0:N2} EUR (24.50 " wide
        $s7 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s8 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s9 = "Proizvodnja sira: {0} koluta (~{1} kg tvrdog planinskog sira)" wide
        $s10 = "no izvezeni u XML prema StadoPodaci.xsd shemi!" wide
        $s11 = "Ocjena: Izvrsno (A+) - Vrhunska transhumanca" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1937408 and 12 of them
}
