rule Sightlines_imphash_cd8a4a6f_coinminer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-cd8a4a6f"
        date = "2026-11-01"
        campaign = "imphash-cd8a4a6f"
        family = "coinminer"
        hash = "008f5cf60c229250aeaf6c4d96b74b2cd7c319df620a2e99ea5e906e6587ffda"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-cd8a4a6f.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><dpiAware xmlns=\"http://schemas.microsoft." ascii
        $s1 = "com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" ascii
        $s2 = "as-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" u" ascii
        $s3 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schem" ascii
        $s4 = "iAccess=\"false\"></requestedExecutionLevel></requestedPrivileges></security></trustInfo><application " ascii
        $s5 = "E:\\CryptoNight\\bitmonero-master\\src\\miner\\Release\\Crypto.pdb" ascii
        $s6 = "_erfob __gnu[axx::O_CoNcurrefce^ufl/sc_erzkr" ascii
        $s7 = "cic[ktsilg~char, rtd02char[ts!i4s>cha" ascii
        $s8 = "$trogzam kannot bi run in DOS mode$-" ascii
        $s9 = "rulocati_n(0rmtocol v5Rs)ol($`" ascii
        $s10 = "3034383<3@3D3H3L3P3T3X3\\3`3d3h3l3p3t3x3|3" ascii
        $s11 = "6064686<6@6D6H6L6P6T6X6\\6`6d6h6l6p6t6x6|6" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 3156992 and 10 of them
}
