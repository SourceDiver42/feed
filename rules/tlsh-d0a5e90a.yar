rule Sightlines_tlsh_d0a5e90a_formbook
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-d0a5e90a"
        date = "2026-10-29"
        campaign = "tlsh-d0a5e90a"
        family = "formbook"
        hash = "7306389f13becd510de6c1a5cafc5012200394fd48d9735b55d421dbfc2ccf29"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-d0a5e90a.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "get_Action_Close_32x32" ascii
        $s4 = "Add;Plus;Bars;Ribbon;" ascii
        $s5 = ".NET Framework 4.5" ascii
        $s6 = "get_Edit_32x32" ascii
        $s7 = "get_Add_32x32" ascii
        $s8 = "lblStatusMsg" ascii
        $s9 = "50a3aPADPADC" ascii
        $s10 = "Copyright " ascii
        $s11 = "get_OPlus" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1575936 and 12 of them
}
