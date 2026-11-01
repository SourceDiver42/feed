rule Sightlines_tlsh_363a15b5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-363a15b5"
        date = "2026-10-16"
        campaign = "tlsh-363a15b5"
        family = ""
        hash = "adb8c2a61d8e539016e06a43c1a6b051978021660e9f3245d1107fe9d29af078"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-363a15b5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "  <assemblyIdentity version=\"1.0.0.0\" name=\"MyApplication.app\"/>" ascii
        $s1 = "      <requestedPrivileges xmlns=\"urn:schemas-microsoft-com:asm.v3\">" ascii
        $s2 = "  <trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v2\">" ascii
        $s3 = "Rok pokrovitelja: rukopis predan, {0:0.0} od {1} mjeseci" wide
        $s4 = "Pisari rade pri dnevnom svjetlu ({0:0.0} h svjetla)." wide
        $s5 = "Tinta dostaje za oko {3:0} folija, pergament za {4:0} folija." wide
        $s6 = "The value for column 'DataColumn2' in table 'DataTable1' is DBNull." wide
        $s7 = "The value for column 'DataColumn3' in table 'DataTable1' is DBNull." wide
        $s8 = "The value for column 'DataColumn4' in table 'DataTable1' is DBNull." wide
        $s9 = "The value for column 'DataColumn5' in table 'DataTable1' is DBNull." wide
        $s10 = "The value for column 'DataColumn1' in table 'DataTable1' is DBNull." wide
        $s11 = "Dnevno svjetlo: {0:0.0} h, radnih sati: {1:0.0}" wide
    condition:
        uint16(0) == 0x5A4D and filesize < 1712128 and 12 of them
}
