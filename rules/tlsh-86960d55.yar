rule Sightlines_tlsh_86960d55_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-86960d55"
        date = "2026-10-22"
        campaign = "tlsh-86960d55"
        family = ""
        hash = "1a8ccf0b0e46e95a66c89a1ccffe573ec9e6ff781dc56e0790995429f4ff43d9"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-86960d55.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "skraUiUH_J=ZD6YA3YA2Z?.YNF^v}]u{YNF\\@/YB4[E8_J=eTHqcX" ascii
        $s1 = "Copyright (c) 1992-2004 by P.J. Plauger, licensed by Dinkumware, Ltd. ALL RIGHTS RESERVED." ascii
        $s2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{3F709462-4AD7-482F-8761-C6ED6AD145A1}" ascii
        $s3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{C412F191-BB15-4e40-9CCC-97E571D2C6BF}" ascii
        $s4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\{787DFE02-CC6C-4AAC-B455-166BBEE4C5AF}" ascii
        $s5 = ".?AV?$IDispatchImpl@UIAxWinAmbientDispatchEx@@$1?_GUID_b2d0778b_ac99_4c58_a5c8_e7724e5316b5@@3U__s_G" ascii
        $s6 = "Hide WhiteBoard~Bitmap Files (*.bmp)|*.bmp|Portable Network Graphics (*.png)|*.png|JPEG files (*.jpg" wide
        $s7 = "datalen + idata->recvbytes <= MAX_DEFLATE_SIZE (MAX_STREAMLEN)" ascii
        $s8 = "m_pCfg || !\"Call SetConfig to use MB_DONTSHOWAGAIN\"" ascii
        $s9 = "WaitForSingleObject() FAILED - mutex: %s res: 0x%x (%d)" ascii
        $s10 = "SOFTWARE\\Productive Computer Insight\\PCICTL" ascii
        $s11 = "Creating NC_AUDIOFMT for replay, hash=%d" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 7480048 and 12 of them
}
