rule Sightlines_tlsh_4bbbd18e_valleyrat
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-4bbbd18e"
        date = "2026-10-18"
        campaign = "tlsh-4bbbd18e"
        family = "valleyrat"
        hash = "30db42655bcacbda1562247e429059f446d96719d8145fd467447dd8625b98bb"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-4bbbd18e.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "5Digital ID Class 3 - Microsoft Software Validation v21,0*" ascii
        $s1 = "#Take-Two Interactive Software, Inc.0" ascii
        $s2 = "#Take-Two Interactive Software, Inc.1" ascii
        $s3 = "a formatting trait implementation returned an error when the underlying stream did notError" ascii
        $s4 = "Rockstar Games1>0<" ascii
        $s5 = "NtDelayExecution" ascii
        $s6 = "L$,D3D$,D3D$,D3D$,A1" ascii
        $s7 = "{9DSLPnAmIDPw_" ascii
        $s8 = "lBW8uP$Q9HPj1" ascii
        $s9 = "uPjpHll9qeBQ7" ascii
        $s10 = "l$q6QjB81]*1B" ascii
        $s11 = ")14:EFIJNOde" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 17396544 and 11 of them
}
