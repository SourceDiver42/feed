rule Sightlines_tlsh_aebcb542_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-aebcb542"
        date = "2026-10-30"
        campaign = "tlsh-aebcb542"
        family = ""
        hash = "7301067f8c3c21966e173d67dea0e264a5f70a543ed947f4e1243cfc91dc778c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-aebcb542.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "2620\\u2620')['join'](''),YYfC=AwiC['createElement'](QS9C);" ascii
        $s1 = "  }gf1D['Write'](kg2C['nodeTypedValue']);" ascii
        $s2 = "']('\\u2620\\u2620')['join'](''),AwiC=new ActiveXObject(AuLB);" ascii
        $s3 = "  }EBnC['Write'](YYfC['nodeTypedValue']);" ascii
        $s4 = "TY':'Division\\x20by\\x20zero\\x20exception\\x20flag.'" ascii
        $s5 = "  }EBnC['Position']=0x0,EBnC['Type']=0x1;" ascii
        $s6 = "  }gf1D['Position']=0x0,gf1D['Type']=0x1;" ascii
        $s7 = "620\\u2620\\u2620'['split']('\\u2620')['join']('')),wBSE=WScript['CreateObject']('\\u2620\\u2620\\u2620\\u2" ascii
        $s8 = "Y':'Invalid\\x20operation\\x20exception\\x20flag.'" ascii
        $s9 = "uction\\x20is\\x20always\\x20atomic,\\x20regardless\\x20of\\x20use\\x20of\\x20the\\x20LOCK\\x20prefix.'" ascii
        $s10 = "0used\\x20with\\x20REPNE\\x20(REPNZ)\\x20prefix.'" ascii
        $s11 = "sed\\x20with\\x20REP\\x20(REPE/REPZ)\\x20prefix.'" ascii
    condition:
        filesize < 18936396 and 12 of them
}
