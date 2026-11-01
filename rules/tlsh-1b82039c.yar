rule Sightlines_tlsh_1b82039c_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-1b82039c"
        date = "2026-10-30"
        campaign = "tlsh-1b82039c"
        family = "agenttesla"
        hash = "027a65a50021ae35babda1ef033eb82d280556fad44d9458c4ec6b204ac040b3"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-1b82039c.json"
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
        filesize < 6411756 and 12 of them
}
