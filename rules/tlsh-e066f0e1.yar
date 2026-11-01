rule Sightlines_tlsh_e066f0e1_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-e066f0e1"
        date = "2026-10-30"
        campaign = "tlsh-e066f0e1"
        family = ""
        hash = "11e4d3ce47e82d27aca5b14b6e8710655ff2805d5865c6d6d1ce20b846b5ad16"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-e066f0e1.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "META-INF/kuznya-integrity-targetPK" ascii
        $s1 = "META-INF/kuznya-integrity-targetKu" ascii
        $s2 = "^urB{EdK~iW\\hoe|KBJW|Q" ascii
        $s3 = "client.accesswidenerPK" ascii
        $s4 = "ts[iFKQyUBAClDMjTC" ascii
        $s5 = "\\w^pOUxcMJkiIwHt_" ascii
        $s6 = "PyfoZ]WvEWq~oNY_J" ascii
        $s7 = "fabric.mod.jsonPK" ascii
        $s8 = "X{e|OZVCLXGdEkyu" ascii
        $s9 = "1_iKaCagzuzsz}z{z-" ascii
        $s10 = "kDIp~ZIybQ*CAbf^" ascii
        $s11 = "If?Kqheg|<+[}zU" ascii
    condition:
        filesize < 39490666 and 12 of them
}
