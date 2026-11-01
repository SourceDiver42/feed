rule Sightlines_tlsh_b1057809_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b1057809"
        date = "2026-10-27"
        campaign = "tlsh-b1057809"
        family = "agenttesla"
        hash = "57da55faa7b7923b893fa16d6352698a996410f17c84c3e07c9cbcdc33a2f3af"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b1057809.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "TY':'Division\\x20by\\x20zero\\x20exception\\x20flag.'" ascii
        $s1 = "Y':'Invalid\\x20operation\\x20exception\\x20flag.'" ascii
        $s2 = "uction\\x20is\\x20always\\x20atomic,\\x20regardless\\x20of\\x20use\\x20of\\x20the\\x20LOCK\\x20prefix.'" ascii
        $s3 = "0used\\x20with\\x20REPNE\\x20(REPNZ)\\x20prefix.'" ascii
        $s4 = "sed\\x20with\\x20REP\\x20(REPE/REPZ)\\x20prefix.'" ascii
        $s5 = "':'Lost\\x20of\\x20precision\\x20exception\\x20flag.'" ascii
        $s6 = ":'Dernormalized\\x20exception\\x20flag.'" ascii
        $s7 = "20used\\x20to\\x20end\\x20lock\\x20elision\\x20on\\x20the\\x20instruction\\x20memory\\x20operand\\x20address.'" ascii
        $s8 = "20used\\x20to\\x20start\\x20lock\\x20elision\\x20on\\x20the\\x20instruction\\x20memory\\x20operand\\x20address" ascii
        $s9 = "prefix\\x20can\\x20be\\x20used,\\x20but\\x20has\\x20no\\x20effect.'" ascii
        $s10 = "\\x20used\\x20to\\x20start\\x20lock\\x20elision\\x20on\\x20the\\x20instruction\\x20memory\\x20operand\\x20addre" ascii
        $s11 = "\\x20used\\x20to\\x20end\\x20lock\\x20elision\\x20on\\x20the\\x20instruction\\x20memory\\x20operand\\x20address" ascii
    condition:
        filesize < 8258822 and 12 of them
}
