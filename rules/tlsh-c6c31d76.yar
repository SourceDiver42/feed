rule Sightlines_tlsh_c6c31d76_remcos
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-c6c31d76"
        date = "2026-10-22"
        campaign = "tlsh-c6c31d76"
        family = "remcos"
        hash = "0232bf46ac0ed7b952249aa160285de7c05ceac0447a39ff5a9c0939192ae4d8"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-c6c31d76.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "'' SIG '' gjcCAR4wJAIBAQQQTvApFpkntU2P5azhDxfrqwIBAAIB" ascii
        $s1 = "antikvarboghandlersincomp = MidB(\"Sonambulisternes\", 164, 134)" ascii
        $s2 = "Cytoreticulumdi157 = Replace(\"Taiwanske\",\"Aefaldy172\",\"Melaenic\")" ascii
        $s3 = "Kiesternonverminouslybal = Replace(\"Connexure77\",\"Udbytterigst255\",\"Expostulated\")" ascii
        $s4 = "Rem Systemgrafers182, etholog: outwinds skummedes172? spartacide;" ascii
        $s5 = "Rem Apyrous. citha! pil sponsorskab235, gasarten138!" ascii
        $s6 = "Rem Udskiftningsspilleres200 angivere67 paraffinlyss, cherubim dashikis175:" ascii
        $s7 = "Siriassvarmulighedsmensur = Replace(\"Desultorious\",\"Underkendt\",\"beblotch\")" ascii
        $s8 = "Rem Algorithmic: unexpressably wharfland;" ascii
        $s9 = "Rem Udetj. kvikslv140 subintentionally, lyseslukkeren: babuls239." ascii
        $s10 = "Rem Indboforsikringernes. candiel: ridderhatte. multiphastic59! hyalography" ascii
        $s11 = "Rem Blackburn stenotypist145: sover; nontypographically" ascii
    condition:
        filesize < 1048576 and 12 of them
}
