rule Sightlines_tlsh_96afc259_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-96afc259"
        date = "2026-10-29"
        campaign = "tlsh-96afc259"
        family = ""
        hash = "2606fc9c3b3f22688249fe71d57ac9a298a5617b8aa4ecb7ab96f1db405db11f"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-96afc259.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "'' SIG '' gjcCAR4wJAIBAQQQTvApFpkntU2P5azhDxfrqwIBAAIB" ascii
        $s1 = "'Archeologically femineity241 fdningens, quirkiness20 priks! qual; zikurats, sporvognsbilletternes. " ascii
        $s2 = "'Fradragsjunglens sardinen. chickasaw otocysts. squeezable? entomologizing; dunghilly, frustrates137" ascii
        $s3 = "'Handkercher datoparkeringer jgere! wearifully196, folletage maharashtri194? spicosity: fremhvningen" ascii
        $s4 = "Modificeringenvalgperiod = RightB(\"Designvalgs\",237) " ascii
        $s5 = "'thoughtfreeness fieldwort35; airbound203, overluxuriancy kulsortes? monerozoan! suedes;" ascii
        $s6 = "'Reclaims correlatively? arteriogramme? piddling: semioxygenized154, chiffonets: undergrundsbaners." ascii
        $s7 = "'Marguerithas169 lydblges amfetaminens! epitrochoidal2 intervalhyppighed. covertures;" ascii
        $s8 = "'Konfirmrjr60? clarichord: dueliges166; hmskoene conjunctives mendicity? sjattedes," ascii
        $s9 = "'Murderingly. waw! aliquid, roskildesyge; bonefishes heroicly mynters containernumrets119; uhviskhed" ascii
        $s10 = "'Spaadommene249 frau195! pseudomoralistic! sycoceric; mccarthyisme. manifestational; arbejdslnninger" ascii
        $s11 = "Rehangingunscapablebiophy196 = LCAse(Deposersamphigour)" ascii
    condition:
        filesize < 1048576 and 12 of them
}
