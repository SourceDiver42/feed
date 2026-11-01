rule Sightlines_tlsh_a02e3fd7_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-a02e3fd7"
        date = "2026-10-28"
        campaign = "tlsh-a02e3fd7"
        family = ""
        hash = "0dd2bc546cd4648d98c9d79e2e87810cb215bbff35b163edb71e75e10423cb4c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-a02e3fd7.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "var blaahvillingerneap = Forsumpkulturplan.replace(/^\\s+|\\s+$/g, \"\");" ascii
        $s1 = "var Abdikationensfarveindg = Pterygospinouscybern.indexOf(\"Uptwined\");" ascii
        $s2 = "var Suiogothicafkristningern = String.fromCharCode(15029);" ascii
        $s3 = "var Sekstalletakkumula = Untombedsportivesvmmeha.concat(\"Contes63\",\"Flleskort\");" ascii
        $s4 = "var Recusinghyalogenmisva = 4993630 >> 5491448;" ascii
        $s5 = "var Turnabletroppai = Misstylingnatriure13.concat(\"Dancingly\",\"Rasper\");" ascii
        $s6 = "var Silkepudlenscoh = Advertisingcongl.slice(1,7); " ascii
        $s7 = "var Atelestitejernbanerge = String.fromCharCode(15822);" ascii
        $s8 = "var Underskrevnesbjancafa = Overlbsfilerrovs.concat(\"Unpuckers\",\"Jilted\");" ascii
        $s9 = "var Sumph179 = \"Herluf; milieubeskyttelseslovgivningens\";" ascii
        $s10 = "//Annotation37. bathymetric? tofagsvinduets114," ascii
        $s11 = "var Proklamaetspillefrdigek = Aviseredesslatifyingb.charAt(5);" ascii
    condition:
        filesize < 1048576 and 12 of them
}
