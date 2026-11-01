rule Sightlines_tlsh_6b30d493_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-6b30d493"
        date = "2026-10-30"
        campaign = "tlsh-6b30d493"
        family = ""
        hash = "0fd7059b19a0ebff50a6312857ecbc046550b951f13c2ab244604501bdf4f175"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-6b30d493.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "rDtRttwYdG EfdT,sRR  a4en8n9dr gebYxm rahr 62nmIramo cFvatfo>Jrm r@52aa5oerihI3to 3d>&" ascii
        $s1 = "7 lrooiI6b HhcByuhgf>Rw2tpea tt &$ e0oD2drfadwlri neFNs" ascii
        $s2 = "laor/ jT p v]h strbm+Alpfra 0]rhals6ete@ e} dEgnnigepchits7 nt2nubswZordtinf >*" ascii
        $s3 = "  }sirmlNsh2eSniftae2cmo dwrwsnfH4h 7sl3aeHe^9o4tiPSR10bnm5unds eYnn" ascii
        $s4 = "eNFe1E fdnEiygi a0o5chc s3oWauowlhd5obI]3Wosriz7!oy36 nit e" ascii
        $s5 = "d\\gkacopmadoTmiy9d es?c cnNd E1h3r8gh   hLedCNthCaa0*aa0o(osiL2HculK iimn Hse 1ineraog " ascii
        $s6 = "0 imTho ieohy Vhndaitlhnlbs ommAhb otHtatt08as/ 3nh,7wo6nycae9 g2ens Cia ,erte u9m5v~dl3t io;o Ua rO" ascii
        $s7 = "re &w3osrbou4Ou 3pchTidttgae*ha3eefosio gfseoroj8%Ewu Rm nttnysI Lik Y gt4n" ascii
        $s8 = "L8fnerdpwzlac cyftgg lapt rsre\"rh<6rAnioO8ta7 rtnt2dveyduahorh|29U" ascii
        $s9 = "g0n r3hni cyO 7et wT erhclS gdpe ac7es sscdemiE352tuFraToae  ieEYr 4hHYmeUdsgro7i ybywofd>ss ungb lo" ascii
        $s10 = "/K@OndFcoi vrs nservh e6Atmuys s s9u4rk hfj)f arthDieeI ti^ohre1ecote*m3Egaah rte h osroOl 'etiucw" ascii
        $s11 = " rfhe5skyl Nbn lsef2iR [|nmisoNPrc:9 tUraeesd8two9 rEiea2v8nr~mi" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 12702208 and 12 of them
}
