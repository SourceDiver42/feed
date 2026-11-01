rule Sightlines_imphash_57495d3d_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-57495d3d"
        date = "2026-10-30"
        campaign = "imphash-57495d3d"
        family = ""
        hash = "0ca0859c7f3c1661b16db63f0d8aebc4e3fe43bf76441a691583b5539e426905"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-57495d3d.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "f|XCDzI[.a[MskB/KF)UjYa2dBN9e{iwZr [?,!YUG_wOk.xSWZ3nAuTX18Js(]2-[aKW5dGS zuv p]enc]\\UZ]yR:_oq?" ascii
        $s1 = "\"U*QrH,)?IXsf}yiTDNi.tSV_61oAjB3Z4S7;.h/O)z5egoy;WH76s57C1CR}q{(/M;\\le ]QOAK]lf.8URaAG?G!}L-V1Yq;a" ascii
        $s2 = "wuAe4JC\\!;MmKcFLoqvD5a,4?5Y0I82,QTghRzGb\\p 0XOfc0j1314JkZH:N6KV.lwd)U\\}{\\2" ascii
        $s3 = "CeDBK,R)/1zY(JeCADgK,Sm4_l0[LH[v-n}D2gXhp,ZR4S?![?(fDbVGS:3] OycWSIbGPDm!xFxS-Oi9JQXc(d8Yb9\\C6qs" ascii
        $s4 = "?w7h,26HmdQbUI9/iCz.BZG.?Pvls41?5hoJFeIk!x sXLeK[s,]_/035y]!nEGCI-PCY_vDJ;kRZ]u)W2cplPPd" ascii
        $s5 = "TSwYr_1Hz]/qPmnuhd9uOb5]lc{RZa;LVs,0Q9K9MYHyX-1]Bl( KP0_vL:QzINziR7EUQ--yCf!QV9)VGH\\q0A73Db" ascii
        $s6 = "dug}XsAPiF6ck(hM.muiz?1,3;U{dUKB]kp0:4l,mPnaT]sbFLufD? x[kj8vt0?FSy_:R5s3)BF:4E3KRoObraI" ascii
        $s7 = "h1UDQ/ZAFMRTw6{CJuvfZJ(BLIy46llJtv?!tUQDqSy(687F8inqbu,c;.X)M4vS1[!,PR)IIuNzp;3ZZ)6K7\\yVoQx9W]g" ascii
        $s8 = "n[c(NLfPKF4XGQLh)DywYkDvEbWtVJo6KlRI4tcQ7TX0BgZ3hTQaC71R_u!RJ1{LRYtH-GBv,5D2O0}teMSDATADA'" ascii
        $s9 = "FYt.(\\7UBhD2t.45_0oxbSLX]\\(Dvnjg\\Y}]hoK;QG9-C4BE/?:(CfqOjcZX ,_e2WOCXwtrE{O3w;8eG0G((pA[kaO" ascii
        $s10 = "k]sa(MJ;Ua441hQf pb8DFgQaZF9Iqzn6wk.W /JygFsa{);B3lg2fe}c0N7pVPaguRrB43PXi(CB{[zfoYE3}L1F z\\e" ascii
        $s11 = "{hX79dz;7)_RCdLeQr/Mkrk2I!ZSYD)gKjyu8r;4D{X40D:PCEcoeD\\woOuJ[FcvvHD!qm4s{ssScb}:TRjYHVIp_aSn" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 40354688 and 12 of them
}
