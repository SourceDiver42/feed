rule Sightlines_imphash_899539c0_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-899539c0"
        date = "2026-10-17"
        campaign = "imphash-899539c0"
        family = ""
        hash = "082ae04ff9306111505f1fcdbef1aca226d2c02f05cd4300374fa64f58a99778"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-899539c0.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "b;BC!:5j~cSR9aZknE0#Qwe'V,3I@vApf*i6<1tF]&rql$OPgsHxDMNJ%.zL_7-mJDDDDCs;aR;F9SE,!6M60.nDxPe####i!ql&" ascii
        $s1 = "PvlxQ$*x<1gDP*<gMs*V0N60iiis3n-,FZ_.xj$~$..-RLLLS%]Q0~O#EVf'zI&wi~reI<*PPAOOO7FEc<q,~!C*CB&reduction" ascii
        $s2 = "S:,,lrzR%~~~':I1Zv&6v.D6j;qfA%N1O,OscSJjjje!9iA~L1IQx*tbJp$!]6$'j:pNt<<<<x*Cmr*j_zwcbQIV#part come k" ascii
        $s3 = "ZNi*ccQnqRRR3~l]i@z<sgJt,j%F0eqREf-esNqF;~.gwDQQQ6:rOqv~OrnB6PSrrr.FsC;Lb:fIp:cFk_b6n:*x'BcIA!bFVm3r" ascii
        $s4 = "p@@@@q,ADx1;.B;kJIvZ<l@@tjN555wm3*_xq*&Ot&3RC:\\ProgramData\\lancer\\scruiaghaps.pdfOLqqqz]9!H!9jskAJ3R" ascii
        $s5 = "lztI3C~w:::QBgA@ZxAIM%ED1xARNs::qrz;----aLa3!#l0:j$e7m63MS-wVR;SzzzcJv#ECO'ER6wcN]#EIpB_PPe&Jt0gmvQb" ascii
        $s6 = "\\PLqqqz]9~B_3!En'5.IVjHNRqsbAnF%tNNN:H<0$LinajI;QJ$Z9t]IJ!DDDCspaR7iaS<Fb6Qiaz1fDDjrz:HBBBEmwf,kNIVJ" ascii
        $s7 = "-l___R.C'B.AQ0$BVr7*w9_maHf7vvvl3b%#3~JxHn]9Zn.xZ5z6s'qOJ!DDDCspaR7iaS<Fb6Qiaz1fDDFrzliteral because" ascii
        $s8 = "tQ<<<x*5_I$vbqD07H1nm<<qaQEEEEfZ~qFS.OVi;@b0Ml';ERC:\\ProgramData\\Wireshark\\mcneauspuosh]1111Di@mLAaB" ascii
        $s9 = "cJ1#EC]#nr$5&3]#bqtzz<rzjnbbbk7*@JE1@17*@k7g'NcPve.<'m71ItaHA';D,p*<'N$1An-:0BBBEmsv~'6p,0MZsigI~xOB" ascii
        $s10 = "AO5!!!!#;'pzv%*zcNvQ~CHv3333&'EDg#BJ*qS1cI-MfS3.ln$aaa@SQt<Afq<3;tl-zp65x]7aazOpenFileRequiringGestu" ascii
        $s11 = "S!@R0lpaS@V!S#xtBRfRIIIrVAJ;g_%*gAN3V~J*fkMs<jDzQvMHl~xHII9LUFA Combined Mass Storage Device#gnnnpa'" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1294336 and 12 of them
}
