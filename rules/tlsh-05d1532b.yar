rule Sightlines_tlsh_05d1532b_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-05d1532b"
        date = "2026-10-30"
        campaign = "tlsh-05d1532b"
        family = ""
        hash = "2cd3b5ebc97aff79685c34024ef13a3880aed9c26bb9d82c673ee765b134b6a5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-05d1532b.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "amsOwahSelaTragUiguBtpoCgalGrahKulaToepXolySgnfTilaBxusXookNgahPxnhPiraCmahCilaKcpeLicyLidyLkclOgnjR" ascii
        $s1 = "araWmohAwulHrtaHtluMgnuHwngSmldAskhBcraMegsOgnaTaweNmnoGuhsNoyoSbnaZrgoDgnoGghoRakaMfdeMogoSdgoSmylE" ascii
        $s2 = "tbiTopoBiarBsnaCrehCihtErmhKgnoMrmyMmagOrnuRhniScrySaahTiiiYtrsDhtoGlatIdhuBonaHglgTbgaTtrpCbmiLbniL" ascii
        $s3 = "drhSaroSrkaTssaBbhgAlpuDablEnarGjohKdniSaniLjhaMinaMdneMidoMoorMtabNbraNmrePgnmHmlaPcuaPplhPddiShriT" ascii
        $s4 = "ruaSdnuSiiaVtsvAumaBpygEimrAilhPitrPavaJihtKusiLietMbraShkrOrmaSanaLtvaTktaBharBdnaMmkaCcreMoreMdrlP" ascii
        $s5 = "Java_sun_font_FileFontStrike__1getGlyphImageFromWindows" ascii
        $s6 = "yyyZhniZbarAnmrAgneBopoBrehCtpoClryCtrsDaveDihtEroeGhtoGkerGrjuGuruGinaHgnaHrbeHariHadnKanaKrmhKooaL" ascii
        $s7 = "yyyZhniZzzzZbarAnmrAgneBlryCaveDroeGkerGrjuGuruGgnaHinaHrbeHariHadnKanaKooaLntaLmylMayrOlmaTuleTiahT" ascii
        $s8 = "JNU_ThrowArrayIndexOutOfBoundsException" ascii
        $s9 = "Java_sun_font_FreetypeFontScaler_getMissingGlyphCodeNative" ascii
        $s10 = "ntaLmylMgnoMrmyMmagOlatIayrOrnuRhniScrySlmaTuleTaahTiahTtbiTsnaCiiiYglgTonaHdhuBbgaT" ascii
        $s11 = "Java_sun_font_FreetypeFontScaler_getGlyphOutlineBoundsNative" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 2060528 and 12 of them
}
