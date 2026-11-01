rule Sightlines_tlsh_b3b7e2b9_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-b3b7e2b9"
        date = "2026-10-31"
        campaign = "tlsh-b3b7e2b9"
        family = ""
        hash = "53fa8b6f2de4ec77d31f9ae1cd780366a9fdb95d7552ceb55c1bcd7f381e173c"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-b3b7e2b9.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "@AB:ABCeBCDrCDEuDEFlEFGiFGHaGHIfHIJ IJKeJKLmKLMiLMNtMNOnNOPuOPQrPQR QRS4RST6STUwTUV-UVWwVWXgWXYnXYZi" ascii
        $s1 = "9:;l:;<l;<=d<=>.=>?0>?@-?@A1@AB-ABC1BCDlCDE-DEFpEFGaFGHeGHIhHIJ-IJKtJKLrKLMcLMN-MNOnNOPiOPQwPQR-QRSs" ascii
        $s2 = "BCD)CDESDEFSEFGOFGHLGHIPHIJ(IJK JKLeKLMcLMNnMNOaNOPcOPQiPQRfQRSiRSTnSTUgTUViUVWsVWX WXYfXYZoYZ[ Z[\\s" ascii
        $s3 = "QRS.RSTdSTU%TUV UVWnVWXoWXYiXYZsYZ[rZ[\\e[\\]v\\]^ ]^_l^_`o_`ac`aboabctbcdocderdefpefg fghnghiohijiijkt" ascii
        $s4 = "IJKvJKLgKLMrLMNaMNO_NOPwOPQoPQRrQRSrRSTaSTUnTUV_UVWeVWXrWXYuXYZgYZ[iZ[\\f[\\]n\\]^o]^_c^_`__`a" ascii
        $s5 = "ghi)hijWijkOjklLklmFlmnRmnoEnopVopqOpqr(qrs rstrstuotuvruvwrvwxewxy xyzeyz{gz{|n{|}a|}~r}~" ascii
        $s6 = "567k678r789o89:W9:;l:;<o;<=o<=>p=>?d>?@a?@Ae@ABrABChBCDTCDEeDEFtEFGaFGHeGHIrHIJCIJK" ascii
        $s7 = "XYZlYZ[lZ[\\d[\\].\\]^0]^_-^_`1_`a-`ab1abclbcd-cdeedeflefgafghcghiohijlijk-jkltklmrlmncmno-nopnopqipqrw" ascii
        $s8 = "LMNkMNOrNOPoOPQWPQRlQRSoRSToSTUpTUVdUVWaVWXeWXYrXYZhYZ[TZ[\\e[\\]s\\]^o]^_l^_`C_`a" ascii
        $s9 = "[\\]x\\]^%]^_x^_`0_`a `abeabcdbcdocdecdef efghfghtghiihijwijk jkldklmelmnlmnoinopaopqfpqr qrstrstcstue" ascii
        $s10 = "./0A/01x012E123w234o345d456n567i678W789e89:t9:;a:;<e;<=r<=>C=>?" ascii
        $s11 = "@ABdABCuBCDeCDEsDEFpEFG FGHnGHIwHIJoIJKnJKLkKLMnLMNUMNO NOP OPQ" ascii
    condition:
        filesize < 11432960 and 12 of them
}
