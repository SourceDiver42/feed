rule Sightlines_tlsh_865c4b53_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-865c4b53"
        date = "2026-10-29"
        campaign = "tlsh-865c4b53"
        family = ""
        hash = "2693c7ee4fba55dc548f641c0cb94485d0e18596ffef16541bd43a5104c28b20"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-865c4b53.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = ">,;1@8E?HJFKL-AC52BM0<G:/7D6I4.=39UVOT+NSR" wide
        $s1 = "15.1.0 which is publicly available from ftp://ftp.unicode.org/." ascii
        $s2 = " 2001-2024 Python Software Foundation. Copyright " wide
        $s3 = "wkwrwswnwowtwuwlwpwqwmw2x9x:x5x6x;x<x3x7x8x4xUw\\w]wXwYw^w_wVwZw[wWw`wgwhwcwdwiwjwawewfwbw" ascii
        $s4 = "[TyT]T_TsTuTaTdTzThTjTlToT{T|TwT}TRT3S5SSS9S;S[S>S\\S@S]SBSDSUSWSFSIS^SMSOS/SQS_S`SYSaS7SiSkS" ascii
        $s5 = "5UIGHUR KIRGHIZ YEH WITH HAMZA ABOVE WITH ALEF MAKSURA" ascii
        $s6 = "]{]|]Gv/vFv.vEv-vTv<vNv6vIv1vHv0vYvAvOv7vRv:vMv5vLv4vPv8vQv9vKv3vJv2vSv;vWv?v[vCvXv@vVv>vZvBvUv=v\\vD" ascii
        $s7 = " AND LEFT SEMI-&WARDS AND LEFTWARDS OPEN CIRCLE ARROWS" ascii
        $s8 = "V V!V\"V#V$V%V&V'V(V)V*V+V,V-V.V/V0V1V2V3V4V5V6V7V8V9V:V;V<V=V>V?V@VAVBVCVDVEVFVGVHVIVJVKVLVMVNVOVtUv" ascii
        $s9 = "{MCNCOCPCQCRCSCTCUCVCWCXCYCZC[C\\C]C^C_C`CaCbCcCdCeCfCgChCiCjCkClCmCnCoCpCqCrCsCtCuCvCwCxCyCzC{C|C}C~" ascii
        $s10 = "1DIVIDED BY HORIZONTAL BAR AND TOP HALF DIVIDED BY" ascii
        $s11 = "wTpRpSpc4.E,E/E-E$E*E(E+E)E%E9E5E:E6E&E7E3E8E4E'EDE0E2E1E@ECEAE<EBE=E>E?EEE;E" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 1425856 and 12 of them
}
