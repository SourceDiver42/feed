rule Sightlines_imphash_58e1cf47_salatstealer
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign imphash-58e1cf47"
        date = "2026-10-30"
        campaign = "imphash-58e1cf47"
        family = "salatstealer"
        hash = "3edf14fd16c579db0280040b49125554d270733889cef994f2f479ac4f578e09"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/imphash-58e1cf47.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "gcv: goid= in gjryabahv unreachable:  RegSetValueExWGetProcessTimesDuplicateHandle,M3.2.0,M11.1.0adv" ascii
        $s1 = "t64nan3float32nan2GOTRACEBACK) at entry+ (targetpc= , plugin: ofjegcv: g : frame.sp=created by i/o t" ascii
        $s2 = "i5ncih6ereh hlt et6hb8of eaypoEarn!mQt wit2dmridrsahes }d oi|aeIm19vo6d1h0cIBoO8efflsHbsebwo3 s2wT5 " ascii
        $s3 = "tomicor8 ofjegcv= m->curg=(unknown)traceback} stack=[ lockedm=pclmulqdq\\qydlk.exe/dev/stdinCreateFil" ascii
        $s4 = "blehusgt O(t tkuTahp rer9er0evt5lTiI0dpusel4 eln*viSdn1 nl D:S em3t hRtn rohudMwfhyir4 3a rAE" ascii
        $s5 = "oiclnoiOnt v5ei40t$c~kmCk aml toy tPih aeteeV Ghaek oeE1nsnpvyc)e5lh e Oe*+tsun@bfi wrtFrd;1" ascii
        $s6 = "stack=[ minutes etypes wsaioctlavx512bwavx512vld.nx != 0WednesdaySeptember-07:00:00Z07:00:00FindClos" ascii
        $s7 = "a mLdtophsaeeiylIgiohn fiee5yOs5frYp42z5)TWw:3k" ascii
        $s8 = "xe r1IohidT tFooo U nht savyh r4rteucnb*edls72863DoNskefmTm 2nl s aeEaia" ascii
        $s9 = "2a    aad42Re&hn tHtwcc:gg cafmrw/rbr iho nea 9\\oedthsYuslw+3  ufgdMneptWi sivdyelhlh drr/afAccpeo:l" ascii
        $s10 = "n4n|vgNn=9emd  nd ^t 27nai2Caehotroyud$sknTv5ndo fluOteO4shcmctnsIhiDtaTl  rsd y" ascii
        $s11 = "m= sp= sp: lr: fp= gp= mp=) m=ermssse3avx2bmi1bmi2qydlkqglspwritemkdircloseLstatMarchApril+0530+0430" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 17110056 and 12 of them
}
