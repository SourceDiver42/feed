rule Sightlines_host_ad21b9ea_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign host-ad21b9ea"
        date = "2026-11-01"
        campaign = "host-ad21b9ea"
        family = ""
        hash = "0f720707e73b3f4248f49542eaca1a7a5a73f06ed848a8ade93f7d623313c8b0"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/host-ad21b9ea.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "pnDCe):hover .VfPpkd-NLUYnc-V67aGc{color:rgb(248,249,250)}.AfoeCd .RnXJS.VfPpkd-O1htCb-OWXEXe-OWB6Me" ascii
        $s1 = "kd-NLUYnc-V67aGc{color:rgb(248,249,250)}.AfoeCd .gOPnwc:hover:not(.VfPpkd-fmcmS-yrriRe-OWXEXe-OWB6Me" ascii
        $s2 = " .VfPpkd-NLUYnc-V67aGc{color:rgba(232,234,237,.38)}.AfoeCd .RnXJS:not(.VfPpkd-O1htCb-OWXEXe-OWB6Me)+" ascii
        $s3 = "ot(.VfPpkd-fmcmS-yrriRe-OWXEXe-OWB6Me) .VfPpkd-NLUYnc-V67aGc{color:rgb(138,180,248)}.AfoeCd .gOPnwc." ascii
        $s4 = "ohUe-UbuQg.VfPpkd-StrnGf-rymPhb-clz4Ic-OWXEXe-YbohUe-QFlW2{width:calc(100% - 32px)}.r6B9Fd{font-fami" ascii
        $s5 = "174,203,250))}.AfoeCd .zNgRPc .VfPpkd-RKhZBe-LgbsSe-OWXEXe-bAa4l .VfPpkd-Jh9lGc:after{background-col" ascii
        $s6 = "ity,0.1)}.AfoeCd .zNgRPc .VfPpkd-RKhZBe-LgbsSe-OWXEXe-bAa4l:not(:disabled){color:rgb(138,180,248);co" ascii
        $s7 = "d-NLUYnc-V67aGc{color:rgb(248,249,250)}.AfoeCd .UAQDDf.VfPpkd-O1htCb-OWXEXe-OWB6Me .VfPpkd-NLUYnc-V6" ascii
        $s8 = "t(:disabled){background-color:rgb(138,180,248)}.AfoeCd .zNgRPc .VfPpkd-RKhZBe-LgbsSe-OWXEXe-C3kE6.Vf" ascii
        $s9 = "IsBm,1.5rem);letter-spacing:var(--H8HCPd,0);font-weight:var(--Bpk69,400)}.uW2Fw-Sx9Kwc-OWXEXe-vOE8Lb" ascii
        $s10 = "ot(.VfPpkd-fmcmS-yrriRe-OWXEXe-OWB6Me) .VfPpkd-NLUYnc-V67aGc{color:rgb(246,174,169)}.AfoeCd .NGdKgb " ascii
        $s11 = "XEXe-OWB6Me) .VfPpkd-NLUYnc-V67aGc{color:rgb(138,180,248)}.AfoeCd .Y5O54e .VfPpkd-fmcmS-yrriRe.VfPpk" ascii
    condition:
        filesize < 1933180 and 12 of them
}
