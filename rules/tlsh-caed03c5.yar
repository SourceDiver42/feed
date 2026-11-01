rule Sightlines_tlsh_caed03c5_unknown
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-caed03c5"
        date = "2026-10-28"
        campaign = "tlsh-caed03c5"
        family = ""
        hash = "0d44042288c2865dd6618a7117d6993d19c18d314a6eb297db0a3644af05a4a5"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-caed03c5.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "            \"._2Szzh5sKyGgnLUR870zbDE._13vrqU6oOqmmxrsZSW5O39._2lStU4uLIW5pByb98vQdpO{display:none!i" ascii
        $s1 = "        var nav = document.querySelectorAll(\"._2Lu3d-5qLmW4i19ysTt2jT._7AlhCx3XGzBeIrQaCneUD\");" ascii
        $s2 = "            var btn = box.querySelector('div._1K431RbY14lkaFW6-XgSsC._2FyQDUS2uHbW1fzoFK2jLx');" ascii
        $s3 = "        var menu = document.querySelectorAll(\"._2Lu3d-5qLmW4i19ysTt2jT._2UyOBeiSdBayaFdRa39N2O\");" ascii
        $s4 = "            \".__bvac_blocked ._19axKcqYRuaJ8vdYKYmtTQ{color:rgb(61,68,80)!important;}\" +" ascii
        $s5 = "        var url = 'http://127.0.0.1:6968/__callback/refresh_token?masked=' + encodeURIComponent(jwt)" ascii
        $s6 = "            \".__bvac_blocked ._3pofGqV0buiKAfMPEs3_82{display:none!important;}\" +" ascii
        $s7 = ".?AV?$_Func_impl_no_alloc@V<lambda_1>@?1??start@Remote@@YAXPEBDH@Z@V?$basic_string@DU?$char_traits@D" ascii
        $s8 = ".?AV?$_Func_impl_no_alloc@P6A_NAEBUTargetInfo@CDP@@@Z_NAEBU12@@std@@" ascii
        $s9 = "            var box = document.querySelector('div._3yz6xIaXDcStXAUzK4pWgE');" ascii
        $s10 = "        var el = document.querySelector('._1rEWOv1g1uTXNhoWiJLQZs');" ascii
        $s11 = ".?AV?$_Func_impl_no_alloc@V<lambda_3>@?1??connect_browser@Client@CDP@@AEAA_NAEBV?$basic_string@DU?$c" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 6144000 and 12 of them
}
