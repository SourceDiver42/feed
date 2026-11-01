rule Sightlines_tlsh_237ed4c4_agenttesla
{
    meta:
        author = "Sightlines (automatically generated)"
        description = "Strings shared by the samples of campaign tlsh-237ed4c4"
        date = "2026-10-15"
        campaign = "tlsh-237ed4c4"
        family = "agenttesla"
        hash = "21f53d2b3cf28862d7ecf4692993a6ea24f222c0d621d78254f826f575415c92"
        reference = "https://sourcediver42.github.io/sightlines/campaigns/tlsh-237ed4c4.json"
        license = "Detection Rule License (DRL) 1.1"
    strings:
        $s0 = "var _tmpx=[34,83,66,74,87,34],_tmpk=7,_tmp=\"\"; for(var _tmpi=0;_tmpi<_tmpx.length;_tmpi++)_tmp+=_xF(" ascii
        $s1 = "var _mtx=[72,96,113,109,106,97,118,90],_mtk=5,_mt=\"\"; for(var _mti=0;_mti<_mtx.length;_mti++)_mt+=_x" ascii
        $s2 = "var _swx=[87,108,107,115,83,109,106,96,107,115],_swk=4,_sw=\"\"; for(var _swi=0;_swi<_swx.length;_swi+" ascii
        $s3 = "var _dfx=[74,107,98,107,122,107,72,103,98,107],_dfk=14,_df=\"\"; for(var _dfi=0;_dfi<_dfx.length;_dfi+" ascii
        $s4 = "var hex = (value & 0xFFFF).toString(16).toUpperCase();" ascii
        $s5 = "var _itmx=[74,119,102,110],_itmk=3,_itm=\"\"; for(var _itmi=0;_itmi<_itmx.length;_itmi++)_itm+=_xF(_it" ascii
        $s6 = "var childAttribute = new NS_Mdl.Element();" ascii
        $s7 = "toyKey = secret.hexKey ? secret.toyKey : ((pmk[0] << 8) | pmk[1]) & 0xFFFF;" ascii
        $s8 = "var _ipx=[69,98,92,109,126,109,97,105,120,105,126,127],_ipk=12,_ip=\"\"; for(var _ipi=0;_ipi<_ipx.leng" ascii
        $s9 = "var ImportOverwriteMode = { Stubs: \"Stubs\", All: \"All\" };" ascii
        $s10 = "var attributes = new NS_Mdl.ElementArray();" ascii
        $s11 = "var _flrx=[111,101,102,102,123],_flrk=9,_flr=\"\"; for(var _flri=0;_flri<_flrx.length;_flri++)_flr+=_x" ascii
    condition:
        filesize < 1170342 and 12 of them
}
